use crate::{
    ivc::PublicInputs as OriginalTreePublicInputs,
    query::universal_circuit::build_cells_tree,
    results_tree::{
        binding::public_inputs::PublicInputs as BindingPublicInputs,
        extraction::public_inputs::PublicInputs as ExtractionPublicInputs,
    },
    revelation::{
        placeholders_check::{
            check_placeholders, CheckedPlaceholder, CheckedPlaceholderTarget,
            NUM_SECONDARY_INDEX_PLACEHOLDERS,
        },
        PublicInputs,
    },
};
use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    poseidon::H,
    public_inputs::PublicInputCommon,
    serialization::{
        deserialize_array, deserialize_long_array, serialize_array, serialize_long_array,
    },
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{SelectCurveBuilder, ToTargets},
    F,
};
use plonky2::{
    field::types::Field,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use serde::{Deserialize, Serialize};
use std::{array, iter};

// L: maximum number of results
// S: maximum number of items in each result
// PH: maximum number of unique placeholder IDs and values bound for query
// PP: maximum number of placeholders present in query (may be duplicate, PP >= PH)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevelationWithResultsTreeWires<
    const L: usize,
    const S: usize,
    const PH: usize,
    const PP: usize,
> where
    [(); S * L]:,
{
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    is_item_included: [BoolTarget; S * L],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    is_result_valid: [BoolTarget; L],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    result_values: [UInt256Target; S * L],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    ids: [Target; S],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    is_placeholder_valid: [BoolTarget; PH],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    placeholder_ids: [Target; PH],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    placeholder_values: [UInt256Target; PH],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    to_be_checked_placeholders: [CheckedPlaceholderTarget; PP],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    secondary_query_bound_placeholders:
        [CheckedPlaceholderTarget; NUM_SECONDARY_INDEX_PLACEHOLDERS],
    order: Target,
    query_limit: Target,
    query_offset: Target,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevelationWithResultsTreeCircuit<
    const L: usize,
    const S: usize,
    const PH: usize,
    const PP: usize,
> where
    [(); S * L]:,
{
    /// Array of real number of the included items
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) num_included_items: [usize; L],
    /// Real number of the results
    pub(crate) num_valid_results: usize,
    /// Arrays corresponding to the results extracted from the results tree
    /// by proof of extraction of results from results tree
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) result_values: [U256; S * L],
    /// integer identifier of items stored in each record of the results tree;
    /// the first id is the identifier of the indexed item
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) ids: [F; S],
    /// Real number of the valid placeholders
    pub(crate) num_placeholders: usize,
    /// Array of the placeholder identifiers that can be employed in the query:
    /// - The first 4 items are expected to be constant identifiers of the query
    ///   bounds `MIN_I1, MAX_I1` and  `MIN_I2, MAX_I2`
    /// - The following `num_placeholders - 4` values are expected to be the
    ///   identifiers of the placeholders employed in the query
    /// - The remaining `PH - num_placeholders` items are expected to be the
    ///   same as `placeholders_ids[0]`
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) placeholder_ids: [F; PH],
    /// Array of the placeholder values that can be employed in the query:
    /// - The first 4 values are expected to be the bounds `MIN_I1, MAX_I1` and
    ///   `MIN_I2, MAX_I2` found in the query for the primary and secondary
    ///   indexed columns
    /// - The following `num_placeholders - 4` values are expected to be the
    ///   values for the placeholders employed in the query
    /// - The remaining `PH - num_placeholders` values are expected to be the
    ///   same as `placeholder_values[0]`
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) placeholder_values: [U256; PH],
    /// Placeholders data to be provided to `check_placeholder` gadget to
    /// check that placeholders employed in universal query circuit matches
    /// with the `placeholder_values` exposed as public input by this proof
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) to_be_checked_placeholders: [CheckedPlaceholder; PP],
    /// Placeholders data related to the placeholders employed in the
    /// universal query circuit to hash the query bounds for the secondary
    /// index; they are provided as well to `check_placeholder` gadget to
    /// check the correctness of the placeholders employed for query bounds
    pub(crate) secondary_query_bound_placeholders:
        [CheckedPlaceholder; NUM_SECONDARY_INDEX_PLACEHOLDERS],
    /// Value specifying whether the ordering of the results of the query:
    /// - `order = 0`: No ordering needs to be enforced on query result
    /// - `order = 1`: Results must be returned in ascending order
    /// - `order = 2`: Results must be returned in descending order
    pub(crate) order: F,
    /// limit value specified in the query
    pub(crate) query_limit: F,
    /// offset value specified in the query
    pub(crate) query_offset: F,
}

impl<const L: usize, const S: usize, const PH: usize, const PP: usize>
    RevelationWithResultsTreeCircuit<L, S, PH, PP>
where
    [(); S * L]:,
{
    pub fn build(
        b: &mut CBuilder,
        // Proof binding the original tree with the results tree
        binding_proof: &BindingPublicInputs<Target>,
        // Proof of extraction of results from results tree according to values for
        // LIMIT and OFFSET specified in the query
        extraction_proof: &ExtractionPublicInputs<Target>,
        // proof of construction of the original tree in the pre-processing stage (IVC proof)
        original_tree_proof: &OriginalTreePublicInputs<Target>,
    ) -> RevelationWithResultsTreeWires<L, S, PH, PP> {
        let zero = b.zero();
        let one = b.one();
        let two = b.two();
        let curve_zero = b.curve_zero();
        let u256_zero = b.zero_u256();
        let u256_max = b.constant_u256(U256::MAX);

        // `is_item_included` and `result_values` supposed to be a 2D-array,
        // but we use a `L * S` length array for efficiency of serialization
        let is_item_included = array::from_fn(|_| b.add_virtual_bool_target_safe());
        let result_values = array::from_fn(|_| b.add_virtual_u256());
        let is_result_valid = array::from_fn(|_| b.add_virtual_bool_target_safe());
        let ids = array::from_fn(|_| b.add_virtual_target());
        let is_placeholder_valid = array::from_fn(|_| b.add_virtual_bool_target_safe());
        let placeholder_ids = b.add_virtual_target_arr();
        // `placeholder_values` are exposed as public inputs to the Solidity contract
        // which will not do range-check.
        let placeholder_values = array::from_fn(|_| b.add_virtual_u256());
        let to_be_checked_placeholders = array::from_fn(|_| CheckedPlaceholderTarget::new(b));
        let secondary_query_bound_placeholders =
            array::from_fn(|_| CheckedPlaceholderTarget::new(b));

        let order = b.add_virtual_target();
        let query_limit = b.add_virtual_target();
        let query_offset = b.add_virtual_target();

        let order_by_desc = b.is_equal(order, two);
        let order_by_asc = b.is_equal(order, one);

        // Enforce hash of the results tree is the same as the
        // hash of the tree employed to extract the results
        b.connect_hashes(
            binding_proof.results_tree_hash_target(),
            extraction_proof.tree_hash_target(),
        );

        // Ensure that counters start form 1
        b.connect(extraction_proof.min_counter_target(), one);

        // Ensure max_counter is the same for both proofs
        b.connect(
            extraction_proof.max_counter_target(),
            binding_proof.entry_count_target(),
        );

        // Ensure query_min and query_max values employed to extract
        // the values are computed as expected from limit and offset
        let max_minus_offset = b.sub(extraction_proof.max_counter_target(), query_offset);
        let desc_query_min = b.sub(max_minus_offset, query_limit);
        let query_min = b.select(order_by_desc, desc_query_min, query_offset);

        let limit_plus_offset = b.add(query_limit, query_offset);
        let desc_query_max = b.sub(extraction_proof.max_counter_target(), query_offset);
        let query_max = b.select(order_by_desc, desc_query_max, limit_plus_offset);

        b.connect(extraction_proof.offset_range_min_target(), query_min);
        b.connect(extraction_proof.offset_range_max_target(), query_max);

        let mut num_results = zero.clone();
        let mut accumulator = curve_zero.clone();
        //  if results need to be sorted in decreasing order, we set prev_value to the
        // highest possible value; otherwise, we set it to the minimum possible value
        let prev_value = b.select_u256(order_by_desc, &u256_max, &u256_zero);
        for i in 0..L {
            let cur_idx = i * S;

            // Recompute the hash of the i-th record to be included in the result
            let cells_hash = build_cells_tree(
                b,
                &result_values[(cur_idx + 2)..(cur_idx + S)],
                &ids[2..],
                &is_item_included[(cur_idx + 2)..(cur_idx + S)],
            );

            // Compute the order-agnostic digest of the record
            let second_item = b.select_u256(
                is_item_included[cur_idx + 1],
                &result_values[cur_idx + 1],
                &u256_zero,
            );
            // D(ids[0] || result_values[i][0] || ids[1] || second_item || cells_hash)
            let record_digest_inputs: Vec<_> = iter::once(ids[0])
                .chain(result_values[cur_idx].to_targets())
                .chain(iter::once(ids[1]))
                .chain(second_item.to_targets())
                .chain(cells_hash.to_targets())
                .collect();
            let record_digest = b.map_to_curve_point(&record_digest_inputs);
            let record_digest = b.select_curve(is_result_valid[i], &record_digest, &curve_zero);
            accumulator = b.curve_add(accumulator, record_digest);

            // Enforce required ordering of the results according to the indexed item,
            // which is result_values[i][0]
            // order_by_desc == (order_by_desc AND less_or_equal)
            let less_or_equal = b.is_less_or_equal_than_u256(&result_values[cur_idx], &prev_value);
            let less_or_equal_if_desc = b.and(order_by_desc, less_or_equal);
            b.connect(order_by_desc.target, less_or_equal_if_desc.target);
            // order_by_asc == (order_by_asc AND greater_or_equal)
            let greater_or_equal =
                b.is_greater_or_equal_than_u256(&result_values[cur_idx], &prev_value);
            let greater_or_equal_if_asc = b.and(order_by_asc, greater_or_equal);
            b.connect(order_by_asc.target, greater_or_equal_if_asc.target);

            num_results = b.add(num_results, is_result_valid[i].target);
        }

        // At the end, we check that the accumulator computed from `result_values` is
        // the same as the accumulator computed by proof `pE`
        b.connect_curve_points(extraction_proof.accumulator_target(), accumulator);

        // Check the placeholder data.
        let (num_placeholders, placeholder_ids_hash) = check_placeholders(
            b,
            &is_placeholder_valid,
            &placeholder_ids,
            &placeholder_values,
            &to_be_checked_placeholders,
            &secondary_query_bound_placeholders,
            &binding_proof.placeholder_hash_target(),
        );

        // check that the tree employed to build the queries is the same as
        // the tree constructed in pre-processing
        b.connect_hashes(
            binding_proof.original_tree_hash_target(),
            original_tree_proof.merkle_hash(),
        );

        let placeholder_values_slice = placeholder_values
            .iter()
            .flat_map(ToTargets::to_targets)
            .collect_vec();
        let results_slice = result_values
            .iter()
            .flat_map(ToTargets::to_targets)
            .collect_vec();

        // include order information, placeholder identifiers hash and metadata hash
        // from pre-processing in computational hash
        // H(pQ.C || placeholder_ids_hash || "ORDER" || order || pD.M)
        const ORDER_PREFIX: &[u8] = b"ORDER";
        let order_prefix_field: Vec<_> = ORDER_PREFIX
            .into_iter()
            .map(|b| F::from_canonical_u8(*b))
            .collect();
        let order_const: Vec<_> = order_prefix_field
            .into_iter()
            .map(|f| b.constant(f))
            .collect();
        let inputs = binding_proof
            .computational_hash_target()
            .to_targets()
            .into_iter()
            .chain(placeholder_ids_hash.to_targets())
            .chain(order_const)
            .chain(iter::once(order))
            .chain(original_tree_proof.metadata_hash().into_iter().cloned())
            .collect();
        let computational_hash = b.hash_n_to_hash_no_pad::<H>(inputs);

        // Register the public inputs.
        PublicInputs::<_, L, S, PH>::new(
            &original_tree_proof.block_hash(),
            &computational_hash.to_targets(),
            &[num_placeholders],
            &placeholder_values_slice,
            &[*binding_proof.to_entry_count_raw()],
            &[*binding_proof.to_overflow_raw()],
            &[num_results],
            &results_slice,
            &[query_limit],
            &[query_offset],
        )
        .register(b);

        RevelationWithResultsTreeWires {
            is_item_included,
            is_result_valid,
            result_values,
            ids,
            is_placeholder_valid,
            placeholder_ids,
            placeholder_values,
            to_be_checked_placeholders,
            secondary_query_bound_placeholders,
            order,
            query_limit,
            query_offset,
        }
    }

    fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &RevelationWithResultsTreeWires<L, S, PH, PP>,
    ) {
        wires
            .is_item_included
            .iter()
            .enumerate()
            .for_each(|(idx, t)| {
                let l = idx / S;
                let i = idx % S;
                pw.set_bool_target(*t, i < self.num_included_items[l]);
            });
        wires
            .is_result_valid
            .iter()
            .enumerate()
            .for_each(|(i, t)| pw.set_bool_target(*t, i < self.num_valid_results));
        pw.set_u256_target_arr(&wires.result_values, &self.result_values);
        pw.set_target_arr(&wires.ids, &self.ids);
        wires
            .is_placeholder_valid
            .iter()
            .enumerate()
            .for_each(|(i, t)| pw.set_bool_target(*t, i < self.num_placeholders));
        pw.set_target_arr(&wires.placeholder_ids, &self.placeholder_ids);
        wires
            .placeholder_values
            .iter()
            .zip(self.placeholder_values)
            .for_each(|(t, v)| pw.set_u256_target(t, v));
        wires
            .to_be_checked_placeholders
            .iter()
            .zip(&self.to_be_checked_placeholders)
            .for_each(|(t, v)| v.assign(pw, t));
        wires
            .secondary_query_bound_placeholders
            .iter()
            .zip(&self.secondary_query_bound_placeholders)
            .for_each(|(t, v)| v.assign(pw, t));
        pw.set_target(wires.order, self.order);
        pw.set_target(wires.query_limit, self.query_limit);
        pw.set_target(wires.query_offset, self.query_offset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        results_tree::{
            binding::public_inputs::ResultsBindingPublicInputs,
            extraction::{
                public_inputs::ResultsExtractionPublicInputs,
                tests::random_results_extraction_public_inputs,
            },
        },
        revelation::tests::{TestPlaceholders, ORIGINAL_TREE_PI_LEN},
    };
    use mp2_common::{
        array::ToField,
        group_hashing::{add_weierstrass_point, map_to_curve_point},
        poseidon::{empty_poseidon_hash, H},
        utils::ToFields,
        C, D,
    };
    use mp2_test::{
        cells_tree::{compute_cells_tree_hash, TestCell},
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::types::{Field, Sample},
        hash::hash_types::HashOut,
        plonk::config::Hasher,
    };
    use plonky2_ecgfp5::curve::curve::{Point, WeierstrassPoint};
    use rand::{thread_rng, Rng};

    // L: maximum number of results
    // S: maximum number of items in each result
    // PH: maximum number of unique placeholder IDs and values bound for query
    // PP: maximum number of placeholders present in query (may be duplicate, PP >= PH)
    const L: usize = 5;
    const S: usize = 10;
    const PH: usize = 10;
    const PP: usize = 20;

    // Real number of the placeholders
    const NUM_PLACEHOLDERS: usize = 5;

    const BINDING_PI_LEN: usize = crate::results_tree::binding::PI_LEN;
    const EXTRACTION_PI_LEN: usize = crate::results_tree::extraction::PI_LEN;

    #[derive(Clone, Debug)]
    struct TestRevelationWithResultsTreeCircuit<'a> {
        c: RevelationWithResultsTreeCircuit<L, S, PH, PP>,
        binding_proof: &'a [F],
        extraction_proof: &'a [F],
        original_tree_proof: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestRevelationWithResultsTreeCircuit<'a> {
        // Circuit wires + binding proof + extraction proof + original tree proof
        type Wires = (
            RevelationWithResultsTreeWires<L, S, PH, PP>,
            Vec<Target>,
            Vec<Target>,
            Vec<Target>,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let binding_proof = b.add_virtual_target_arr::<BINDING_PI_LEN>().to_vec();
            let extraction_proof = b.add_virtual_target_arr::<EXTRACTION_PI_LEN>().to_vec();
            let original_tree_proof = b.add_virtual_target_arr::<ORIGINAL_TREE_PI_LEN>().to_vec();

            let binding_pi = BindingPublicInputs::from_slice(&binding_proof);
            let extraction_pi = ExtractionPublicInputs::from_slice(&extraction_proof);
            let original_tree_pi = OriginalTreePublicInputs::from_slice(&original_tree_proof);

            let wires = RevelationWithResultsTreeCircuit::build(
                b,
                &binding_pi,
                &extraction_pi,
                &original_tree_pi,
            );

            (wires, binding_proof, extraction_proof, original_tree_proof)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);
            pw.set_target_arr(&wires.1, self.binding_proof);
            pw.set_target_arr(&wires.2, self.extraction_proof);
            pw.set_target_arr(&wires.3, self.original_tree_proof);
        }
    }

    // Generate a random binding proof.
    fn random_binding_proof(
        original_tree_pi: &OriginalTreePublicInputs<F>,
        placeholder_hash: &HashOut<F>,
    ) -> Vec<F> {
        let [original_tree_hash_range, entry_cnt_range, placeholder_hash_range, overflow_range] = [
            ResultsBindingPublicInputs::OriginalTreeHash,
            ResultsBindingPublicInputs::EntryCount,
            ResultsBindingPublicInputs::PlaceholderHash,
            ResultsBindingPublicInputs::Overflow,
        ]
        .map(BindingPublicInputs::<F>::to_range);
        let mut rng = thread_rng();
        let mut pi = random_vector::<u32>(BINDING_PI_LEN).to_fields();

        let entry_counter = F::from_canonical_u32(300);
        let overflow = F::from_bool(rng.gen_bool(0.5));

        pi[original_tree_hash_range.clone()]
            .copy_from_slice(&original_tree_pi.merkle_root_hash_fields().to_fields());
        pi[entry_cnt_range.clone()].copy_from_slice(&[entry_counter]);
        pi[placeholder_hash_range.clone()].copy_from_slice(&placeholder_hash.to_fields());
        pi[overflow_range.clone()].copy_from_slice(&[overflow]);

        pi
    }

    // Generate a random extraction proof.
    fn random_extraction_proof(
        binding_pi: &BindingPublicInputs<F>,
        accumulator: &WeierstrassPoint,
    ) -> Vec<F> {
        let [mut extraction_proof] = random_results_extraction_public_inputs();

        let [tree_hash_range, min_cnt_range, max_cnt_range, offset_rng_min_range, offset_rng_max_range, accumulator_range] =
            [
                ResultsExtractionPublicInputs::TreeHash,
                ResultsExtractionPublicInputs::MinCounter,
                ResultsExtractionPublicInputs::MaxCounter,
                ResultsExtractionPublicInputs::OffsetRangeMin,
                ResultsExtractionPublicInputs::OffsetRangeMax,
                ResultsExtractionPublicInputs::Accumulator,
            ]
            .map(ExtractionPublicInputs::<F>::to_range);

        let min_counter = F::ONE;
        let offset_range_min = F::from_canonical_u32(100);
        let offset_range_max = F::from_canonical_u32(200);

        extraction_proof[tree_hash_range]
            .copy_from_slice(&binding_pi.results_tree_hash().to_fields());
        extraction_proof[min_cnt_range].copy_from_slice(&[min_counter]);
        extraction_proof[max_cnt_range].copy_from_slice(&[binding_pi.entry_count()]);
        extraction_proof[offset_rng_min_range].copy_from_slice(&[offset_range_min]);
        extraction_proof[offset_rng_max_range].copy_from_slice(&[offset_range_max]);
        extraction_proof[accumulator_range].copy_from_slice(&accumulator.to_fields());

        extraction_proof
    }

    async fn test_revelation_with_results_tree_circuit(order_type: usize) {
        // Construct the witness.
        let mut rng = thread_rng();
        let num_included_items: [usize; L] = array::from_fn(|_| rng.gen_range(1..(S + 1)));
        let num_valid_results = rng.gen_range(0..(S + 1));
        let order = F::from_canonical_usize(order_type);
        let query_limit = F::from_canonical_usize(100);
        let query_offset = F::from_canonical_usize(100);
        let mut result_values = [[U256::ZERO; S]; L];
        let ids: [F; S] = F::rand_array();

        // Generate testing cells for each result and compute expected accumulator.
        let mut num_results = 0;
        let mut exp_accumulator = WeierstrassPoint::NEUTRAL;
        for l in 0..L {
            let num_items = num_included_items[l];
            // let cells: Vec<TestCell> = (0..num_items).map(|_| TestCell::random()).collect();
            let cells: Vec<TestCell> = (0..num_items)
                .map(|i| TestCell::random_with_id(ids[i]))
                .collect();

            // Fill result_values and ids based on the generated cells.
            for (i, cell) in cells.iter().enumerate() {
                result_values[l][i] = cell.value;
            }

            let exp_cells_hash = if cells.len() < 3 {
                *empty_poseidon_hash()
            } else {
                compute_cells_tree_hash(cells[2..].to_vec()).await
            };
            let second_item = if num_included_items[l] > 1 {
                result_values[l][1]
            } else {
                U256::ZERO
            };
            let record_digest_inputs: Vec<_> = iter::once(ids[0])
                .chain(result_values[l][0].to_fields())
                .chain(iter::once(ids[1]))
                .chain(second_item.to_fields())
                .chain(exp_cells_hash.to_fields())
                .collect();
            let record_digest = map_to_curve_point(&record_digest_inputs);
            let final_digest = if num_valid_results > l {
                num_results += 1;
                record_digest
            } else {
                Point::NEUTRAL
            };

            exp_accumulator =
                add_weierstrass_point(&[exp_accumulator, final_digest.to_weierstrass()]);
        }
        let flat_result_values: [U256; S * L] = result_values.concat().try_into().unwrap();

        // Generate the testing placeholder data.
        let test_placeholders = TestPlaceholders::sample(NUM_PLACEHOLDERS);

        // Generate the original tree proof.
        let original_tree_proof = random_vector::<u32>(ORIGINAL_TREE_PI_LEN).to_fields();
        let original_tree_pi = OriginalTreePublicInputs::from_slice(&original_tree_proof);

        // Generate the binding proof.
        let binding_proof =
            random_binding_proof(&original_tree_pi, &test_placeholders.final_placeholder_hash);
        let binding_pi = BindingPublicInputs::from_slice(&binding_proof);

        // Generate the extraction proof.
        let extraction_proof = random_extraction_proof(&binding_pi, &exp_accumulator);

        // Construct the circuit.
        let test_circuit = TestRevelationWithResultsTreeCircuit {
            c: RevelationWithResultsTreeCircuit {
                num_included_items,
                num_valid_results,
                result_values: flat_result_values,
                ids,
                num_placeholders: test_placeholders.num_placeholders,
                placeholder_ids: test_placeholders.placeholder_ids,
                placeholder_values: test_placeholders.placeholder_values,
                to_be_checked_placeholders: test_placeholders.to_be_checked_placeholders,
                secondary_query_bound_placeholders: test_placeholders
                    .secondary_query_bound_placeholders,
                order,
                query_limit,
                query_offset,
            },
            binding_proof: &binding_proof,
            extraction_proof: &extraction_proof,
            original_tree_proof: &original_tree_proof,
        };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::<_, L, S, PH>::from_slice(&proof.public_inputs);

        // Check the public inputs.
        // Original block hash
        assert_eq!(
            pi.original_block_hash(),
            original_tree_pi.block_hash_fields()
        );

        // Computational hash
        {
            const ORDER_PREFIX: &[u8] = b"ORDER";
            let order_prefix_field: Vec<_> = ORDER_PREFIX
                .into_iter()
                .map(|b| F::from_canonical_u8(*b))
                .collect();

            // H(pQ.C || placeholder_ids_hash || "ORDER" || order || pD.M)
            let hash_inputs = binding_pi
                .to_computational_hash_raw()
                .iter()
                .chain(&test_placeholders.placeholder_ids_hash.to_fields())
                .chain(&order_prefix_field)
                .chain(iter::once(&order))
                .chain(original_tree_pi.metadata_hash())
                .cloned()
                .collect_vec();
            let exp_hash = H::hash_no_pad(&hash_inputs);

            assert_eq!(pi.computational_hash(), exp_hash);
        }

        // Number of placeholders
        assert_eq!(
            pi.num_placeholders(),
            test_placeholders.num_placeholders.to_field()
        );

        // Placeholder values
        assert_eq!(
            pi.placeholder_values(),
            test_placeholders.placeholder_values
        );

        // Entry count
        assert_eq!(pi.entry_count(), binding_pi.entry_count());

        // result values
        assert_eq!(pi.result_values(), result_values);

        // overflow flag
        assert_eq!(pi.overflow_flag(), binding_pi.overflow_flag());

        // Query limit
        assert_eq!(pi.query_limit(), query_limit);

        // Query offset
        assert_eq!(pi.query_offset(), query_offset);
    }

    #[tokio::test]
    async fn test_revelation_with_results_tree_circuit_with_no_ordering() {
        test_revelation_with_results_tree_circuit(0).await;
    }
    #[tokio::test]
    async fn test_revelation_with_results_tree_circuit_with_ascending_order() {
        test_revelation_with_results_tree_circuit(1).await;
    }
    #[tokio::test]
    async fn test_revelation_with_results_tree_circuit_with_descending_order() {
        test_revelation_with_results_tree_circuit(2).await;
    }
}
