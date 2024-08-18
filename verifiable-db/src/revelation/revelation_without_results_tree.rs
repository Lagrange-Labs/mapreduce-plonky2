//! The revelation circuit handling the queries where we don't need to build the results tree

use crate::{
    ivc::PublicInputs as OriginalTreePublicInputs,
    query::{
        computational_hash_ids::AggregationOperation,
        public_inputs::PublicInputs as QueryProofPublicInputs,
    },
    revelation::{placeholders_check::check_placeholders, PublicInputs},
};
use alloy::primitives::U256;
use anyhow::Result;
use itertools::Itertools;
use mp2_common::{
    array::ToField,
    default_config,
    poseidon::{flatten_poseidon_hash_target, H},
    proof::ProofWithVK,
    public_inputs::PublicInputCommon,
    serialization::{
        deserialize, deserialize_array, deserialize_long_array, serialize, serialize_array,
        serialize_long_array,
    },
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::ToTargets,
    C, D, F,
};
use plonky2::{
    hash::poseidon::PoseidonHash,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::VerifierOnlyCircuitData,
        config::Hasher,
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    framework::{
        RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
};
use serde::{Deserialize, Serialize};
use std::array;

use super::{
    placeholders_check::{
        CheckedPlaceholder, CheckedPlaceholderTarget, NUM_SECONDARY_INDEX_PLACEHOLDERS,
    },
    NUM_PREPROCESSING_IO, NUM_QUERY_IO, PI_LEN as REVELATION_PI_LEN,
};

// L: maximum number of results
// S: maximum number of items in each result
// PH: maximum number of unique placeholder IDs and values bound for query
// PP: maximum number of placeholders present in query (may be duplicate, PP >= PH)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevelationWithoutResultsTreeWires<
    const L: usize,
    const S: usize,
    const PH: usize,
    const PP: usize,
> {
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
    secondary_query_bound_placeholders:
        [CheckedPlaceholderTarget; NUM_SECONDARY_INDEX_PLACEHOLDERS],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevelationWithoutResultsTreeCircuit<
    const L: usize,
    const S: usize,
    const PH: usize,
    const PP: usize,
> {
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
}

impl<const L: usize, const S: usize, const PH: usize, const PP: usize>
    RevelationWithoutResultsTreeCircuit<L, S, PH, PP>
where
    [(); S - 1]:,
{
    pub fn build(
        b: &mut CBuilder,
        // Proof of the query results computed by the aggregation circuits
        query_proof: &QueryProofPublicInputs<Target, S>,
        // proof of construction of the original tree in the pre-processing stage (IVC proof)
        original_tree_proof: &OriginalTreePublicInputs<Target>,
    ) -> RevelationWithoutResultsTreeWires<L, S, PH, PP> {
        let zero = b.zero();
        let u256_zero = b.zero_u256();

        let is_placeholder_valid = array::from_fn(|_| b.add_virtual_bool_target_safe());
        let placeholder_ids = b.add_virtual_target_arr();
        // `placeholder_values` are exposed as public inputs to the Solidity contract
        // which will not do range-check.
        let placeholder_values = array::from_fn(|_| b.add_virtual_u256());
        let to_be_checked_placeholders = array::from_fn(|_| CheckedPlaceholderTarget::new(b));
        let secondary_query_bound_placeholders =
            array::from_fn(|_| CheckedPlaceholderTarget::new(b));

        // The operation cannot be ID for aggregation.
        let [op_avg, op_count] = [AggregationOperation::AvgOp, AggregationOperation::CountOp]
            .map(|op| b.constant(op.to_field()));

        let mut overflow = query_proof.overflow_flag_target().target;

        // Convert the entry count to an Uint256.
        let entry_count = query_proof.num_matching_rows_target();
        let entry_count = UInt256Target::new_from_target(b, entry_count);

        // Compute the output results array, and deal with AVG and COUNT operations if any.
        let ops = query_proof.operation_ids_target();
        assert_eq!(ops.len(), S);
        let mut results = Vec::with_capacity(L * S);
        // flag to determine whether entry count is zero
        let is_entry_count_zero = b.add_virtual_bool_target_unsafe();
        ops.into_iter().enumerate().for_each(|(i, op)| {
            let is_op_avg = b.is_equal(op, op_avg);
            let is_op_count = b.is_equal(op, op_count);
            let result = query_proof.value_target_at_index(i);

            // Compute the AVG result (and it's set to zero if the divisor is zero).
            let (avg_result, _, is_divisor_zero) = b.div_u256(&result, &entry_count);

            let result = b.select_u256(is_op_avg, &avg_result, &result);
            let result = b.select_u256(is_op_count, &entry_count, &result);

            b.connect(is_divisor_zero.target, is_entry_count_zero.target);

            results.push(result);

            // Accumulate overflow.
            let is_overflow = b.and(is_op_avg, is_divisor_zero);
            overflow = b.add(overflow, is_overflow.target);
        });
        results.resize(L * S, u256_zero);

        // Pre-compute the final placeholder hash then check it in the
        // `check_placeholders` function:
        // H(pQ.H_p || pQ.MIN_I || pQ.MAX_I)
        let inputs = query_proof
            .placeholder_hash_target()
            .to_targets()
            .into_iter()
            .chain(query_proof.min_query_target().to_targets())
            .chain(query_proof.max_query_target().to_targets())
            .collect();
        let final_placeholder_hash = b.hash_n_to_hash_no_pad::<H>(inputs);

        // Check the placeholder data.
        let (num_placeholders, placeholder_ids_hash) = check_placeholders(
            b,
            &is_placeholder_valid,
            &placeholder_ids,
            &placeholder_values,
            &to_be_checked_placeholders,
            &secondary_query_bound_placeholders,
            &final_placeholder_hash,
        );

        // Check that the tree employed to build the queries is the same as the
        // tree constructed in pre-processing.
        b.connect_hashes(
            query_proof.tree_hash_target(),
            original_tree_proof.merkle_hash(),
        );

        // Add the hash of placeholder identifiers and pre-processing metadata
        // hash to the computational hash:
        // H(pQ.C || placeholder_ids_hash || pQ.M)
        let inputs = query_proof
            .to_computational_hash_raw()
            .iter()
            .chain(&placeholder_ids_hash.to_targets())
            .chain(original_tree_proof.metadata_hash())
            .cloned()
            .collect();
        let computational_hash = b.hash_n_to_hash_no_pad::<H>(inputs);

        let placeholder_values_slice = placeholder_values
            .iter()
            .flat_map(ToTargets::to_targets)
            .collect_vec();
        let results_slice = results.iter().flat_map(ToTargets::to_targets).collect_vec();

        let overflow = b.is_not_equal(overflow, zero).target;

        let num_results = b.not(is_entry_count_zero);

        let flat_computational_hash = flatten_poseidon_hash_target(b, computational_hash);

        // Register the public innputs.
        PublicInputs::<_, L, S, PH>::new(
            &original_tree_proof.block_hash(),
            &flat_computational_hash,
            &placeholder_values_slice,
            &results_slice,
            &[num_placeholders],
            // The aggregation query proof only has one result.
            &[num_results.target],
            &[query_proof.num_matching_rows_target()],
            &[overflow],
            // Query limit
            &[zero],
            // Query offset
            &[zero],
        )
        .register(b);

        RevelationWithoutResultsTreeWires {
            is_placeholder_valid,
            placeholder_ids,
            placeholder_values,
            to_be_checked_placeholders,
            secondary_query_bound_placeholders,
        }
    }

    fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &RevelationWithoutResultsTreeWires<L, S, PH, PP>,
    ) {
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
    }
}

pub struct CircuitBuilderParams {
    pub(crate) query_circuit_set: RecursiveCircuits<F, C, D>,
    pub(crate) preprocessing_circuit_set: RecursiveCircuits<F, C, D>,
    pub(crate) preprocessing_vk: VerifierOnlyCircuitData<C, D>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecursiveCircuitWires<const L: usize, const S: usize, const PH: usize, const PP: usize> {
    revelation_circuit: RevelationWithoutResultsTreeWires<L, S, PH, PP>,
    query_verifier: RecursiveCircuitsVerifierTarget<D>,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    preprocessing_proof: ProofWithPublicInputsTarget<D>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecursiveCircuitInputs<const L: usize, const S: usize, const PH: usize, const PP: usize>
{
    pub(crate) inputs: RevelationWithoutResultsTreeCircuit<L, S, PH, PP>,
    pub(crate) query_proof: ProofWithVK,
    pub(crate) preprocessing_proof: ProofWithPublicInputs<F, C, D>,
    pub(crate) query_circuit_set: RecursiveCircuits<F, C, D>,
}

impl<const L: usize, const S: usize, const PH: usize, const PP: usize> CircuitLogicWires<F, D, 0>
    for RecursiveCircuitWires<L, S, PH, PP>
where
    [(); S - 1]:,
    [(); NUM_QUERY_IO::<S>]:,
    [(); <PoseidonHash as Hasher<F>>::HASH_SIZE]:,
{
    type CircuitBuilderParams = CircuitBuilderParams;

    type Inputs = RecursiveCircuitInputs<L, S, PH, PP>;

    const NUM_PUBLIC_INPUTS: usize = REVELATION_PI_LEN::<L, S, PH>;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let query_verifier = RecursiveCircuitsVerifierGagdet::<F, C, D, { NUM_QUERY_IO::<S> }>::new(
            default_config(),
            &builder_parameters.query_circuit_set,
        );
        let query_verifier = query_verifier.verify_proof_in_circuit_set(builder);
        let preprocessing_verifier =
            RecursiveCircuitsVerifierGagdet::<F, C, D, NUM_PREPROCESSING_IO>::new(
                default_config(),
                &builder_parameters.preprocessing_circuit_set,
            );
        let preprocessing_proof = preprocessing_verifier.verify_proof_fixed_circuit_in_circuit_set(
            builder,
            &builder_parameters.preprocessing_vk,
        );
        let query_pi = QueryProofPublicInputs::from_slice(
            query_verifier.get_public_input_targets::<F, { NUM_QUERY_IO::<S> }>(),
        );
        let preprocessing_pi =
            OriginalTreePublicInputs::from_slice(&preprocessing_proof.public_inputs);
        let revelation_circuit =
            RevelationWithoutResultsTreeCircuit::build(builder, &query_pi, &preprocessing_pi);

        Self {
            revelation_circuit,
            query_verifier,
            preprocessing_proof,
        }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        let (proof, verifier_data) = (&inputs.query_proof).into();
        self.query_verifier
            .set_target(pw, &inputs.query_circuit_set, proof, verifier_data)?;
        pw.set_proof_with_pis_target(&self.preprocessing_proof, &inputs.preprocessing_proof);
        inputs.inputs.assign(pw, &self.revelation_circuit);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        query::{
            aggregation::{random_aggregation_operations, random_aggregation_public_inputs},
            public_inputs::QueryPublicInputs,
        },
        revelation::{
            random_original_tree_proof,
            tests::{compute_results_from_query_proof, TestPlaceholders},
        },
    };
    use mp2_common::{poseidon::flatten_poseidon_hash_value, utils::ToFields, C, D};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{field::types::Field, plonk::config::Hasher};
    use rand::{prelude::SliceRandom, thread_rng, Rng};

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

    const QUERY_PI_LEN: usize = crate::query::PI_LEN::<S>;

    impl From<&TestPlaceholders<PH, PP>> for RevelationWithoutResultsTreeCircuit<L, S, PH, PP> {
        fn from(test_placeholders: &TestPlaceholders<PH, PP>) -> Self {
            Self {
                num_placeholders: test_placeholders.num_placeholders,
                placeholder_ids: test_placeholders.placeholder_ids,
                placeholder_values: test_placeholders.placeholder_values,
                to_be_checked_placeholders: test_placeholders.to_be_checked_placeholders,
                secondary_query_bound_placeholders: test_placeholders
                    .secondary_query_bound_placeholders,
            }
        }
    }

    #[derive(Clone, Debug)]
    struct TestRevelationWithoutResultsTreeCircuit<'a> {
        c: RevelationWithoutResultsTreeCircuit<L, S, PH, PP>,
        query_proof: &'a [F],
        original_tree_proof: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestRevelationWithoutResultsTreeCircuit<'a> {
        // Circuit wires + query proof + original tree proof (IVC proof)
        type Wires = (
            RevelationWithoutResultsTreeWires<L, S, PH, PP>,
            Vec<Target>,
            Vec<Target>,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let query_proof = b.add_virtual_target_arr::<QUERY_PI_LEN>().to_vec();
            let original_tree_proof = b.add_virtual_target_arr::<NUM_PREPROCESSING_IO>().to_vec();

            let query_pi = QueryProofPublicInputs::from_slice(&query_proof);
            let original_tree_pi = OriginalTreePublicInputs::from_slice(&original_tree_proof);

            let wires = RevelationWithoutResultsTreeCircuit::build(b, &query_pi, &original_tree_pi);

            (wires, query_proof, original_tree_proof)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);
            pw.set_target_arr(&wires.1, self.query_proof);
            pw.set_target_arr(&wires.2, self.original_tree_proof);
        }
    }

    /// Generate a random query proof.
    fn random_query_proof(
        entry_count: u32,
        ops: &[F; S],
        test_placeholders: &TestPlaceholders<PH, PP>,
    ) -> Vec<F> {
        let [mut proof] = random_aggregation_public_inputs(ops);

        let [count_range, min_query_range, max_query_range, p_hash_range] = [
            QueryPublicInputs::NumMatching,
            QueryPublicInputs::MinQuery,
            QueryPublicInputs::MaxQuery,
            QueryPublicInputs::PlaceholderHash,
        ]
        .map(QueryProofPublicInputs::<F, S>::to_range);

        // Set the count, minimum, maximum query and the placeholder hash.
        [
            (count_range, vec![entry_count.to_field()]),
            (min_query_range, test_placeholders.min_query.to_fields()),
            (max_query_range, test_placeholders.max_query.to_fields()),
            (
                p_hash_range,
                test_placeholders.query_placeholder_hash.to_fields(),
            ),
        ]
        .into_iter()
        .for_each(|(range, fields)| proof[range].copy_from_slice(&fields));

        proof
    }

    /// Utility function for testing the revelation circuit with results tree
    fn test_revelation_without_results_tree_circuit(ops: &[F; S], entry_count: Option<u32>) {
        let rng = &mut thread_rng();

        // Generate the testing placeholder data.
        let test_placeholders = TestPlaceholders::sample(NUM_PLACEHOLDERS);

        // Generate the query proof.
        let entry_count = entry_count.unwrap_or_else(|| rng.gen());
        let query_proof = random_query_proof(entry_count, ops, &test_placeholders);
        let query_pi = QueryProofPublicInputs::<_, S>::from_slice(&query_proof);

        // Generate the original tree proof (IVC proof).
        let original_tree_proof = random_original_tree_proof(&query_pi);
        let original_tree_pi = OriginalTreePublicInputs::from_slice(&original_tree_proof);

        // Construct the test circuit.
        let test_circuit = TestRevelationWithoutResultsTreeCircuit {
            c: (&test_placeholders).into(),
            query_proof: &query_proof,
            original_tree_proof: &original_tree_proof,
        };

        // Prove for the test circuit.
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::<_, L, S, PH>::from_slice(&proof.public_inputs);

        // Initialize the overflow flag to false.
        let entry_count = query_pi.num_matching_rows();

        // Check the public inputs.
        // Original block hash
        assert_eq!(
            pi.original_block_hash(),
            original_tree_pi.block_hash_fields()
        );
        // Computational hash
        {
            // H(pQ.C || placeholder_ids_hash || pQ.M)
            let inputs = query_pi
                .to_computational_hash_raw()
                .iter()
                .chain(&test_placeholders.placeholder_ids_hash.to_fields())
                .chain(original_tree_pi.metadata_hash())
                .cloned()
                .collect_vec();
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(
                pi.flat_computational_hash(),
                flatten_poseidon_hash_value(exp_hash),
            );
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
        assert_eq!(pi.entry_count(), entry_count);
        // check results
        let (result, overflow) = compute_results_from_query_proof(&query_pi);
        let mut exp_results = [[U256::ZERO; S]; L];
        exp_results[0] = result;
        assert_eq!(pi.result_values(), exp_results);
        // overflow flag
        assert_eq!(pi.overflow_flag(), overflow);
        // Query limit
        assert_eq!(pi.query_limit(), F::ZERO);
        // Query offset
        assert_eq!(pi.query_offset(), F::ZERO);
    }

    #[test]
    fn test_revelation_without_results_tree_simple() {
        // Generate the random operations and set the first operation to SUM
        // (not ID which should not be present in the aggregation).
        let mut ops: [_; S] = random_aggregation_operations();
        ops[0] = AggregationOperation::SumOp.to_field();

        test_revelation_without_results_tree_circuit(&ops, None);
    }

    // Test for COUNT operation.
    #[test]
    fn test_revelation_without_results_tree_for_op_count() {
        // Set the first operation to COUNT.
        let mut ops: [_; S] = random_aggregation_operations();
        ops[0] = AggregationOperation::CountOp.to_field();

        test_revelation_without_results_tree_circuit(&ops, None);
    }

    // Test for AVG operation.
    #[test]
    fn test_revelation_without_results_tree_for_op_avg() {
        // Set the first operation to AVG.
        let mut ops: [_; S] = random_aggregation_operations();
        ops[0] = AggregationOperation::AvgOp.to_field();

        test_revelation_without_results_tree_circuit(&ops, None);
    }

    // Test for AVG operation with zero entry count.
    #[test]
    fn test_revelation_without_results_tree_for_op_avg_with_no_entries() {
        // Set the first operation to AVG.
        let mut ops: [_; S] = random_aggregation_operations();
        ops[0] = AggregationOperation::AvgOp.to_field();

        test_revelation_without_results_tree_circuit(&ops, Some(0));
    }

    // Test for no AVG operation with zero entry count.
    #[test]
    fn test_revelation_without_results_tree_for_no_op_avg_with_no_entries() {
        // Initialize the all operations to SUM or COUNT (not AVG).
        let mut rng = thread_rng();
        let ops = array::from_fn(|_| {
            [AggregationOperation::SumOp, AggregationOperation::CountOp]
                .choose(&mut rng)
                .unwrap()
                .to_field()
        });

        test_revelation_without_results_tree_circuit(&ops, Some(0));
    }
}
