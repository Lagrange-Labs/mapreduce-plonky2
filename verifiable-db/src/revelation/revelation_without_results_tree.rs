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
use itertools::Itertools;
use mp2_common::{
    array::ToField,
    poseidon::H,
    public_inputs::PublicInputCommon,
    serialization::{
        deserialize_array, deserialize_long_array, serialize_array, serialize_long_array,
    },
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256, NUM_LIMBS},
    utils::ToTargets,
    F,
};
use plonky2::iop::{
    target::{BoolTarget, Target},
    witness::{PartialWitness, WitnessWrite},
};
use serde::{Deserialize, Serialize};
use std::array;

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
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    placeholder_pos: [Target; PP],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    placeholder_pairs: [(Target, UInt256Target); PP],
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
    /// The Position in `placeholder_ids` and `placeholder_values` arrays of the
    /// corresponding pair in `placeholder_pairs`
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) placeholder_pos: [usize; PP],
    /// Pairs of the placeholder identifiers and values employed in the
    /// universal query circuit operations
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) placeholder_pairs: [(F, U256); PP],
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
        let one = b.one();
        let u256_zero = b.zero_u256();

        let is_placeholder_valid = array::from_fn(|_| b.add_virtual_bool_target_safe());
        let placeholder_ids = b.add_virtual_target_arr();
        // `placeholder_values` are exposed as public inputs to the Solidity constract
        // which will not do range-check.
        let placeholder_values = array::from_fn(|_| b.add_virtual_u256());
        let placeholder_pos = b.add_virtual_target_arr();
        // Initialize `placeholder_pairs` as unsafe, since they're compared and used to
        // compute the placeholder hash in `check_placeholders` function.
        let placeholder_pairs =
            array::from_fn(|_| (b.add_virtual_target(), b.add_virtual_u256_unsafe()));

        // The operation cannot be ID for aggregation.
        let [op_avg, op_count] = [AggregationOperation::AvgOp, AggregationOperation::CountOp]
            .map(|op| b.constant(op.to_field()));

        // Convert the entry count to an Uint256.
        let entry_count = query_proof.num_matching_rows_target();
        let entry_count = UInt256Target::new_from_target(b, entry_count);

        // Compute the output results array, and deal with AVG and COUNT operations if any.
        let ops = query_proof.operation_ids_target();
        assert_eq!(ops.len(), S);
        let mut results = Vec::with_capacity(L * S);
        ops.into_iter().enumerate().for_each(|(i, op)| {
            let is_op_avg = b.is_equal(op, op_avg);
            let is_op_count = b.is_equal(op, op_count);
            let result = query_proof.value_target_at_index(i);

            // Compute the AVG result (and it's set to zero if the divisor is zero).
            let (avg_result, _, _) = b.div_u256(&result, &entry_count);

            let result = b.select_u256(is_op_avg, &avg_result, &result);
            let result = b.select_u256(is_op_count, &entry_count, &result);

            results.push(result);
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
            &placeholder_pos,
            &placeholder_pairs,
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

        // Register the public innputs.
        PublicInputs::<_, L, S, PH>::new(
            &original_tree_proof.block_hash(),
            &computational_hash.to_targets(),
            &[num_placeholders],
            &placeholder_values_slice,
            &[query_proof.num_matching_rows_target()],
            &[query_proof.overflow_flag_target().target],
            // The aggregation query proof only has one result.
            &[one],
            &results_slice,
            &[zero],
            &[zero],
        )
        .register(b);

        RevelationWithoutResultsTreeWires {
            is_placeholder_valid,
            placeholder_ids,
            placeholder_values,
            placeholder_pos,
            placeholder_pairs,
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
        let placeholder_pos: [_; PP] = array::from_fn(|i| self.placeholder_pos[i].to_field());
        pw.set_target_arr(&wires.placeholder_pos, &placeholder_pos);
        wires
            .placeholder_pairs
            .iter()
            .zip(self.placeholder_pairs)
            .for_each(|(t, v)| {
                pw.set_target(t.0, v.0);
                pw.set_u256_target(&t.1, v.1);
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ivc::public_inputs::H_RANGE as ORIGINAL_TREE_H_RANGE,
        query::{
            aggregation::tests::{random_aggregation_operations, random_aggregation_public_inputs},
            public_inputs::QueryPublicInputs,
        },
        revelation::tests::TestPlaceholders,
    };
    use mp2_common::{utils::ToFields, C, D};
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::types::{Field, PrimeField64},
        plonk::config::Hasher,
    };
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

    const QUERY_PI_LEN: usize = crate::query::PI_LEN::<S>;
    const ORIGINAL_TREE_PI_LEN: usize = OriginalTreePublicInputs::<Target>::TOTAL_LEN;

    impl From<&TestPlaceholders<PH, PP>> for RevelationWithoutResultsTreeCircuit<L, S, PH, PP> {
        fn from(test_placeholders: &TestPlaceholders<PH, PP>) -> Self {
            Self {
                num_placeholders: test_placeholders.num_placeholders,
                placeholder_ids: test_placeholders.placeholder_ids,
                placeholder_values: test_placeholders.placeholder_values,
                placeholder_pos: test_placeholders.placeholder_pos,
                placeholder_pairs: test_placeholders.placeholder_pairs,
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
            let original_tree_proof = b.add_virtual_target_arr::<ORIGINAL_TREE_PI_LEN>().to_vec();

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
        .map(|input| QueryProofPublicInputs::<F, S>::to_range(input));

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

    /// Generate a random original tree proof.
    fn random_original_tree_proof(query_pi: &QueryProofPublicInputs<F, S>) -> Vec<F> {
        let mut proof = random_vector::<u32>(ORIGINAL_TREE_PI_LEN).to_fields();

        // Set the tree hash.
        proof[ORIGINAL_TREE_H_RANGE].copy_from_slice(query_pi.to_hash_raw());

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
        assert_eq!(pi.entry_count(), entry_count);
        // overflow flag
        assert_eq!(pi.overflow_flag(), query_pi.overflow_flag());
        // Result values
        {
            // Convert the entry count to an Uint256.
            let entry_count = U256::from(entry_count.to_canonical_u64());

            let [op_avg, op_count] = [AggregationOperation::AvgOp, AggregationOperation::CountOp]
                .map(|op| op.to_field());

            // Compute the results array, and deal with AVG and COUNT operations if any.
            let ops = query_pi.operation_ids();
            let result = array::from_fn(|i| {
                let value = query_pi.value_at_index(i);

                let op = ops[i];
                if op == op_avg {
                    value.checked_div(entry_count).unwrap_or(U256::ZERO)
                } else if op == op_count {
                    entry_count
                } else {
                    value
                }
            });

            let mut exp_results = [[U256::ZERO; S]; L];
            exp_results[0] = result;

            assert_eq!(pi.result_values(), exp_results);
        }
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
}
