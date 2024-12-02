use mp2_common::{types::CBuilder, u256::CircuitBuilderU256, utils::FromTargets, F};
use plonky2::iop::{target::Target, witness::PartialWitness};
use serde::{Deserialize, Serialize};

use crate::{
    ivc::PublicInputs as OriginalTreePublicInputs,
    query::{
        batching::public_inputs::PublicInputs as QueryProofPublicInputs,
        universal_circuit::universal_query_gadget::OutputValuesTarget,
    },
};

use super::revelation_without_results_tree::{
    QueryProofInputWires, RevelationWithoutResultsTreeCircuit, RevelationWithoutResultsTreeWires,
};

impl<'a, const S: usize> From<&'a QueryProofPublicInputs<'a, Target, S>> for QueryProofInputWires<S>
where
    [(); S - 1]:,
{
    fn from(value: &'a QueryProofPublicInputs<Target, S>) -> Self {
        Self {
            tree_hash: value.tree_hash_target(),
            results: OutputValuesTarget::from_targets(&value.to_values_raw()),
            entry_count: value.num_matching_rows_target(),
            overflow: value.overflow_flag_target().target,
            placeholder_hash: value.placeholder_hash_target(),
            computational_hash: value.computational_hash_target(),
            min_primary: value.min_primary_target(),
            max_primary: value.max_primary_target(),
            ops: value.operation_ids_target(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevelationCircuitBatching<
    const L: usize,
    const S: usize,
    const PH: usize,
    const PP: usize,
>(RevelationWithoutResultsTreeCircuit<L, S, PH, PP>);

impl<const L: usize, const S: usize, const PH: usize, const PP: usize>
    RevelationCircuitBatching<L, S, PH, PP>
where
    [(); S - 1]:,
{
    pub(crate) fn build(
        b: &mut CBuilder,
        query_proof: &QueryProofPublicInputs<Target, S>,
        original_tree_proof: &OriginalTreePublicInputs<Target>,
    ) -> RevelationWithoutResultsTreeWires<L, S, PH, PP> {
        let wires = RevelationWithoutResultsTreeCircuit::build_core(
            b,
            query_proof.into(),
            original_tree_proof,
        );
        // additional constraints on boundary rows to ensure completeness of proven rows
        // (i.e., that we look at all the rows with primary and secondary index values in the query range)

        let left_boundary_row = query_proof.left_boundary_row_target();

        // 1. Either the index tree node of left boundary row has no predecessor, or
        //    the value of the predecessor is smaller than MIN_primary
        let smaller_than_min_primary = b.is_less_than_u256(
            &left_boundary_row.index_node_info.predecessor_info.value,
            &query_proof.min_primary_target(),
        );
        // assert not pQ.left_boundary_row.index_node_data.predecessor_info.is_found or
        // pQ.left_boundary_row.index_node_data.predecessor_value < pQ.MIN_primary
        let constraint = b.and(
            left_boundary_row.index_node_info.predecessor_info.is_found,
            smaller_than_min_primary,
        );
        b.connect(
            left_boundary_row
                .index_node_info
                .predecessor_info
                .is_found
                .target,
            constraint.target,
        );

        // 2. Either the rows tree node storing left boundary row has no predecessor, or
        //    the value of the predecessor is smaller than MIN_secondary
        let smaller_than_min_secondary = b.is_less_than_u256(
            &left_boundary_row.row_node_info.predecessor_info.value,
            &query_proof.min_secondary_target(),
        );
        // assert not pQ.left_boundary_row.row_node_data.predecessor_info.is_found or
        // pQ.left_boundary_row.row_node_data.predecessor_value < pQ.MIN_secondary
        let constraint = b.and(
            left_boundary_row.row_node_info.predecessor_info.is_found,
            smaller_than_min_secondary,
        );
        b.connect(
            left_boundary_row
                .row_node_info
                .predecessor_info
                .is_found
                .target,
            constraint.target,
        );

        let right_boundary_row = query_proof.right_boundary_row_target();

        // 3. Either the index tree node of right boundary row has no successor, or
        //    the value of the successor is greater than MAX_primary
        let greater_than_max_primary = b.is_greater_than_u256(
            &right_boundary_row.index_node_info.successor_info.value,
            &query_proof.max_primary_target(),
        );
        // assert not pQ.right_boundary_row.index_node_data.successor_info.is_found or
        // pQ.right_boundary_row.index_node_data.successor_value > pQ.MAX_primary
        let constraint = b.and(
            right_boundary_row.index_node_info.successor_info.is_found,
            greater_than_max_primary,
        );
        b.connect(
            right_boundary_row
                .index_node_info
                .successor_info
                .is_found
                .target,
            constraint.target,
        );

        // 4. Either the rows tree node storing right boundary row has no successor, or
        //    the value of the successor is greater than MAX_secondary
        let greater_than_max_secondary = b.is_greater_than_u256(
            &right_boundary_row.row_node_info.successor_info.value,
            &query_proof.max_secondary_target(),
        );
        // assert not pQ.right_boundary_row.row_node_data.successor_info.is_found or
        // pQ.right_boundary_row.row_node_data.successor_value > pQ.MAX_secondary
        let constraint = b.and(
            right_boundary_row.row_node_info.successor_info.is_found,
            greater_than_max_secondary,
        );
        b.connect(
            right_boundary_row
                .row_node_info
                .successor_info
                .is_found
                .target,
            constraint.target,
        );
        wires
    }

    pub(crate) fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &RevelationWithoutResultsTreeWires<L, S, PH, PP>,
    ) {
        self.0.assign(pw, wires)
    }
}

#[cfg(test)]
mod tests {
    use std::array;

    use alloy::primitives::U256;
    use itertools::Itertools;
    use mp2_common::{
        array::ToField,
        poseidon::{flatten_poseidon_hash_value, H},
        types::CBuilder,
        utils::{FromFields, ToFields},
        C, D, F,
    };
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::types::Field,
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::config::Hasher,
    };
    use rand::{seq::SliceRandom, thread_rng, Rng};

    use crate::{
        ivc::PublicInputs as OriginalTreePublicInputs,
        query::{
            self,
            aggregation::{QueryBoundSource, QueryBounds},
            batching::{
                public_inputs::{
                    tests::gen_values_in_range, PublicInputs as QueryProofPublicInputs,
                    QueryPublicInputs,
                },
                row_chunk::tests::BoundaryRowData,
            },
            computational_hash_ids::AggregationOperation,
            universal_circuit::{
                universal_circuit_inputs::Placeholders, universal_query_gadget::OutputValues,
            },
        },
        revelation::{
            revelation_without_results_tree::{
                RevelationWithoutResultsTreeCircuit, RevelationWithoutResultsTreeWires,
            },
            tests::{compute_results_from_query_proof_outputs, TestPlaceholders},
            PublicInputs, NUM_PREPROCESSING_IO,
        },
        test_utils::{random_aggregation_operations, random_original_tree_proof},
    };

    use super::RevelationCircuitBatching;

    // L: maximum number of results
    // S: maximum number of items in each result
    // PH: maximum number of unique placeholder IDs and values bound for query
    // PP: maximum number of placeholders present in query (may be duplicate, PP >= PH)
    const L: usize = 5;
    const S: usize = 10;
    const PH: usize = 10;
    const PP: usize = 20;

    // Real number of the placeholders
    const NUM_PLACEHOLDERS: usize = 6;

    const QUERY_PI_LEN: usize = QueryProofPublicInputs::<F, S>::total_len();

    #[derive(Clone, Debug)]
    struct TestRevelationBatchingCircuit<'a> {
        c: RevelationWithoutResultsTreeCircuit<L, S, PH, PP>,
        query_proof: &'a [F],
        original_tree_proof: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestRevelationBatchingCircuit<'a> {
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

            let wires = RevelationCircuitBatching::build(b, &query_pi, &original_tree_pi);

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
        let [mut proof] = QueryProofPublicInputs::sample_from_ops(ops);

        let [count_range, min_query_primary, max_query_primary, min_query_secondary, max_query_secondary, p_hash_range, left_row_range, right_row_range] =
            [
                QueryPublicInputs::NumMatching,
                QueryPublicInputs::MinPrimary,
                QueryPublicInputs::MaxPrimary,
                QueryPublicInputs::MinSecondary,
                QueryPublicInputs::MaxSecondary,
                QueryPublicInputs::PlaceholderHash,
                QueryPublicInputs::LeftBoundaryRow,
                QueryPublicInputs::RightBoundaryRow,
            ]
            .map(QueryProofPublicInputs::<F, S>::to_range);

        // Set the count, minimum, maximum query and the placeholder hash.
        [
            (count_range, vec![entry_count.to_field()]),
            (min_query_primary, test_placeholders.min_query.to_fields()),
            (max_query_primary, test_placeholders.max_query.to_fields()),
            (
                p_hash_range,
                test_placeholders.query_placeholder_hash.to_fields(),
            ),
        ]
        .into_iter()
        .for_each(|(range, fields)| proof[range].copy_from_slice(&fields));

        // Set boundary rows to satisfy constraints for completeness
        let rng = &mut thread_rng();
        let min_secondary = U256::from_fields(&proof[min_query_secondary]);
        let max_secondary = U256::from_fields(&proof[max_query_secondary]);
        let placeholders =
            Placeholders::new_empty(test_placeholders.min_query, test_placeholders.max_query);
        let query_bounds = QueryBounds::new(
            &placeholders,
            Some(QueryBoundSource::Constant(min_secondary)),
            Some(QueryBoundSource::Constant(max_secondary)),
        )
        .unwrap();
        let mut left_boundary_row = BoundaryRowData::sample(rng, &query_bounds);
        // for predecessor of `left_boundary_row` in index tree, we need to either mark it as
        // non-existent or to make its value out of range
        if rng.gen() || query_bounds.min_query_primary() == U256::ZERO {
            left_boundary_row.index_node_info.predecessor_info.is_found = false;
        } else {
            let [predecessor_value] = gen_values_in_range(
                rng,
                U256::ZERO,
                query_bounds.min_query_primary() - U256::from(1),
            );
            left_boundary_row.index_node_info.predecessor_info.value = predecessor_value;
        }
        // for predecessor of `left_boundary_row` in rows tree, we need to either mark it as
        // non-existent or to make its value out of range
        if rng.gen() || min_secondary == U256::ZERO {
            left_boundary_row.row_node_info.predecessor_info.is_found = false;
        } else {
            let [predecessor_value] =
                gen_values_in_range(rng, U256::ZERO, min_secondary - U256::from(1));
            left_boundary_row.row_node_info.predecessor_info.value = predecessor_value;
        }
        let mut right_boundary_row = BoundaryRowData::sample(rng, &query_bounds);
        // for successor of `right_boundary_row` in index tree, we need to either mark it as
        // non-existent or to make its value out of range
        if rng.gen() || query_bounds.max_query_primary() == U256::MAX {
            right_boundary_row.index_node_info.successor_info.is_found = false;
        } else {
            let [successor_value] = gen_values_in_range(
                rng,
                query_bounds.max_query_primary() + U256::from(1),
                U256::MAX,
            );
            right_boundary_row.index_node_info.successor_info.value = successor_value;
        }
        // for successor of `right_boundary_row` in rows tree, we need to either mark it as
        // non-existent or to make its value out of range
        if rng.gen() || max_secondary == U256::MAX {
            right_boundary_row.row_node_info.successor_info.is_found = false;
        } else {
            let [successor_value] =
                gen_values_in_range(rng, max_secondary + U256::from(1), U256::MAX);
            right_boundary_row.row_node_info.successor_info.value = successor_value;
        }

        proof[left_row_range].copy_from_slice(&left_boundary_row.to_fields());
        proof[right_row_range].copy_from_slice(&right_boundary_row.to_fields());

        proof
    }

    /// Utility function for testing the revelation circuit with results tree
    fn test_revelation_batching_circuit(ops: &[F; S], entry_count: Option<u32>) {
        let rng = &mut thread_rng();

        // Generate the testing placeholder data.
        let test_placeholders = TestPlaceholders::sample(NUM_PLACEHOLDERS);

        // Generate the query proof.
        let entry_count = entry_count.unwrap_or_else(|| rng.gen());
        let query_proof = random_query_proof(entry_count, ops, &test_placeholders);
        let query_pi = QueryProofPublicInputs::<_, S>::from_slice(&query_proof);

        // Generate the original tree proof (IVC proof).
        let original_tree_proof = random_original_tree_proof(query_pi.tree_hash());
        let original_tree_pi = OriginalTreePublicInputs::from_slice(&original_tree_proof);

        // Construct the test circuit.
        let test_circuit = TestRevelationBatchingCircuit {
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

            assert_eq!(
                pi.flat_computational_hash(),
                flatten_poseidon_hash_value(exp_hash),
            );
        }
        // Number of placeholders
        assert_eq!(
            pi.num_placeholders(),
            test_placeholders
                .check_placeholder_inputs
                .num_placeholders
                .to_field()
        );
        // Placeholder values
        assert_eq!(
            pi.placeholder_values(),
            test_placeholders
                .check_placeholder_inputs
                .placeholder_values
        );
        // Entry count
        assert_eq!(pi.entry_count(), entry_count);
        // check results
        let result = compute_results_from_query_proof_outputs(
            query_pi.num_matching_rows(),
            OutputValues::<S>::from_fields(query_pi.to_values_raw()),
            &query_pi.operation_ids(),
        );
        let mut exp_results = [[U256::ZERO; S]; L];
        exp_results[0] = result;
        assert_eq!(pi.result_values(), exp_results);
        // overflow flag
        assert_eq!(pi.overflow_flag(), query_pi.overflow_flag());
        // Query limit
        assert_eq!(pi.query_limit(), F::ZERO);
        // Query offset
        assert_eq!(pi.query_offset(), F::ZERO);
    }

    #[test]
    fn test_revelation_batching_simple() {
        // Generate the random operations and set the first operation to SUM
        // (not ID which should not be present in the aggregation).
        let mut ops: [_; S] = random_aggregation_operations();
        ops[0] = AggregationOperation::SumOp.to_field();

        test_revelation_batching_circuit(&ops, None);
    }

    // Test for COUNT operation.
    #[test]
    fn test_revelation_batching_for_op_count() {
        // Set the first operation to COUNT.
        let mut ops: [_; S] = random_aggregation_operations();
        ops[0] = AggregationOperation::CountOp.to_field();

        test_revelation_batching_circuit(&ops, None);
    }

    // Test for AVG operation.
    #[test]
    fn test_revelation_batching_for_op_avg() {
        // Set the first operation to AVG.
        let mut ops: [_; S] = random_aggregation_operations();
        ops[0] = AggregationOperation::AvgOp.to_field();

        test_revelation_batching_circuit(&ops, None);
    }

    // Test for AVG operation with zero entry count.
    #[test]
    fn test_revelation_batching_for_op_avg_with_no_entries() {
        // Set the first operation to AVG.
        let mut ops: [_; S] = random_aggregation_operations();
        ops[0] = AggregationOperation::AvgOp.to_field();

        test_revelation_batching_circuit(&ops, Some(0));
    }

    // Test for no AVG operation with zero entry count.
    #[test]
    fn test_revelation_batching_for_no_op_avg_with_no_entries() {
        // Initialize the all operations to SUM or COUNT (not AVG).
        let mut rng = thread_rng();
        let ops = array::from_fn(|_| {
            [AggregationOperation::SumOp, AggregationOperation::CountOp]
                .choose(&mut rng)
                .unwrap()
                .to_field()
        });

        test_revelation_batching_circuit(&ops, Some(0));
    }
}
