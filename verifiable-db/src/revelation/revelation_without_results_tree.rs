//! The revelation circuit handling the queries where we don't need to build the results tree

use crate::{
    ivc::PublicInputs as OriginalTreePublicInputs,
    query::{
        computational_hash_ids::AggregationOperation, pi_len as query_pi_len,
        public_inputs::PublicInputsQueryCircuits as QueryProofPublicInputs,
    },
    revelation::PublicInputs,
    CBuilder, C, D, F, H,
};
use anyhow::Result;
use itertools::Itertools;
use mp2_common::{
    array::ToField,
    default_config,
    poseidon::flatten_poseidon_hash_target,
    proof::ProofWithVK,
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    u256::{CircuitBuilderU256, UInt256Target},
    utils::ToTargets,
};
use plonky2::{
    iop::{
        target::Target,
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

use super::{
    pi_len as revelation_pi_len,
    placeholders_check::{CheckPlaceholderGadget, CheckPlaceholderInputWires},
    NUM_PREPROCESSING_IO,
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
    check_placeholder: CheckPlaceholderInputWires<PH, PP>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevelationWithoutResultsTreeCircuit<
    const L: usize,
    const S: usize,
    const PH: usize,
    const PP: usize,
> {
    pub(crate) check_placeholder: CheckPlaceholderGadget<PH, PP>,
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

        // The operation cannot be ID for aggregation.
        let [op_avg, op_count] = [AggregationOperation::AvgOp, AggregationOperation::CountOp]
            .map(|op| b.constant(op.to_field()));

        // Convert the entry count to an Uint256.
        let entry_count = UInt256Target::new_from_target(b, query_proof.num_matching_rows_target());

        // Compute the output results array, and deal with AVG and COUNT operations if any.
        let mut results = Vec::with_capacity(L * S);
        // flag to determine whether entry count is zero
        let is_entry_count_zero = b.add_virtual_bool_target_unsafe();
        query_proof
            .operation_ids_target()
            .into_iter()
            .enumerate()
            .for_each(|(i, op)| {
                let is_op_avg = b.is_equal(op, op_avg);
                let is_op_count = b.is_equal(op, op_count);
                let result = query_proof.value_target_at_index(i);

                // Compute the AVG result (and it's set to zero if the divisor is zero).
                let (avg_result, _, is_divisor_zero) = b.div_u256(&result, &entry_count);

                let result = b.select_u256(is_op_avg, &avg_result, &result);
                let result = b.select_u256(is_op_count, &entry_count, &result);

                b.connect(is_divisor_zero.target, is_entry_count_zero.target);

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
            .chain(query_proof.min_primary_target().to_targets())
            .chain(query_proof.max_primary_target().to_targets())
            .collect();
        let final_placeholder_hash = b.hash_n_to_hash_no_pad::<H>(inputs);

        // Check the placeholder data.
        let check_placeholder_wires =
            CheckPlaceholderGadget::<PH, PP>::build(b, &final_placeholder_hash);

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
            .computational_hash_target()
            .to_targets()
            .iter()
            .chain(&check_placeholder_wires.placeholder_id_hash.to_targets())
            .chain(original_tree_proof.metadata_hash())
            .cloned()
            .collect();
        let computational_hash = b.hash_n_to_hash_no_pad::<H>(inputs);

        let placeholder_values_slice = check_placeholder_wires
            .input_wires
            .placeholder_values
            .iter()
            .flat_map(ToTargets::to_targets)
            .collect_vec();
        let results_slice = results.iter().flat_map(ToTargets::to_targets).collect_vec();

        let num_results = b.not(is_entry_count_zero);

        let flat_computational_hash = flatten_poseidon_hash_target(b, computational_hash);

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

        // Register the public innputs.
        PublicInputs::<_, L, S, PH>::new(
            &original_tree_proof.block_hash(),
            &flat_computational_hash,
            &placeholder_values_slice,
            &results_slice,
            &[check_placeholder_wires.num_placeholders],
            // The aggregation query proof only has one result.
            &[num_results.target],
            &[query_proof.num_matching_rows_target()],
            &[query_proof.overflow_flag_target().target],
            // Query limit
            &[zero],
            // Query offset
            &[zero],
        )
        .register(b);

        RevelationWithoutResultsTreeWires {
            check_placeholder: check_placeholder_wires.input_wires,
        }
    }

    pub(crate) fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &RevelationWithoutResultsTreeWires<L, S, PH, PP>,
    ) {
        self.check_placeholder.assign(pw, &wires.check_placeholder);
    }
}
#[derive(Clone, Debug)]
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
    [(); query_pi_len::<S>()]:,
    [(); <H as Hasher<F>>::HASH_SIZE]:,
{
    type CircuitBuilderParams = CircuitBuilderParams;

    type Inputs = RecursiveCircuitInputs<L, S, PH, PP>;

    const NUM_PUBLIC_INPUTS: usize = revelation_pi_len::<L, S, PH>();

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let query_verifier =
            RecursiveCircuitsVerifierGagdet::<F, C, D, { query_pi_len::<S>() }>::new(
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
        let preprocessing_pi =
            OriginalTreePublicInputs::from_slice(&preprocessing_proof.public_inputs);
        let revelation_circuit = {
            let query_pi = QueryProofPublicInputs::from_slice(
                query_verifier.get_public_input_targets::<F, { query_pi_len::<S>() }>(),
            );
            RevelationWithoutResultsTreeCircuit::build(builder, &query_pi, &preprocessing_pi)
        };

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
    use std::array;

    use crate::{CBuilder, C, D, F, H};
    use alloy::primitives::U256;
    use itertools::Itertools;
    use mp2_common::{
        array::ToField,
        poseidon::flatten_poseidon_hash_value,
        utils::{FromFields, ToFields},
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
            computational_hash_ids::AggregationOperation,
            public_inputs::{
                PublicInputsQueryCircuits as QueryProofPublicInputs, QueryPublicInputs,
            },
            universal_circuit::{
                universal_circuit_inputs::Placeholders, universal_query_gadget::OutputValues,
            },
            utils::{QueryBoundSource, QueryBounds},
        },
        revelation::{
            revelation_without_results_tree::{
                RevelationWithoutResultsTreeCircuit, RevelationWithoutResultsTreeWires,
            },
            tests::{compute_results_from_query_proof_outputs, TestPlaceholders},
            PublicInputs, NUM_PREPROCESSING_IO,
        },
        test_utils::{
            random_aggregation_operations, random_original_tree_proof,
            sample_boundary_rows_for_revelation,
        },
    };

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

    impl From<&TestPlaceholders<PH, PP>> for RevelationWithoutResultsTreeCircuit<L, S, PH, PP> {
        fn from(test_placeholders: &TestPlaceholders<PH, PP>) -> Self {
            Self {
                check_placeholder: test_placeholders.check_placeholder_inputs.clone(),
            }
        }
    }

    #[derive(Clone, Debug)]
    struct TestRevelationCircuit<'a> {
        c: RevelationWithoutResultsTreeCircuit<L, S, PH, PP>,
        query_proof: &'a [F],
        original_tree_proof: &'a [F],
    }

    impl UserCircuit<F, D> for TestRevelationCircuit<'_> {
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
        let (left_boundary_row, right_boundary_row) =
            sample_boundary_rows_for_revelation(&query_bounds, rng);

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
        let test_circuit = TestRevelationCircuit {
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
