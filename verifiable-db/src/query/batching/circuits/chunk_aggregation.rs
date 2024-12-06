use anyhow::Result;
use std::array;

use itertools::Itertools;
use mp2_common::{
    proof::ProofWithVK,
    public_inputs::PublicInputCommon,
    serialization::{
        deserialize_array, deserialize_long_array, serialize_array, serialize_long_array,
    },
    u256::CircuitBuilderU256,
    utils::ToTargets,
    D, F,
};
use plonky2::{
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, proof::ProofWithPublicInputsTarget},
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use crate::query::{
    batching::row_chunk::aggregate_chunks::aggregate_chunks, pi_len, public_inputs::PublicInputs
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkAggregationWires<const NUM_CHUNKS: usize, const MAX_NUM_RESULTS: usize> {
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    /// Boolean flag specifying whether the i-th chunk is dummy or not
    is_non_dummy_chunk: [BoolTarget; NUM_CHUNKS],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkAggregationCircuit<const NUM_CHUNKS: usize, const MAX_NUM_RESULTS: usize> {
    /// Number of non-dummy chunks to be aggregated. Must be at
    /// most `NUM_CHUNKS`
    pub(crate) num_non_dummy_chunks: usize,
}

impl<const NUM_CHUNKS: usize, const MAX_NUM_RESULTS: usize>
    ChunkAggregationCircuit<NUM_CHUNKS, MAX_NUM_RESULTS>
{
    pub(crate) fn build(
        b: &mut CircuitBuilder<F, D>,
        chunk_proofs: &[PublicInputs<Target, MAX_NUM_RESULTS>; NUM_CHUNKS],
    ) -> ChunkAggregationWires<NUM_CHUNKS, MAX_NUM_RESULTS>
    where
        [(); MAX_NUM_RESULTS - 1]:,
    {
        let is_non_dummy_chunk = array::from_fn(|_| b.add_virtual_bool_target_safe());

        // Enforce the first chunk is non-dummy
        b.assert_one(is_non_dummy_chunk[0].target);

        // build `RowChunkDataTarget` for first chunk
        let mut row_chunk = chunk_proofs[0].to_row_chunk_target();
        // save query bounds of first chunk to check that they are the same across
        // all the aggregated chunks
        let min_query_primary = chunk_proofs[0].min_primary_target();
        let max_query_primary = chunk_proofs[0].max_primary_target();
        let min_query_secondary = chunk_proofs[0].min_secondary_target();
        let max_query_secondary = chunk_proofs[0].max_secondary_target();
        // save computational hash and placeholder hash of the first chunk to check
        // that they are the same across all the aggregated chunks
        let computational_hash = chunk_proofs[0].computational_hash_target();
        let placeholder_hash = chunk_proofs[0].placeholder_hash_target();
        // save identifiers of aggregation operations of the first chunk to check
        // that they are the same across all the aggregated chunks
        let ops_ids = chunk_proofs[0].operation_ids_target();
        for i in 1..NUM_CHUNKS {
            let chunk_proof = &chunk_proofs[i];

            let current_chunk = chunk_proof.to_dummy_row_chunk_target(b, is_non_dummy_chunk[i]);
            row_chunk = aggregate_chunks(
                b,
                &row_chunk,
                &current_chunk,
                (&min_query_primary, &max_query_primary),
                (&min_query_secondary, &max_query_secondary),
                &ops_ids,
                &is_non_dummy_chunk[i],
            );
            // check the query bounds employed to prove the current chunk are the same
            // as all other chunks
            b.enforce_equal_u256(&chunk_proof.min_primary_target(), &min_query_primary);
            b.enforce_equal_u256(&chunk_proof.max_primary_target(), &max_query_primary);
            b.enforce_equal_u256(&chunk_proof.min_secondary_target(), &min_query_secondary);
            b.enforce_equal_u256(&chunk_proof.max_secondary_target(), &max_query_secondary);
            // check the same computational hash is associated to rows processed
            // in all the chunks
            b.connect_hashes(chunk_proof.computational_hash_target(), computational_hash);
            // check the same placeholder hash is associated to rows processed in
            // all the chunks
            b.connect_hashes(chunk_proof.placeholder_hash_target(), placeholder_hash);
            // check the same set of aggregation operations have been employed
            // in all the chunks
            chunk_proof
                .operation_ids_target()
                .into_iter()
                .zip_eq(ops_ids)
                .for_each(|(current_op, op)| b.connect(current_op, op));
        }

        let overflow_flag = {
            let zero = b.zero();
            b.is_not_equal(row_chunk.chunk_outputs.num_overflows, zero)
        };

        PublicInputs::<Target, MAX_NUM_RESULTS>::new(
            &row_chunk.chunk_outputs.tree_hash.to_targets(),
            &row_chunk.chunk_outputs.values.to_targets(),
            &[row_chunk.chunk_outputs.count],
            &ops_ids,
            &row_chunk.left_boundary_row.to_targets(),
            &row_chunk.right_boundary_row.to_targets(),
            &min_query_primary.to_targets(),
            &max_query_primary.to_targets(),
            &min_query_secondary.to_targets(),
            &max_query_secondary.to_targets(),
            &[overflow_flag.target],
            &computational_hash.to_targets(),
            &placeholder_hash.to_targets(),
        )
        .register(b);

        ChunkAggregationWires { is_non_dummy_chunk }
    }

    pub(crate) fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &ChunkAggregationWires<NUM_CHUNKS, MAX_NUM_RESULTS>,
    ) {
        wires
            .is_non_dummy_chunk
            .iter()
            .enumerate()
            .for_each(|(i, wire)| pw.set_bool_target(*wire, i < self.num_non_dummy_chunks));
    }
}

impl<const NUM_CHUNKS: usize, const MAX_NUM_RESULTS: usize> CircuitLogicWires<F, D, NUM_CHUNKS>
    for ChunkAggregationWires<NUM_CHUNKS, MAX_NUM_RESULTS>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    type CircuitBuilderParams = ();

    type Inputs = ChunkAggregationCircuit<NUM_CHUNKS, MAX_NUM_RESULTS>;

    const NUM_PUBLIC_INPUTS: usize = pi_len::<MAX_NUM_RESULTS>();

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; NUM_CHUNKS],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let pis = verified_proofs.map(|proof| PublicInputs::from_slice(&proof.public_inputs));
        ChunkAggregationCircuit::build(builder, &pis)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkAggregationInputs<const NUM_CHUNKS: usize, const MAX_NUM_RESULTS: usize> {
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) chunk_proofs: [ProofWithVK; NUM_CHUNKS],
    pub(crate) circuit: ChunkAggregationCircuit<NUM_CHUNKS, MAX_NUM_RESULTS>,
}

#[cfg(test)]
mod tests {
    use std::array;

    use itertools::Itertools;
    use mp2_common::{array::ToField, utils::FromFields, C, D, F};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::types::Field,
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::circuit_builder::CircuitBuilder,
    };

    use crate::{
        query::{
            aggregation::tests::aggregate_output_values,
            public_inputs::PublicInputs,
            computational_hash_ids::{AggregationOperation, Identifiers},
            universal_circuit::universal_query_gadget::OutputValues,
        },
        test_utils::random_aggregation_operations,
    };

    use super::{ChunkAggregationCircuit, ChunkAggregationWires};

    const MAX_NUM_RESULTS: usize = 10;
    const NUM_CHUNKS: usize = 5;

    #[derive(Clone, Debug)]
    struct TestChunkAggregationWires<const NUM_CHUNKS: usize, const MAX_NUM_RESULTS: usize> {
        pis: [Vec<Target>; NUM_CHUNKS],
        inputs: ChunkAggregationWires<NUM_CHUNKS, MAX_NUM_RESULTS>,
    }

    #[derive(Clone, Debug)]
    struct TestChunkAggregationCircuit<const NUM_CHUNKS: usize, const MAX_NUM_RESULTS: usize> {
        pis: [Vec<F>; NUM_CHUNKS],
        inputs: ChunkAggregationCircuit<NUM_CHUNKS, MAX_NUM_RESULTS>,
    }

    impl<const NUM_CHUNKS: usize, const MAX_NUM_RESULTS: usize>
        TestChunkAggregationCircuit<NUM_CHUNKS, MAX_NUM_RESULTS>
    {
        fn new(pis: &[Vec<F>]) -> Self {
            assert!(
                !pis.is_empty(),
                "there should be at least one chunk to prove"
            );
            let dummy_pi = pis.last().unwrap();
            let inputs = ChunkAggregationCircuit {
                num_non_dummy_chunks: pis.len(),
            };
            let pis = array::from_fn(|i| pis.get(i).unwrap_or(dummy_pi).clone());
            Self { pis, inputs }
        }
    }

    impl<const NUM_CHUNKS: usize, const MAX_NUM_RESULTS: usize> UserCircuit<F, D>
        for TestChunkAggregationCircuit<NUM_CHUNKS, MAX_NUM_RESULTS>
    where
        [(); MAX_NUM_RESULTS - 1]:,
    {
        type Wires = TestChunkAggregationWires<NUM_CHUNKS, MAX_NUM_RESULTS>;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let raw_pis = array::from_fn(|_| {
                c.add_virtual_targets(PublicInputs::<Target, MAX_NUM_RESULTS>::total_len())
            });
            let pis = raw_pis
                .iter()
                .map(|pi| PublicInputs::from_slice(pi))
                .collect_vec()
                .try_into()
                .unwrap();
            let inputs = ChunkAggregationCircuit::build(c, &pis);

            TestChunkAggregationWires {
                pis: raw_pis,
                inputs,
            }
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.inputs.assign(pw, &wires.inputs);
            self.pis
                .iter()
                .zip_eq(&wires.pis)
                .for_each(|(values, targets)| pw.set_target_arr(targets, values));
        }
    }

    fn test_chunk_aggregation_circuit(first_op_id: bool, dummy_chunks: bool) {
        let mut ops = random_aggregation_operations();
        if first_op_id {
            ops[0] = Identifiers::AggregationOperations(AggregationOperation::IdOp).to_field()
        }
        let raw_pis = if dummy_chunks {
            // if we test with dummy chunks to be aggregated, we generate `ACTUAL_NUM_CHUNKS <= NUM_CHUNKS`
            // inputs, so that the remaining `NUM_CHUNKS - ACTUAL_NUM_CHUNKS` input slots are dummies
            const NUM_ACTUAL_CHUNKS: usize = 3;
            PublicInputs::<F, MAX_NUM_RESULTS>::sample_from_ops::<NUM_ACTUAL_CHUNKS>(&ops).to_vec()
        } else {
            PublicInputs::<F, MAX_NUM_RESULTS>::sample_from_ops::<NUM_CHUNKS>(&ops).to_vec()
        };

        let circuit = TestChunkAggregationCircuit::<NUM_CHUNKS, MAX_NUM_RESULTS>::new(&raw_pis);

        let proof = run_circuit::<F, D, C, _>(circuit);

        let input_pis = raw_pis
            .iter()
            .map(|pi| PublicInputs::<F, MAX_NUM_RESULTS>::from_slice(pi))
            .collect_vec();

        let (expected_outputs, expected_overflow) = {
            let outputs = input_pis
                .iter()
                .map(|pi| OutputValues::<MAX_NUM_RESULTS>::from_fields(pi.to_values_raw()))
                .collect_vec();
            let mut num_overflows = input_pis
                .iter()
                .fold(0, |acc, pi| pi.overflow_flag() as u32 + acc);
            let expected_outputs = ops
                .into_iter()
                .enumerate()
                .flat_map(|(i, op)| {
                    let (out_value, overflows) = aggregate_output_values(i, &outputs, op);
                    num_overflows += overflows;
                    out_value
                })
                .collect_vec();
            (
                OutputValues::<MAX_NUM_RESULTS>::from_fields(&expected_outputs),
                num_overflows != 0,
            )
        };

        let expected_count = input_pis
            .iter()
            .fold(F::ZERO, |acc, pi| pi.num_matching_rows() + acc);
        let expected_left_row = input_pis[0].to_left_row_raw();
        let expected_right_row = input_pis.last().unwrap().to_right_row_raw();

        let result_pis = PublicInputs::<F, MAX_NUM_RESULTS>::from_slice(&proof.public_inputs);

        // check public inputs
        assert_eq!(
            result_pis.tree_hash(),
            input_pis[0].tree_hash(), // tree hash is the same for all input_pis
        );
        assert_eq!(result_pis.operation_ids(), ops,);
        assert_eq!(result_pis.num_matching_rows(), expected_count,);
        // check aggregated outputs
        if ops[0] == Identifiers::AggregationOperations(AggregationOperation::IdOp).to_field() {
            assert_eq!(
                result_pis.first_value_as_curve_point(),
                expected_outputs.first_value_as_curve_point(),
            )
        } else {
            assert_eq!(
                result_pis.first_value_as_u256(),
                expected_outputs.first_value_as_u256(),
            )
        };
        (1..MAX_NUM_RESULTS).for_each(|i| {
            assert_eq!(
                result_pis.value_at_index(i),
                expected_outputs.value_at_index(i)
            )
        });
        // check boundary rows
        assert_eq!(result_pis.to_left_row_raw(), expected_left_row,);
        assert_eq!(result_pis.to_right_row_raw(), expected_right_row,);
        // check query bounds
        assert_eq!(
            result_pis.min_primary(),
            input_pis[0].min_primary(), // query bounds are all the same in all `input_pis`
        );
        assert_eq!(
            result_pis.max_primary(),
            input_pis[0].max_primary(), // query bounds are all the same in all `input_pis`
        );
        assert_eq!(
            result_pis.min_secondary(),
            input_pis[0].min_secondary(), // query bounds are all the same in all `input_pis`
        );
        assert_eq!(
            result_pis.max_secondary(),
            input_pis[0].max_secondary(), // query bounds are all the same in all `input_pis`
        );
        // check overflow error
        assert_eq!(result_pis.overflow_flag(), expected_overflow,);
        // check computational hash
        assert_eq!(
            result_pis.computational_hash(),
            input_pis[0].computational_hash(), // computational hash is the same in all `input_pis`
        );
        // check placeholder hash
        assert_eq!(
            result_pis.placeholder_hash(),
            input_pis[0].placeholder_hash(),
        );
    }

    #[test]
    fn test_chunk_aggregation_no_dummy_chunks() {
        test_chunk_aggregation_circuit(false, false);
    }

    #[test]
    fn test_chunk_aggregation_dummy_chunks() {
        test_chunk_aggregation_circuit(false, true);
    }

    #[test]
    fn test_chunk_aggregation_no_dummy_chunks_id_op() {
        test_chunk_aggregation_circuit(true, false);
    }

    #[test]
    fn test_chunk_aggregation_dummy_chunks_id_op() {
        test_chunk_aggregation_circuit(true, true);
    }
}
