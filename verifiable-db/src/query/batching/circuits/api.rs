use std::iter::{repeat, repeat_with};

use anyhow::{ensure, Result};

use itertools::Itertools;
use mp2_common::{array::ToField, proof::ProofWithVK, types::HashOutput, C, D, F};
use plonky2::iop::target::Target;
use recursion_framework::{
    circuit_builder::CircuitWithUniversalVerifier, framework::RecursiveCircuits,
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "batching_circuits")]
use mp2_common::{default_config, poseidon::H};
#[cfg(feature = "batching_circuits")]
use plonky2::plonk::config::Hasher;
#[cfg(feature = "batching_circuits")]
use recursion_framework::{
    circuit_builder::CircuitWithUniversalVerifierBuilder,
    framework::prepare_recursive_circuit_for_circuit_set,
};

use crate::query::{
    aggregation::{ChildPosition, NodeInfo, QueryBounds, QueryHashNonExistenceCircuits},
    batching::{
        circuits::chunk_aggregation::ChunkAggregationCircuit, public_inputs::PublicInputs,
        row_process_gadget::RowProcessingGadgetInputs,
    },
    computational_hash_ids::{AggregationOperation, ColumnIDs, Identifiers},
    universal_circuit::{
        output_with_aggregation::Circuit as OutputAggCircuit,
        universal_circuit_inputs::{BasicOperation, Placeholders, ResultStructure, RowCells},
    },
};

use super::{
    chunk_aggregation::{ChunkAggregationInputs, ChunkAggregationWires},
    non_existence::{NonExistenceCircuit, NonExistenceWires},
    row_chunk_processing::{RowChunkProcessingCircuit, RowChunkProcessingWires},
};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Parameters<
    const NUM_CHUNKS: usize,
    const NUM_ROWS: usize,
    const ROW_TREE_MAX_DEPTH: usize,
    const INDEX_TREE_MAX_DEPTH: usize,
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
> where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); MAX_NUM_RESULTS - 1]:,
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
{
    row_chunk_agg_circuit: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        0,
        RowChunkProcessingWires<
            NUM_ROWS,
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            OutputAggCircuit<MAX_NUM_RESULTS>,
        >,
    >,
    //ToDo: add row_chunk_circuit for queries without aggregation, once we integrate results tree
    aggregation_circuit: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        NUM_CHUNKS,
        ChunkAggregationWires<NUM_CHUNKS, MAX_NUM_RESULTS>,
    >,
    non_existence_circuit: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        0,
        NonExistenceWires<INDEX_TREE_MAX_DEPTH, MAX_NUM_RESULTS>,
    >,
    circuit_set: RecursiveCircuits<F, C, D>,
}

pub const fn num_io<const S: usize>() -> usize {
    PublicInputs::<Target, S>::total_len()
}
#[cfg(feature = "batching_circuits")]
impl<
        const NUM_CHUNKS: usize,
        const NUM_ROWS: usize,
        const ROW_TREE_MAX_DEPTH: usize,
        const INDEX_TREE_MAX_DEPTH: usize,
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_PREDICATE_OPS: usize,
        const MAX_NUM_RESULT_OPS: usize,
        const MAX_NUM_RESULTS: usize,
    >
    Parameters<
        NUM_CHUNKS,
        NUM_ROWS,
        ROW_TREE_MAX_DEPTH,
        INDEX_TREE_MAX_DEPTH,
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
    >
where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); MAX_NUM_RESULTS - 1]:,
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
    [(); <H as Hasher<F>>::HASH_SIZE]:,
    [(); num_io::<MAX_NUM_RESULTS>()]:,
{
    const CIRCUIT_SET_SIZE: usize = 3;

    pub(crate) fn build() -> Self {
        let builder =
            CircuitWithUniversalVerifierBuilder::<F, D, { num_io::<MAX_NUM_RESULTS>() }>::new::<C>(
                default_config(),
                Self::CIRCUIT_SET_SIZE,
            );
        let row_chunk_agg_circuit = builder.build_circuit(());
        let aggregation_circuit = builder.build_circuit(());
        let non_existence_circuit = builder.build_circuit(());

        let circuits = vec![
            prepare_recursive_circuit_for_circuit_set(&row_chunk_agg_circuit),
            prepare_recursive_circuit_for_circuit_set(&aggregation_circuit),
            prepare_recursive_circuit_for_circuit_set(&non_existence_circuit),
        ];
        let circuit_set = RecursiveCircuits::new(circuits);

        Self {
            row_chunk_agg_circuit,
            aggregation_circuit,
            non_existence_circuit,
            circuit_set,
        }
    }

    pub(crate) fn generate_proof(
        &self,
        input: CircuitInput<
            NUM_CHUNKS,
            NUM_ROWS,
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
        >,
    ) -> Result<Vec<u8>> {
        let proof: ProofWithVK = match input {
            CircuitInput::RowChunkWithAggregation(row_chunk_processing_circuit) => (
                self.circuit_set.generate_proof(
                    &self.row_chunk_agg_circuit,
                    [],
                    [],
                    row_chunk_processing_circuit,
                )?,
                self.row_chunk_agg_circuit
                    .circuit_data()
                    .verifier_only
                    .clone(),
            )
                .into(),
            CircuitInput::ChunkAggregation(chunk_aggregation_inputs) => {
                let ChunkAggregationInputs {
                    chunk_proofs,
                    circuit,
                } = chunk_aggregation_inputs;
                let input_vd = chunk_proofs
                    .iter()
                    .map(|p| p.verifier_data())
                    .cloned()
                    .collect_vec();
                let input_proofs = chunk_proofs.map(|p| p.proof);
                (
                    self.circuit_set.generate_proof(
                        &self.aggregation_circuit,
                        input_proofs,
                        input_vd.iter().collect_vec().try_into().unwrap(),
                        circuit,
                    )?,
                    self.aggregation_circuit
                        .circuit_data()
                        .verifier_only
                        .clone(),
                )
                    .into()
            }
            CircuitInput::NonExistence(non_existence_circuit) => (
                self.circuit_set.generate_proof(
                    &self.non_existence_circuit,
                    [],
                    [],
                    non_existence_circuit,
                )?,
                self.non_existence_circuit
                    .circuit_data()
                    .verifier_only
                    .clone(),
            )
                .into(),
        };
        proof.serialize()
    }

    pub(crate) fn get_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        &self.circuit_set
    }
}

#[cfg(feature = "batching_circuits")]
#[cfg(test)]
mod tests {
    use alloy::primitives::U256;
    use itertools::Itertools;
    use mp2_common::{
        array::ToField,
        proof::ProofWithVK,
        utils::{FromFields, ToFields},
        F,
    };
    use mp2_test::utils::{gen_random_u256, random_vector};
    use rand::thread_rng;

    use crate::query::{
        aggregation::{
            output_computation::tests::compute_dummy_output_values, tests::aggregate_output_values,
            ChildPosition, QueryBoundSource, QueryBounds,
        },
        batching::{
            circuits::{
                api::{CircuitInput, NodePath, RowInput, TreePathInputs},
                tests::{build_test_tree, compute_output_values_for_row},
            },
            public_inputs::PublicInputs,
            row_chunk::tests::{BoundaryRowData, BoundaryRowNodeInfo},
        },
        computational_hash_ids::{
            AggregationOperation, ColumnIDs, Identifiers, Operation, PlaceholderIdentifier,
        },
        merkle_path::tests::{generate_test_tree, NeighborInfo},
        universal_circuit::{
            universal_circuit_inputs::{
                BasicOperation, ColumnCell, InputOperand, OutputItem, PlaceholderId, Placeholders,
                ResultStructure, RowCells,
            },
            universal_query_circuit::placeholder_hash,
            universal_query_gadget::CurveOrU256,
            ComputationalHash,
        },
    };

    use plonky2::{
        field::types::{Field, PrimeField64},
        plonk::config::GenericHashOut,
    };

    use super::Parameters;

    const NUM_CHUNKS: usize = 4;
    const NUM_ROWS: usize = 3;
    const ROW_TREE_MAX_DEPTH: usize = 10;
    const INDEX_TREE_MAX_DEPTH: usize = 15;
    const MAX_NUM_COLUMNS: usize = 30;
    const MAX_NUM_PREDICATE_OPS: usize = 20;
    const MAX_NUM_RESULT_OPS: usize = 30;
    const MAX_NUM_RESULTS: usize = 10;

    #[tokio::test]
    async fn test_api() {
        const NUM_ACTUAL_COLUMNS: usize = 5;
        // generate a proof for the following query:
        // SELECT AVG(C1/C2), MIN(C1*(C3-4)), MAX(C5%$1), COUNT(C4) FROM T WHERE (C4 > $2 + 4 XOR C3 < C1*C2) AND C2 >= $3*4 AND C2 <= $4 AND C1 >= 2876 AND C1 <= 7894
        let rng = &mut thread_rng();
        let column_ids = random_vector::<u64>(NUM_ACTUAL_COLUMNS);
        let primary_index = F::from_canonical_u64(column_ids[0]);
        let secondary_index = F::from_canonical_u64(column_ids[1]);
        let column_ids = ColumnIDs::new(column_ids[0], column_ids[1], column_ids[2..].to_vec());

        // query bound values
        let min_query_primary = U256::from(2876);
        let max_query_primary = U256::from(7894);
        let min_query_secondary = U256::from(68);
        let max_query_secondary = U256::from(9768443);

        // define placeholders
        let first_placeholder_id = PlaceholderId::Generic(0);
        let second_placeholder_id = PlaceholderIdentifier::Generic(1);
        let mut placeholders = Placeholders::new_empty(min_query_primary, max_query_primary);
        [first_placeholder_id, second_placeholder_id]
            .iter()
            .for_each(|id| placeholders.insert(*id, gen_random_u256(rng)));
        let third_placeholder_id = PlaceholderId::Generic(2);
        // value of $3 is min_secondary/4
        placeholders.insert(third_placeholder_id, min_query_secondary / U256::from(4));
        let fourth_placeholder_id = PlaceholderId::Generic(3);
        // $4 is equal to max_secondary
        placeholders.insert(fourth_placeholder_id, max_query_secondary);
        let bounds = QueryBounds::new(
            &placeholders,
            Some(QueryBoundSource::Operation(BasicOperation {
                first_operand: InputOperand::Placeholder(third_placeholder_id),
                second_operand: Some(InputOperand::Constant(U256::from(4))),
                op: Operation::MulOp,
            })),
            Some(QueryBoundSource::Placeholder(fourth_placeholder_id)),
        )
        .unwrap();

        // build predicate_operations
        let mut predicate_operations = vec![];
        // C4 > $2
        let placeholder_cmp = BasicOperation {
            first_operand: InputOperand::Column(3),
            second_operand: Some(InputOperand::Placeholder(second_placeholder_id)),
            op: Operation::GreaterThanOp,
        };
        predicate_operations.push(placeholder_cmp);
        // C1 * C2
        let column_prod = BasicOperation {
            first_operand: InputOperand::Column(0),
            second_operand: Some(InputOperand::Column(1)),
            op: Operation::MulOp,
        };
        predicate_operations.push(column_prod);
        // C3 < C1*C2
        let cmp_expr = BasicOperation {
            first_operand: InputOperand::Column(2),
            second_operand: Some(InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&predicate_operations, &column_prod)
                    .unwrap(),
            )),
            op: Operation::LessThanOp,
        };
        predicate_operations.push(cmp_expr);
        // C4 > $2 XOR C3 < C1*C2
        let xor_expr = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&predicate_operations, &placeholder_cmp)
                    .unwrap(),
            ),
            second_operand: Some(InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&predicate_operations, &cmp_expr)
                    .unwrap(),
            )),
            op: Operation::XorOp,
        };
        predicate_operations.push(xor_expr);
        // build operations to compute results
        let mut result_operations = vec![];
        // C1/C2
        let column_div = BasicOperation {
            first_operand: InputOperand::Column(0),
            second_operand: Some(InputOperand::Column(1)),
            op: Operation::DivOp,
        };
        result_operations.push(column_div);
        // C3 - 4
        let constant_sub = BasicOperation {
            first_operand: InputOperand::Column(2),
            second_operand: Some(InputOperand::Constant(U256::from(4))),
            op: Operation::SubOp,
        };
        result_operations.push(constant_sub);
        // C1*(C3-4)
        let prod_expr = BasicOperation {
            first_operand: InputOperand::Column(0),
            second_operand: Some(InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&result_operations, &constant_sub)
                    .unwrap(),
            )),
            op: Operation::MulOp,
        };
        result_operations.push(prod_expr);
        // C5 % $1
        let placeholder_mod = BasicOperation {
            first_operand: InputOperand::Column(4),
            second_operand: Some(InputOperand::Placeholder(first_placeholder_id)),
            op: Operation::ModOp,
        };
        result_operations.push(placeholder_mod);
        let output_items = vec![
            OutputItem::ComputedValue(
                BasicOperation::locate_previous_operation(&result_operations, &column_div).unwrap(),
            ),
            OutputItem::ComputedValue(
                BasicOperation::locate_previous_operation(&result_operations, &prod_expr).unwrap(),
            ),
            OutputItem::ComputedValue(
                BasicOperation::locate_previous_operation(&result_operations, &placeholder_mod)
                    .unwrap(),
            ),
            OutputItem::Column(3),
        ];
        let output_ops: [F; 4] = [
            AggregationOperation::AvgOp.to_field(),
            AggregationOperation::MinOp.to_field(),
            AggregationOperation::MaxOp.to_field(),
            AggregationOperation::CountOp.to_field(),
        ];

        let results = ResultStructure::new_for_query_with_aggregation(
            result_operations,
            output_items,
            output_ops
                .iter()
                .map(|op| op.to_canonical_u64())
                .collect_vec(),
        )
        .unwrap();

        let [node_0, node_1, node_2] = build_test_tree(&bounds, &column_ids.to_vec()).await;

        let params = Parameters::<
            NUM_CHUNKS,
            NUM_ROWS,
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
        >::build();

        let to_row_cells = |values: &[U256]| {
            let column_cells = values
                .iter()
                .zip(column_ids.to_vec().iter())
                .map(|(&value, &id)| ColumnCell { value, id })
                .collect_vec();
            RowCells::new(
                column_cells[0].clone(),
                column_cells[1].clone(),
                column_cells[2..].to_vec(),
            )
        };

        // we split the rows to be proven in chunks:
        // - first chunk with rows 1A and 1C
        // - second chunk with rows 2B, 2D and 2A

        // prove first chunk
        let [node_1a, node_1b, node_1c, node_1d] = node_1
            .rows_tree
            .iter()
            .map(|n| n.node)
            .collect_vec()
            .try_into()
            .unwrap();
        let path_1a = vec![];

        let path_1 = vec![];
        let node_1_children = [Some(node_0.node), Some(node_2.node)];

        let row_path_1a = NodePath::new(
            TreePathInputs::new(node_1a, path_1a, [Some(node_1b), Some(node_1c)]),
            TreePathInputs::new(node_1.node, path_1.clone(), node_1_children),
        );

        let row_cells_1a = to_row_cells(&node_1.rows_tree[0].values);
        let row_1a = RowInput::new(&row_cells_1a, &row_path_1a);

        let path_1c = vec![(node_1a, ChildPosition::Right)];
        let row_path_1c = NodePath::new(
            TreePathInputs::new(node_1c, path_1c, [None, Some(node_1d)]),
            TreePathInputs::new(node_1.node, path_1, node_1_children),
        );

        let row_cells_1c = to_row_cells(&node_1.rows_tree[2].values);
        let row_1c = RowInput::new(&row_cells_1c, &row_path_1c);

        let row_chunk_inputs = CircuitInput::new_row_chunks_input(
            &[row_1a, row_1c],
            &predicate_operations,
            &placeholders,
            &bounds,
            &results,
        )
        .unwrap();

        let expected_placeholder_hash =
            if let CircuitInput::RowChunkWithAggregation(input) = &row_chunk_inputs {
                let placeholder_hash_ids = input.ids_for_placeholder_hash();
                placeholder_hash(&placeholder_hash_ids, &placeholders, &bounds).unwrap()
            } else {
                unreachable!()
            };

        let first_chunk_proof = params.generate_proof(row_chunk_inputs).unwrap();

        // prove second chunk
        let [node_2a, node_2b, node_2c, node_2d] = node_2
            .rows_tree
            .iter()
            .map(|n| n.node)
            .collect_vec()
            .try_into()
            .unwrap();
        let path_2d = vec![
            (node_2b, ChildPosition::Right),
            (node_2a, ChildPosition::Left),
        ];

        let path_2 = vec![(node_1.node, ChildPosition::Right)];
        let node_2_children = [None, None];
        let row_path_2d = NodePath::new(
            TreePathInputs::new(node_2d, path_2d, [None, None]),
            TreePathInputs::new(node_2.node, path_2.clone(), node_2_children),
        );

        let row_cells_2d = to_row_cells(&node_2.rows_tree[3].values);

        let row_2d = RowInput::new(&row_cells_2d, &row_path_2d);

        let path_2b = vec![(node_2a, ChildPosition::Left)];
        let row_path_2b = NodePath::new(
            TreePathInputs::new(node_2b, path_2b, [Some(node_2c), Some(node_2d)]),
            TreePathInputs::new(node_2.node, path_2.clone(), node_2_children),
        );

        let row_cells_2b = to_row_cells(&node_2.rows_tree[1].values);

        let row_2b = RowInput::new(&row_cells_2b, &row_path_2b);

        let path_2a = vec![];
        let row_path_2a = NodePath::new(
            TreePathInputs::new(node_2a, path_2a, [Some(node_2b), None]),
            TreePathInputs::new(node_2.node, path_2, node_2_children),
        );

        let row_cells_2a = to_row_cells(&node_2.rows_tree[0].values);

        let row_2a = RowInput::new(&row_cells_2a, &row_path_2a);

        let second_chunk_inputs = CircuitInput::new_row_chunks_input(
            &[row_2b, row_2d, row_2a],
            &predicate_operations,
            &placeholders,
            &bounds,
            &results,
        )
        .unwrap();

        let second_chunk_proof = params.generate_proof(second_chunk_inputs).unwrap();

        // now, aggregate the 2 chunks
        let aggregation_input =
            CircuitInput::new_chunk_aggregation_input(&[first_chunk_proof, second_chunk_proof])
                .unwrap();

        let final_proof = params.generate_proof(aggregation_input).unwrap();

        // check public inputs
        let proof = ProofWithVK::deserialize(&final_proof).unwrap();
        let pis = PublicInputs::<F, MAX_NUM_RESULTS>::from_slice(&proof.proof().public_inputs);

        let (predicate_1a, error_1a, output_1a) = compute_output_values_for_row::<MAX_NUM_RESULTS>(
            &row_cells_1a,
            &predicate_operations,
            &results,
            &placeholders,
        );
        let (predicate_1c, error_1c, output_1c) = compute_output_values_for_row::<MAX_NUM_RESULTS>(
            &row_cells_1c,
            &predicate_operations,
            &results,
            &placeholders,
        );
        let (predicate_2a, error_2a, output_2a) = compute_output_values_for_row::<MAX_NUM_RESULTS>(
            &row_cells_2a,
            &predicate_operations,
            &results,
            &placeholders,
        );
        let (predicate_2b, error_2b, output_2b) = compute_output_values_for_row::<MAX_NUM_RESULTS>(
            &row_cells_2b,
            &predicate_operations,
            &results,
            &placeholders,
        );
        let (predicate_2d, error_2d, output_2d) = compute_output_values_for_row::<MAX_NUM_RESULTS>(
            &row_cells_2d,
            &predicate_operations,
            &results,
            &placeholders,
        );

        let (expected_outputs, expected_err) = {
            let outputs = [output_1a, output_1c, output_2d, output_2b, output_2a];
            let mut num_overflows = 0;
            let outputs = output_ops
                .into_iter()
                .enumerate()
                .map(|(i, op)| {
                    let (out, overflows) = aggregate_output_values(i, &outputs, op);
                    num_overflows += overflows;
                    U256::from_fields(CurveOrU256::<F>::from_slice(&out).to_u256_raw())
                })
                .collect_vec();
            (outputs, num_overflows != 0)
        };

        let computational_hash = ComputationalHash::from_bytes(
            (&Identifiers::computational_hash_universal_circuit(
                &column_ids,
                &predicate_operations,
                &results,
                Some(bounds.min_query_secondary().into()),
                Some(bounds.max_query_secondary().into()),
            )
            .unwrap())
                .into(),
        );

        let left_boundary_row = {
            // left boundary row should correspond to row 1a
            // predecessor of node_1a is node_1b, which is not in the path
            let predecessor_1a = NeighborInfo::new(node_1b.value, None);
            // successor of node_1a is node_1c, which is not in the path
            let successor_1a = NeighborInfo::new(node_1c.value, None);
            let row_info_1a = BoundaryRowNodeInfo {
                end_node_hash: node_1a.compute_node_hash(secondary_index),
                predecessor_info: predecessor_1a,
                successor_info: successor_1a,
            };
            // predecessor of node_1 is node_0, which is not in the path
            let predecessor_1 = NeighborInfo::new(node_0.node.value, None);
            // successor of node_1 is node_2, which is not in the path
            let successor_1 = NeighborInfo::new(node_2.node.value, None);
            let index_info_1a = BoundaryRowNodeInfo {
                end_node_hash: node_1.node.compute_node_hash(primary_index),
                predecessor_info: predecessor_1,
                successor_info: successor_1,
            };
            BoundaryRowData {
                row_node_info: row_info_1a,
                index_node_info: index_info_1a,
            }
        };

        let right_boundary_row = {
            // right boundary row should correspond to row 2a
            // predecessor of node_2a is node_2d, which is not in the path
            let predecessor_2a = NeighborInfo::new(node_2d.value, None);
            // No successor of node_2a
            let successor_2a = NeighborInfo::new_dummy_successor();
            let row_info_2a = BoundaryRowNodeInfo {
                end_node_hash: node_2a.compute_node_hash(secondary_index),
                predecessor_info: predecessor_2a,
                successor_info: successor_2a,
            };
            // predecessor of node_2 is node_1, which is in the path
            let node_1_hash = node_1.node.compute_node_hash(primary_index);
            let predecessor_2 = NeighborInfo::new(node_1.node.value, Some(node_1_hash));
            // No successor of node_2
            let successor_2 = NeighborInfo::new_dummy_successor();
            let index_info_2a = BoundaryRowNodeInfo {
                end_node_hash: node_2.node.compute_node_hash(primary_index),
                predecessor_info: predecessor_2,
                successor_info: successor_2,
            };
            BoundaryRowData {
                row_node_info: row_info_2a,
                index_node_info: index_info_2a,
            }
        };

        let root = node_1.node.compute_node_hash(primary_index);
        assert_eq!(root, pis.tree_hash(),);
        assert_eq!(&pis.operation_ids()[..output_ops.len()], &output_ops);

        assert_eq!(
            pis.overflow_flag(),
            error_1a | error_1c | error_2d | error_2b | error_2a | expected_err
        );
        assert_eq!(
            pis.num_matching_rows(),
            F::from_canonical_u8(
                predicate_1a as u8
                    + predicate_1c as u8
                    + predicate_2b as u8
                    + predicate_2d as u8
                    + predicate_2a as u8
            ),
        );
        assert_eq!(pis.first_value_as_u256(), expected_outputs[0],);
        assert_eq!(
            expected_outputs[1..],
            pis.values()[..expected_outputs.len() - 1],
        );
        assert_eq!(pis.to_left_row_raw(), left_boundary_row.to_fields(),);
        assert_eq!(pis.to_right_row_raw(), right_boundary_row.to_fields(),);

        assert_eq!(pis.min_primary(), min_query_primary);
        assert_eq!(pis.max_primary(), max_query_primary);
        assert_eq!(pis.min_secondary(), min_query_secondary);
        assert_eq!(pis.max_secondary(), max_query_secondary);
        assert_eq!(pis.computational_hash(), computational_hash);
        assert_eq!(pis.placeholder_hash(), expected_placeholder_hash);

        // generate an index tree with all nodes out side of primary index range to test non-existence circuit API
        let [node_a, node_b, _node_c, node_d, node_e, _node_f, _node_g] = generate_test_tree(
            primary_index,
            Some((max_query_primary + U256::from(1), U256::MAX)),
        );
        // we use node_e to prove non-existence
        let path_e = vec![
            (node_d, ChildPosition::Left),
            (node_b, ChildPosition::Left),
            (node_a, ChildPosition::Left),
        ];
        let merkle_path_e = TreePathInputs::new(node_e, path_e, [None, None]);

        let input = CircuitInput::new_non_existence_input(
            merkle_path_e,
            &column_ids,
            &predicate_operations,
            &results,
            &placeholders,
            &bounds,
        )
        .unwrap();

        let proof = params.generate_proof(input).unwrap();

        // check public inputs
        let proof = ProofWithVK::deserialize(&proof).unwrap();
        let pis = PublicInputs::<F, MAX_NUM_RESULTS>::from_slice(&proof.proof().public_inputs);

        let root = node_a.compute_node_hash(primary_index);
        assert_eq!(root, pis.tree_hash(),);
        assert_eq!(&pis.operation_ids()[..output_ops.len()], &output_ops);
        let expected_outputs = compute_dummy_output_values(&pis.operation_ids());
        assert_eq!(pis.to_values_raw(), &expected_outputs,);
        assert_eq!(pis.num_matching_rows(), F::ZERO,);
        assert!(!pis.overflow_flag());
        assert_eq!(pis.min_primary(), min_query_primary);
        assert_eq!(pis.max_primary(), max_query_primary);
        assert_eq!(pis.computational_hash(), computational_hash);
        assert_eq!(pis.placeholder_hash(), expected_placeholder_hash);
    }
}
