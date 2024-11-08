use std::iter::{repeat, repeat_with};

use anyhow::{ensure, Result};

use itertools::Itertools;
use mp2_common::{
    array::ToField, default_config, poseidon::H, proof::ProofWithVK, types::HashOutput, C, D, F,
};
use plonky2::{iop::target::Target, plonk::config::Hasher};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{prepare_recursive_circuit_for_circuit_set, RecursiveCircuits},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

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
/// Data structure containing all the information needed to verify the membership of
/// a node in a tree and to compute info about its predecessor/successor
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct TreePathInputs {
    /// Info about the node
    pub(crate) node_info: NodeInfo,
    /// Info about the nodes in the path from the node up to the root of the tree; The `ChildPosition` refers to
    /// the position of the previous node in the path as a child of the current node
    pub(crate) path: Vec<(NodeInfo, ChildPosition)>,
    /// Hash of the siblings of the nodes in path (except for the root)
    pub(crate) siblings: Vec<Option<HashOutput>>,
    /// Info about the children of the node
    pub(crate) children: [Option<NodeInfo>; 2],
}

impl TreePathInputs {
    /// Instantiate a new instance of `TreePathInputs` for a given node from the following input data:
    /// - `node_info`: data about the given node
    /// - `path`: data about the nodes in the path from the node up to the root of the tree;
    ///     The `ChildPosition` refers to the position of the previous node in the path as a child of the current node
    /// - `siblings`: hash of the siblings of the nodes in the path (except for the root)
    /// - `children`: data about the children of the given node
    pub fn new(
        node_info: NodeInfo,
        path: Vec<(NodeInfo, ChildPosition)>,
        siblings: Vec<Option<HashOutput>>,
        children: [Option<NodeInfo>; 2],
    ) -> Self {
        Self {
            node_info,
            path,
            siblings,
            children,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
/// Data structure containing the information about the paths in both the rows tree
/// and the index tree for a generic row of our tables
pub struct RowPath {
    pub(crate) row_tree_path: TreePathInputs,
    /// Info about the node of the index tree storing the rows tree containing the row
    pub(crate) index_tree_path: TreePathInputs,
}

impl RowPath {
    /// Instantiate a new instance of `RowPath` for a given proven row from the following input data:
    /// - `row_node_info`: data about the node of the row tree storing the row
    /// - `row_tree_path`: data about the nodes in the path of the rows tree for the node storing the row;
    ///     The `ChildPosition` refers to the position of the previous node in the path as a child of the current node
    /// - `row_path_siblings`: hash of the siblings of the node in the rows tree path (except for the root)
    /// - `row_node_children`: data about the children of the node of the row tree storing the row
    /// - `index_node_info`: data about the node of the index tree storing the rows tree containing the row
    /// - `index_tree_path`: data about the nodes in the path of the index tree for the index_node;
    ///     The `ChildPosition` refers to the position of the previous node in the path as a child of the current node
    /// - `index_path_siblings`: hash of the siblings of the nodes in the index tree path (except for the root)
    /// - `index_node_children`: data about the children of the index_node
    pub fn new(
        row_node_info: NodeInfo,
        row_tree_path: Vec<(NodeInfo, ChildPosition)>,
        row_path_siblings: Vec<Option<HashOutput>>,
        row_node_children: [Option<NodeInfo>; 2],
        index_node_info: NodeInfo,
        index_tree_path: Vec<(NodeInfo, ChildPosition)>,
        index_path_siblings: Vec<Option<HashOutput>>,
        index_node_children: [Option<NodeInfo>; 2],
    ) -> Self {
        let row_path = TreePathInputs::new(
            row_node_info,
            row_tree_path,
            row_path_siblings,
            row_node_children,
        );
        let index_path = TreePathInputs::new(
            index_node_info,
            index_tree_path,
            index_path_siblings,
            index_node_children,
        );
        Self {
            row_tree_path: row_path,
            index_tree_path: index_path,
        }
    }
}

pub struct RowWithPath {
    pub(crate) cells: RowCells,
    pub(crate) path: RowPath,
}

impl RowWithPath {
    pub fn new(cells: &RowCells, path: &RowPath) -> Self {
        Self {
            cells: cells.clone(),
            path: path.clone(),
        }
    }
}

pub(crate) enum CircuitInput<
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
{
    RowChunkWithAggregation(
        RowChunkProcessingCircuit<
            NUM_ROWS,
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            OutputAggCircuit<MAX_NUM_RESULTS>,
        >,
    ),
    ChunkAggregation(ChunkAggregationInputs<NUM_CHUNKS, MAX_NUM_RESULTS>),
    NonExistence(NonExistenceCircuit<INDEX_TREE_MAX_DEPTH, MAX_NUM_RESULTS>),
}

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
    CircuitInput<
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
    [(); 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS)]:,
{
    pub(crate) fn new_row_chunks_input(
        rows: &[RowWithPath],
        predicate_operations: &[BasicOperation],
        placeholders: &Placeholders,
        query_bounds: &QueryBounds,
        results: &ResultStructure,
    ) -> Result<Self> {
        ensure!(rows.len() >= 1, "there must be at least 1 row to be proven");
        let column_ids = &rows[0].cells.column_ids();
        let row_inputs = rows
            .into_iter()
            .map(|row| RowProcessingGadgetInputs::try_from(row))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self::RowChunkWithAggregation(
            RowChunkProcessingCircuit::new(
                row_inputs,
                column_ids,
                predicate_operations,
                placeholders,
                query_bounds,
                results,
            )?,
        ))
    }

    pub(crate) fn new_chunk_aggregation_input(chunks_proofs: &[Vec<u8>]) -> Result<Self> {
        ensure!(
            chunks_proofs.len() >= 1,
            "At least one chunk proof must be provided"
        );
        // deserialize `chunk_proofs`` and pad to NUM_CHUNKS proofs by replicating the last proof in `chunk_proofs`
        let last_proof = chunks_proofs.last().unwrap();
        let proofs = chunks_proofs
            .into_iter()
            .map(|p| ProofWithVK::deserialize(p))
            .chain(repeat_with(|| ProofWithVK::deserialize(&last_proof)))
            .take(NUM_CHUNKS)
            .collect::<Result<Vec<_>>>()?;

        let num_proofs = proofs.len();

        Ok(Self::ChunkAggregation(ChunkAggregationInputs {
            chunk_proofs: proofs.try_into().unwrap(),
            circuit: ChunkAggregationCircuit {
                num_non_dummy_chunks: num_proofs,
            },
        }))
    }

    pub(crate) fn new_non_existence_input(
        index_node_path: TreePathInputs,
        column_ids: &ColumnIDs,
        predicate_operations: &[BasicOperation],
        results: &ResultStructure,
        placeholders: &Placeholders,
        query_bounds: &QueryBounds,
    ) -> Result<Self> {
        let QueryHashNonExistenceCircuits {
            computational_hash,
            placeholder_hash,
        } = QueryHashNonExistenceCircuits::new::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
        >(
            column_ids,
            predicate_operations,
            results,
            placeholders,
            query_bounds,
            false,
        )?;

        let aggregation_operations = results
            .aggregation_operations()
            .into_iter()
            .chain(repeat(
                Identifiers::AggregationOperations(AggregationOperation::default()).to_field(),
            ))
            .take(MAX_NUM_RESULTS)
            .collect_vec()
            .try_into()
            .unwrap();

        Ok(Self::NonExistence(NonExistenceCircuit::new(
            &index_node_path,
            column_ids.primary,
            aggregation_operations,
            computational_hash,
            placeholder_hash,
            query_bounds,
        )?))
    }
}

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
#[rustfmt::skip]
pub(crate) const NUM_IO<const MAX_NUM_RESULTS: usize>: usize = PublicInputs::<Target, MAX_NUM_RESULTS>::total_len();

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
    [(); NUM_IO::<MAX_NUM_RESULTS>]:,
{
    const CIRCUIT_SET_SIZE: usize = 3;

    pub(crate) fn build() -> Self {
        let builder =
            CircuitWithUniversalVerifierBuilder::<F, D, { NUM_IO::<MAX_NUM_RESULTS> }>::new::<C>(
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
}

#[cfg(test)]
mod tests {
    use crate::query::batching::circuits::api::NUM_IO;

    use super::Parameters;

    const NUM_CHUNKS: usize = 5;
    const NUM_ROWS: usize = 5;
    const ROW_TREE_MAX_DEPTH: usize = 10;
    const INDEX_TREE_MAX_DEPTH: usize = 15;
    const MAX_NUM_COLUMNS: usize = 30;
    const MAX_NUM_PREDICATE_OPS: usize = 20;
    const MAX_NUM_RESULT_OPS: usize = 30;
    const MAX_NUM_RESULTS: usize = 10;

    #[test]
    fn build_params() {
        assert_eq!(NUM_IO::<MAX_NUM_RESULTS>, 267);
        Parameters::<
            NUM_CHUNKS,
            NUM_ROWS,
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
        >::build();
    }
}
