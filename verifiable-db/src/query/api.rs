use std::iter::{repeat, repeat_with};

use anyhow::{bail, ensure, Result};

use itertools::Itertools;
use mp2_common::{array::ToField, default_config, poseidon::{HashPermutation, H}, proof::{serialize_proof, ProofWithVK}, types::HashOutput, utils::ToFields, C, D, F};
use plonky2::{hash::hashing::hash_n_to_hash_no_pad, plonk::config::{GenericHashOut, Hasher}};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder}, framework::{prepare_recursive_circuit_for_circuit_set, RecursiveCircuits},
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
        circuits::{
                chunk_aggregation::{ChunkAggregationCircuit, ChunkAggregationInputs, ChunkAggregationWires}, 
                non_existence::{NonExistenceCircuit, NonExistenceWires},
                row_chunk_processing::{RowChunkProcessingCircuit, RowChunkProcessingWires},
        },
        row_chunk::row_process_gadget::RowProcessingGadgetInputs,
    },
    computational_hash_ids::{AggregationOperation, ColumnIDs, Identifiers},
    universal_circuit::{
        output_with_aggregation::Circuit as OutputAggCircuit,
        output_no_aggregation::Circuit as OutputNoAggCircuit,
        universal_circuit_inputs::{BasicOperation, Placeholders, ResultStructure, RowCells},
    },
};

use super::{computational_hash_ids::Output, pi_len, universal_circuit::{universal_circuit_inputs::PlaceholderId, universal_query_circuit::{placeholder_hash, UniversalCircuitInput, UniversalQueryCircuitParams}}};

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
        children: [Option<NodeInfo>; 2],
    ) -> Self {
        let siblings = path
            .iter()
            .map(|(node, child_pos)| {
                let sibling_index = match *child_pos {
                    ChildPosition::Left => 1,
                    ChildPosition::Right => 0,
                };
                Some(HashOutput::from(node.child_hashes[sibling_index]))
            })
            .collect_vec();
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
/// and the index tree for a node in a rows tree
pub struct NodePath {
    pub(crate) row_tree_path: TreePathInputs,
    /// Info about the node of the index tree storing the rows tree containing the row
    pub(crate) index_tree_path: TreePathInputs,
}

impl NodePath {
    /// Instantiate a new instance of `NodePath` for a given proven row from the following input data:
    /// - `row_path`: path from the node to the root of the rows tree storing the node
    /// - `index_path` : path from the index tree node storing the rows tree containing the node, up to the
    ///     root of the index tree
    pub fn new(row_path: TreePathInputs, index_path: TreePathInputs) -> Self {
        Self {
            row_tree_path: row_path,
            index_tree_path: index_path,
        }
    }
}

#[derive(Clone, Debug)]
/// Data structure containing the inputs necessary to prove a query for a row
/// of the DB table.
pub struct RowInput {
    pub(crate) cells: RowCells,
    pub(crate) path: NodePath,
}

impl RowInput {
    /// Initialize `RowInput` from the set of cells of the given row and the path
    /// in the tree of the node of the rows tree associated to the given row
    pub fn new(cells: &RowCells, path: &NodePath) -> Self {
        Self {
            cells: cells.clone(),
            path: path.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum CircuitInput<
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
    /// Inputs for the universal query circuit
    UniversalCircuit(
        UniversalCircuitInput<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
        >,
    ),
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
    /// Construct the input necessary to prove a query over a chunk of rows provided as input.
    /// It requires to provide at least 1 row; in case there are no rows to be proven, then
    /// `Self::new_non_existence_input` should be used instead
    pub fn new_row_chunks_input(
        rows: &[RowInput],
        predicate_operations: &[BasicOperation],
        placeholders: &Placeholders,
        query_bounds: &QueryBounds,
        results: &ResultStructure,
    ) -> Result<Self> {
        ensure!(
            !rows.is_empty(),
            "there must be at least 1 row to be proven"
        );
        ensure!(
            rows.len() <= NUM_ROWS,
            format!(
                "Found {} rows provided as input, maximum allowed is {NUM_ROWS}",
                rows.len()
            )
        );
        let column_ids = &rows[0].cells.column_ids();
        ensure!(
            rows.iter()
                .all(|row| row.cells.column_ids().to_vec() == column_ids.to_vec()),
            "Rows provided as input don't have the same column ids",
        );
        let row_inputs = rows
            .iter()
            .map(RowProcessingGadgetInputs::try_from)
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

    /// Construct the input necessary to aggregate 2 or more row chunks already proven.
    /// It requires at least 2 chunks to be aggregated
    pub fn new_chunk_aggregation_input(chunks_proofs: &[Vec<u8>]) -> Result<Self> {
        ensure!(
            chunks_proofs.len() >= 2,
            "At least 2 chunk proofs must be provided"
        );
        // deserialize `chunk_proofs`` and pad to NUM_CHUNKS proofs by replicating the last proof in `chunk_proofs`
        let last_proof = chunks_proofs.last().unwrap();
        let proofs = chunks_proofs
            .iter()
            .map(|p| ProofWithVK::deserialize(p))
            .chain(repeat_with(|| ProofWithVK::deserialize(last_proof)))
            .take(NUM_CHUNKS)
            .collect::<Result<Vec<_>>>()?;

        let num_proofs = chunks_proofs.len();

        ensure!(
            num_proofs <= NUM_CHUNKS,
            format!("Found {num_proofs} proofs provided as input, maximum allowed is {NUM_CHUNKS}")
        );

        Ok(Self::ChunkAggregation(ChunkAggregationInputs {
            chunk_proofs: proofs.try_into().unwrap(),
            circuit: ChunkAggregationCircuit {
                num_non_dummy_chunks: num_proofs,
            },
        }))
    }

    /// Construct the input to prove a query in case there are no rows with a primary index value
    /// in the primary query range. The circuit employed to prove the non-existence of such a row
    /// requires to provide a specific node of the index tree, as described in the docs
    /// https://www.notion.so/lagrangelabs/Batching-Query-10628d1c65a880b1b151d4ac017fa445?pvs=4#10e28d1c65a880498f41cd1cad0c61c3
    pub fn new_non_existence_input(
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

    pub const fn num_placeholders_ids() -> usize {
        2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS)
    }
    /// Initialize input for universal circuit to prove the execution of a query over a
    /// single row, from the following inputs:
    ///     - `column_cells`: set of columns (including primary and secondary indexes) of the row being proven
    ///     - `predicate_operations`: Set of operations employed to compute the filtering predicate of the query for the
    ///     row being proven
    ///     - `results`: Data structure specifying how the results for each row are computed according to the query
    ///     - `placeholders`: Set of placeholders employed in the query
    ///     - `is_leaf`: Flag specifying whether the row being proven is stored in a leaf node of the rows tree or not
    ///     - `query_bounds`: bounds on primary and secondary indexes specified in the query
    /// Note that the following assumption is expected on the structure of the inputs:
    /// The output of the last operation in `predicate_operations` is taken as the filtering predicate evaluation;
    /// this is an assumption exploited in the circuit for efficiency, and it is a simple assumption to be required for
    /// the caller of this method
    pub fn new_universal_circuit(
        column_cells: &RowCells,
        predicate_operations: &[BasicOperation],
        results: &ResultStructure,
        placeholders: &Placeholders,
        is_leaf: bool,
        query_bounds: &QueryBounds,
    ) -> Result<Self> {
        Ok(CircuitInput::UniversalCircuit(
            match results.output_variant {
                Output::Aggregation => bail!(
                    "Universal query circuit should only be used for queries with no aggregation"
                ),
                Output::NoAggregation => UniversalCircuitInput::new_query_no_agg(
                    column_cells,
                    predicate_operations,
                    placeholders,
                    is_leaf,
                    query_bounds,
                    results,
                )?,
            },
        ))
    }

    /// This method returns the ids of the placeholders employed to compute the placeholder hash,
    /// in the same order, so that those ids can be provided as input to other circuits that need
    /// to recompute this hash
    pub fn ids_for_placeholder_hash(
        predicate_operations: &[BasicOperation],
        results: &ResultStructure,
        placeholders: &Placeholders,
        query_bounds: &QueryBounds,
    ) -> Result<[PlaceholderId; 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS)]> {
        UniversalCircuitInput::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
        >::ids_for_placeholder_hash(predicate_operations, results, placeholders, query_bounds)
    }

    /// Compute the `placeholder_hash` associated to a query
    pub fn placeholder_hash(
        predicate_operations: &[BasicOperation],
        results: &ResultStructure,
        placeholders: &Placeholders,
        query_bounds: &QueryBounds,
    ) -> Result<HashOutput> {
        let placeholder_hash_ids = Self::ids_for_placeholder_hash(
            predicate_operations,
            results,
            placeholders,
            query_bounds,
        )?;
        let hash = placeholder_hash(&placeholder_hash_ids, placeholders, query_bounds)?;
        // add primary query bounds to placeholder hash
        HashOutput::try_from(
            hash_n_to_hash_no_pad::<_, HashPermutation>(
                &hash
                    .to_vec()
                    .into_iter()
                    .chain(query_bounds.min_query_primary().to_fields())
                    .chain(query_bounds.max_query_primary().to_fields())
                    .collect_vec(),
            )
            .to_bytes(),
        )
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
    universal_circuit: UniversalQueryCircuitParams<
        MAX_NUM_COLUMNS, 
        MAX_NUM_PREDICATE_OPS, 
        MAX_NUM_RESULT_OPS, 
        MAX_NUM_RESULTS,
        OutputNoAggCircuit<MAX_NUM_RESULTS>,
    >,
    circuit_set: RecursiveCircuits<F, C, D>,
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
    [(); pi_len::<MAX_NUM_RESULTS>()]:,
{
    const CIRCUIT_SET_SIZE: usize = 3;

    pub(crate) fn build() -> Self {
        let builder =
            CircuitWithUniversalVerifierBuilder::<F, D, { pi_len::<MAX_NUM_RESULTS>() }>::new::<C>(
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

        let universal_circuit = UniversalQueryCircuitParams::build(default_config());

        Self {
            row_chunk_agg_circuit,
            aggregation_circuit,
            non_existence_circuit,
            universal_circuit,
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
        match input {
            CircuitInput::RowChunkWithAggregation(row_chunk_processing_circuit) => 
            ProofWithVK::serialize(
            &(
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
            ).into()),
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
                ProofWithVK::serialize(
                    &(
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
                    .into())
            }
            CircuitInput::NonExistence(non_existence_circuit) => 
            ProofWithVK::serialize(
                &(
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
                .into()),
            CircuitInput::UniversalCircuit(universal_circuit_input) => 
                if let UniversalCircuitInput::QueryNoAgg(input) = universal_circuit_input {
                    serialize_proof(&self.universal_circuit.generate_proof(&input)?)
                } else {
                    unreachable!("Universal circuit should only be used for queries with no aggregation operations")
                }
            ,
        }
    }

    pub(crate) fn get_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        &self.circuit_set
    }

    pub(crate) fn get_universal_circuit(&self) -> &UniversalQueryCircuitParams<
        MAX_NUM_COLUMNS, 
        MAX_NUM_PREDICATE_OPS, 
        MAX_NUM_RESULT_OPS, 
        MAX_NUM_RESULTS,
        OutputNoAggCircuit<MAX_NUM_RESULTS>,
    > {
        &self.universal_circuit
    }
}
