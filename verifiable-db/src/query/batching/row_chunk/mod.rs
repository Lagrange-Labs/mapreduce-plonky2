//! This module contains data structures and gadgets employed to build and aggregate
//! row chunks. A row chunk is a set of rows that have already been aggregated 
//! and whose rows are all proven to be consecutive. The first and last rows in
//! the chunk are labelled as the `left_boundary_row` and the `right_boundary_row`,
//! respectively, and are the rows employed to aggregate 2 different chunks.

use plonky2::hash::hash_types::HashOutTarget;

use crate::query::{merkle_path::NeighborInfoTarget, universal_circuit::universal_query_gadget::UniversalQueryOutputWires};

/// This module contains gadgets to enforce whether 2 rows are consecutive
pub(crate) mod consecutive_rows;
/// This module contains gadgets to aggregate 2 different row chunks
pub(crate) mod aggregate_chunks;

/// Data structure containing the wires representing the data realted to the node of 
/// the row/index tree containing a row that is on the boundary of a row chunk. 
#[derive(Clone, Debug)]
pub(crate) struct BoundaryRowNodeInfoTarget {
    /// Hash of the node storing the row in the row/index tree
    pub(crate) end_node_hash: HashOutTarget,
    /// Data about the predecessor of end_node in the row/index tree
    pub(crate) predecessor_info: NeighborInfoTarget,
    /// Data about the predecessor of end_node in the row/index tree
    pub(crate) successor_info: NeighborInfoTarget,
}

/// Data structure containing the `BoundaryRowNodeInfoTarget` wires for the nodes
/// realted to a given boundary row. In particular, it contains the 
/// `BoundaryRowNodeInfoTarget` related to the following nodes:
/// - `row_node`: the node of the rows tree containing the given boundary row
/// - `index_node`: the node of the index tree that stores the rows tree containing
///     `row_node`
#[derive(Clone, Debug)] 
pub(crate) struct BoundaryRowData {
    row_node_info: BoundaryRowNodeInfoTarget,
    index_node_info: BoundaryRowNodeInfoTarget,
}

/// Data structure containing the wires associated to a given row chunk
#[derive(Clone, Debug)]
pub(crate) struct RowChunkData<
    const MAX_NUM_RESULTS: usize,
>
where [(); MAX_NUM_RESULTS-1]:,
{
    pub(crate) left_boundary_row: BoundaryRowData,
    pub(crate) right_boundary_row: BoundaryRowData,
    pub(crate) chunk_outputs: UniversalQueryOutputWires<MAX_NUM_RESULTS>,
}