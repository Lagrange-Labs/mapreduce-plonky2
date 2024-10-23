//! This module contains data structures and gadgets employed to build and aggregate
//! row chunks. A row chunk is a set of rows that have already been aggregated 
//! and whose rows are all proven to be consecutive. The first and last rows in
//! the chunk are labelled as the `left_boundary_row` and the `right_boundary_row`,
//! respectively, and are the rows employed to aggregate 2 different chunks.

use mp2_common::{serialization::circuit_data_serialization::SerializableRichField, types::CBuilder, utils::{HashBuilder, SelectTarget}};
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::target::BoolTarget, plonk::circuit_builder::CircuitBuilder};

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

impl SelectTarget for BoundaryRowNodeInfoTarget {
    fn select<F: SerializableRichField<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        cond: &BoolTarget,
        first: &Self,
        second: &Self,
    ) -> Self {
        Self {
            end_node_hash: b.select_hash(*cond, &first.end_node_hash, &second.end_node_hash),
            predecessor_info: NeighborInfoTarget::select(
                b, 
                cond, 
                &first.predecessor_info, 
                &second.predecessor_info
            ),
            successor_info: NeighborInfoTarget::select(
                b, 
                cond, 
                &first.successor_info, 
                &second.successor_info
            ),
        }
    }
}

/// Data structure containing the `BoundaryRowNodeInfoTarget` wires for the nodes
/// realted to a given boundary row. In particular, it contains the 
/// `BoundaryRowNodeInfoTarget` related to the following nodes:
/// - `row_node`: the node of the rows tree containing the given boundary row
/// - `index_node`: the node of the index tree that stores the rows tree containing
///     `row_node`
#[derive(Clone, Debug)] 
pub(crate) struct BoundaryRowDataTarget {
    row_node_info: BoundaryRowNodeInfoTarget,
    index_node_info: BoundaryRowNodeInfoTarget,
}

impl SelectTarget for BoundaryRowDataTarget {
    fn select<F: SerializableRichField<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        cond: &BoolTarget,
        first: &Self,
        second: &Self,
    ) -> Self {
        Self {
            row_node_info: BoundaryRowNodeInfoTarget::select(
                b, 
                cond, 
                &first.row_node_info, 
                &second.row_node_info
            ),
            index_node_info: BoundaryRowNodeInfoTarget::select(
                b, 
                cond, 
                &first.index_node_info, 
                &second.index_node_info
            ),
        }
    }
}

/// Data structure containing the wires associated to a given row chunk
#[derive(Clone, Debug)]
pub(crate) struct RowChunkDataTarget<
    const MAX_NUM_RESULTS: usize,
>
where [(); MAX_NUM_RESULTS-1]:,
{
    pub(crate) left_boundary_row: BoundaryRowDataTarget,
    pub(crate) right_boundary_row: BoundaryRowDataTarget,
    pub(crate) chunk_outputs: UniversalQueryOutputWires<MAX_NUM_RESULTS>,
}

#[cfg(test)]
pub(crate) mod tests {
    use mp2_common::F;
    use plonky2::{hash::hash_types::HashOut, iop::witness::{PartialWitness, WitnessWrite}, field::types::Field};

    use crate::query::{merkle_path::tests::NeighborInfo, universal_circuit::universal_query_gadget::OutputValues};

    use super::{BoundaryRowDataTarget, BoundaryRowNodeInfoTarget, RowChunkDataTarget};
    #[derive(Clone, Debug)]
    pub(crate) struct BoundaryRowNodeInfo {
        pub(crate) end_node_hash: HashOut<F>,
        pub(crate) predecessor_info: NeighborInfo,
        pub(crate) successor_info: NeighborInfo,
    }

    impl BoundaryRowNodeInfo {
        pub(crate) fn assign(&self, pw: &mut PartialWitness<F>, wires: &BoundaryRowNodeInfoTarget) {
            pw.set_hash_target(wires.end_node_hash, self.end_node_hash);
            self.predecessor_info.assign(pw, &wires.predecessor_info);
            self.successor_info.assign(pw, &wires.successor_info);
        }
    }
    #[derive(Clone, Debug)]
    pub(crate) struct BoundaryRowData {
        pub(crate) row_node_info: BoundaryRowNodeInfo,
        pub(crate) index_node_info: BoundaryRowNodeInfo,
    }

    impl BoundaryRowData {
        pub(crate) fn assign(&self, pw: &mut PartialWitness<F>, wires: &BoundaryRowDataTarget) {
            self.row_node_info.assign(pw, &wires.row_node_info);
            self.index_node_info.assign(pw, &wires.index_node_info);
        }
    }
    #[derive(Clone, Debug)]
    pub(crate) struct RowChunkData<const MAX_NUM_RESULTS: usize> 
    where [(); MAX_NUM_RESULTS-1]:,
    {
        pub(crate) left_boundary_row: BoundaryRowData,
        pub(crate) right_boundary_row: BoundaryRowData,
        pub(crate) chunk_tree_hash: HashOut<F>,
        pub(crate) output_values: OutputValues<MAX_NUM_RESULTS>,
        pub(crate) num_overflows: u64,
        pub(crate) count: u64,
    }

    impl<const MAX_NUM_RESULTS: usize> RowChunkData<MAX_NUM_RESULTS>
    where [(); MAX_NUM_RESULTS-1]:,
    {
        pub(crate) fn assign(&self, pw: &mut PartialWitness<F>, wires: &RowChunkDataTarget<MAX_NUM_RESULTS>) {
            self.left_boundary_row.assign(pw, &wires.left_boundary_row);
            self.right_boundary_row.assign(pw, &wires.right_boundary_row);
            pw.set_hash_target(wires.chunk_outputs.tree_hash, self.chunk_tree_hash);
            pw.set_target(wires.chunk_outputs.num_overflows, F::from_canonical_u64(self.num_overflows));
            pw.set_target(wires.chunk_outputs.count, F::from_canonical_u64(self.count));
        }
    }

}