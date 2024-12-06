//! This module contains data structures and gadgets employed to build and aggregate
//! row chunks. A row chunk is a set of rows that have already been aggregated
//! and whose rows are all proven to be consecutive. The first and last rows in
//! the chunk are labelled as the `left_boundary_row` and the `right_boundary_row`,
//! respectively, and are the rows employed to aggregate 2 different chunks.

use alloy::primitives::U256;
use mp2_common::{
    serialization::circuit_data_serialization::SerializableRichField,
    utils::{FromFields, FromTargets, HashBuilder, SelectTarget, ToFields, ToTargets}, F,
};
use mp2_test::utils::gen_random_field_hash;
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use rand::Rng;

use crate::{query::{
    merkle_path::{MerklePathWithNeighborsTarget, NeighborInfoTarget},
    universal_circuit::universal_query_gadget::UniversalQueryOutputWires,
}, test_utils::gen_values_in_range};

use super::{merkle_path::NeighborInfo, utils::QueryBounds};

/// This module contains gadgets to aggregate 2 different row chunks
pub(crate) mod aggregate_chunks;
/// This module contains gadgets to enforce whether 2 rows are consecutive
pub(crate) mod consecutive_rows;
/// This module copntains a gadget to prove a single row of the DB
pub(crate) mod row_process_gadget;

/// Data structure containing the wires representing the data related to the node of
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

impl<'a, const MAX_DEPTH: usize> From<&'a MerklePathWithNeighborsTarget<MAX_DEPTH>>
    for BoundaryRowNodeInfoTarget
where
    [(); MAX_DEPTH - 1]:,
{
    fn from(value: &'a MerklePathWithNeighborsTarget<MAX_DEPTH>) -> Self {
        Self {
            end_node_hash: value.end_node_hash,
            predecessor_info: value.predecessor_info.clone(),
            successor_info: value.successor_info.clone(),
        }
    }
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
                &second.predecessor_info,
            ),
            successor_info: NeighborInfoTarget::select(
                b,
                cond,
                &first.successor_info,
                &second.successor_info,
            ),
        }
    }
}

impl FromTargets for BoundaryRowNodeInfoTarget {
    const NUM_TARGETS: usize = NUM_HASH_OUT_ELTS + 2 * NeighborInfoTarget::NUM_TARGETS;

    fn from_targets(t: &[Target]) -> Self {
        assert!(t.len() >= Self::NUM_TARGETS);
        Self {
            end_node_hash: HashOutTarget::from_vec(t[..NUM_HASH_OUT_ELTS].to_vec()),
            predecessor_info: NeighborInfoTarget::from_targets(&t[NUM_HASH_OUT_ELTS..]),
            successor_info: NeighborInfoTarget::from_targets(
                &t[NUM_HASH_OUT_ELTS + NeighborInfoTarget::NUM_TARGETS..],
            ),
        }
    }
}

impl ToTargets for BoundaryRowNodeInfoTarget {
    fn to_targets(&self) -> Vec<Target> {
        self.end_node_hash
            .to_targets()
            .into_iter()
            .chain(self.predecessor_info.to_targets())
            .chain(self.successor_info.to_targets())
            .collect()
    }
}

/// Data structure containing the `BoundaryRowNodeInfoTarget` wires for the nodes
/// related to a given boundary row. In particular, it contains the
/// `BoundaryRowNodeInfoTarget` related to the following nodes:
/// - `row_node`: the node of the rows tree containing the given boundary row
/// - `index_node`: the node of the index tree that stores the rows tree containing
///     `row_node`
#[derive(Clone, Debug)]
pub(crate) struct BoundaryRowDataTarget {
    pub(crate) row_node_info: BoundaryRowNodeInfoTarget,
    pub(crate) index_node_info: BoundaryRowNodeInfoTarget,
}

impl FromTargets for BoundaryRowDataTarget {
    const NUM_TARGETS: usize = 2 * BoundaryRowNodeInfoTarget::NUM_TARGETS;
    fn from_targets(t: &[Target]) -> Self {
        assert!(t.len() >= Self::NUM_TARGETS);
        Self {
            row_node_info: BoundaryRowNodeInfoTarget::from_targets(t),
            index_node_info: BoundaryRowNodeInfoTarget::from_targets(
                &t[BoundaryRowNodeInfoTarget::NUM_TARGETS..],
            ),
        }
    }
}

impl ToTargets for BoundaryRowDataTarget {
    fn to_targets(&self) -> Vec<Target> {
        self.row_node_info
            .to_targets()
            .into_iter()
            .chain(self.index_node_info.to_targets())
            .collect()
    }
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
                &second.row_node_info,
            ),
            index_node_info: BoundaryRowNodeInfoTarget::select(
                b,
                cond,
                &first.index_node_info,
                &second.index_node_info,
            ),
        }
    }
}

/// Data structure containing the wires associated to a given row chunk
#[derive(Clone, Debug)]
pub(crate) struct RowChunkDataTarget<const MAX_NUM_RESULTS: usize>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    pub(crate) left_boundary_row: BoundaryRowDataTarget,
    pub(crate) right_boundary_row: BoundaryRowDataTarget,
    pub(crate) chunk_outputs: UniversalQueryOutputWires<MAX_NUM_RESULTS>,
}

impl<const MAX_NUM_RESULTS: usize> FromTargets for RowChunkDataTarget<MAX_NUM_RESULTS>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    const NUM_TARGETS: usize =
        2 * BoundaryRowDataTarget::NUM_TARGETS + UniversalQueryOutputWires::NUM_TARGETS;

    fn from_targets(t: &[Target]) -> Self {
        assert!(t.len() >= Self::NUM_TARGETS);
        Self {
            left_boundary_row: BoundaryRowDataTarget::from_targets(t),
            right_boundary_row: BoundaryRowDataTarget::from_targets(
                &t[BoundaryRowDataTarget::NUM_TARGETS..],
            ),
            chunk_outputs: UniversalQueryOutputWires::from_targets(
                &t[2 * BoundaryRowDataTarget::NUM_TARGETS..],
            ),
        }
    }
}

impl<const MAX_NUM_RESULTS: usize> ToTargets for RowChunkDataTarget<MAX_NUM_RESULTS>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    fn to_targets(&self) -> Vec<Target> {
        self.left_boundary_row
            .to_targets()
            .into_iter()
            .chain(self.right_boundary_row.to_targets())
            .chain(self.chunk_outputs.to_targets())
            .collect()
    }
}


#[derive(Clone, Debug)]
pub(crate) struct BoundaryRowNodeInfo {
    pub(crate) end_node_hash: HashOut<F>,
    pub(crate) predecessor_info: NeighborInfo,
    pub(crate) successor_info: NeighborInfo,
}

impl ToFields<F> for BoundaryRowNodeInfo {
    fn to_fields(&self) -> Vec<F> {
        self.end_node_hash
            .to_fields()
            .into_iter()
            .chain(self.predecessor_info.to_fields())
            .chain(self.successor_info.to_fields())
            .collect()
    }
}

impl FromFields<F> for BoundaryRowNodeInfo {
    fn from_fields(t: &[F]) -> Self {
        assert!(t.len() >= BoundaryRowNodeInfoTarget::NUM_TARGETS);
        let end_node_hash = HashOut::from_partial(&t[..NUM_HASH_OUT_ELTS]);
        let predecessor_info = NeighborInfo::from_fields(&t[NUM_HASH_OUT_ELTS..]);
        let successor_info = NeighborInfo::from_fields(
            &t[NUM_HASH_OUT_ELTS + NeighborInfoTarget::NUM_TARGETS..],
        );

        Self {
            end_node_hash,
            predecessor_info,
            successor_info,
        }
    }
}

impl BoundaryRowNodeInfo {
        /// Generate an instance of `Self` representing a random node, given the `query_bounds`
        /// provided as input and a flag `is_index_tree` specifying whether the random node
        /// should be part of an index tree or of a rows tree. It is used to generate test data
        /// without the need to generate an actual tree
        pub(crate) fn sample<R: Rng>(
            rng: &mut R,
            query_bounds: &QueryBounds,
            is_index_tree: bool,
        ) -> Self {
            let (min_query_bound, max_query_bound) = if is_index_tree {
                (
                    query_bounds.min_query_primary(),
                    query_bounds.max_query_primary(),
                )
            } else {
                (
                    *query_bounds.min_query_secondary().value(),
                    *query_bounds.max_query_secondary().value(),
                )
            };
            let end_node_hash = gen_random_field_hash();
            let [predecessor_value] = gen_values_in_range(
                rng,
                if is_index_tree {
                    min_query_bound // predecessor in index tree must always be in range
                } else {
                    U256::ZERO
                },
                max_query_bound, // predecessor value must always be smaller than max_secondary in circuit
            );
            let predecessor_info = NeighborInfo::sample(
                rng,
                predecessor_value,
                if is_index_tree {
                    // in index tree, there must always be a predecessor for boundary rows
                    Some(true)
                } else {
                    None
                },
            );
            let [successor_value] = gen_values_in_range(
                rng,
                predecessor_value.max(min_query_bound), // successor value must
                // always be greater than min_secondary in circuit, and it must be also
                // greater than predecessor value since we are in a BST
                if is_index_tree {
                    max_query_bound // successor in index tree must always be in range
                } else {
                    U256::MAX
                },
            );
            let successor_info = NeighborInfo::sample(
                rng,
                successor_value,
                if is_index_tree {
                    // in index tree, there must always be a successor for boundary rows
                    Some(true)
                } else {
                    None
                },
            );

            Self {
                end_node_hash,
                predecessor_info,
                successor_info,
            }
        }

        /// Given a boundary node with info stored in `self`, this method generates at random the
        /// information about a node that can be the successor of `self` in a BST. This method
        /// requires as additional inputs the `query_bounds` and a flag `is_index_tree`, which
        /// specifies whether `self` and the generated node should be part of an index tree or
        /// of a rows tree
        pub(crate) fn sample_successor_in_tree<R: Rng>(
            &self,
            rng: &mut R,
            query_bounds: &QueryBounds,
            is_index_tree: bool,
        ) -> Self {
            let (min_query_bound, max_query_bound) = if is_index_tree {
                (
                    query_bounds.min_query_primary(),
                    query_bounds.max_query_primary(),
                )
            } else {
                (
                    *query_bounds.min_query_secondary().value(),
                    *query_bounds.max_query_secondary().value(),
                )
            };
            let end_node_hash = self.successor_info.hash;
            // value of predecessor must be in query range and between the predecessor and successor value
            // of `self`
            let [predecessor_value] = gen_values_in_range(
                rng,
                min_query_bound.max(self.predecessor_info.value),
                self.successor_info.value.min(max_query_bound),
            );
            let predecessor_info = if self.successor_info.is_in_path {
                NeighborInfo::new(predecessor_value, None)
            } else {
                NeighborInfo::new(predecessor_value, Some(self.end_node_hash))
            };
            let [successor_value] = gen_values_in_range(
                rng,
                predecessor_value.max(min_query_bound),
                if is_index_tree {
                    max_query_bound // successor must always be in range in index tree
                } else {
                    U256::MAX
                },
            );
            let successor_info = NeighborInfo::sample(
                rng,
                successor_value,
                if is_index_tree {
                    // in index tree, there must always be a successor for boundary rows
                    Some(true)
                } else {
                    None
                },
            );
            BoundaryRowNodeInfo {
                end_node_hash,
                predecessor_info,
                successor_info,
            }
        }
}

#[derive(Clone, Debug)]
pub(crate) struct BoundaryRowData {
    pub(crate) row_node_info: BoundaryRowNodeInfo,
    pub(crate) index_node_info: BoundaryRowNodeInfo,
}

impl ToFields<F> for BoundaryRowData {
    fn to_fields(&self) -> Vec<F> {
        self.row_node_info
            .to_fields()
            .into_iter()
            .chain(self.index_node_info.to_fields())
            .collect()
    }
}

impl FromFields<F> for BoundaryRowData {
    fn from_fields(t: &[F]) -> Self {
        assert!(t.len() >= BoundaryRowDataTarget::NUM_TARGETS);
        let row_node_info = BoundaryRowNodeInfo::from_fields(t);
        let index_node_info =
            BoundaryRowNodeInfo::from_fields(&t[BoundaryRowNodeInfoTarget::NUM_TARGETS..]);

        Self {
            row_node_info,
            index_node_info,
        }
    }
}

impl BoundaryRowData {
    /// Generate a random instance of `Self`, given the `query_bounds` provided as inputs.
    /// It is employed to generate test data without the need to build an actual test tree
    pub(crate) fn sample<R: Rng>(rng: &mut R, query_bounds: &QueryBounds) -> Self {
        Self {
            row_node_info: BoundaryRowNodeInfo::sample(rng, query_bounds, false),
            index_node_info: BoundaryRowNodeInfo::sample(rng, query_bounds, true),
        }
    }

    /// Given the boundary row `self`, generates at random the data of the consecutive row of
    /// `self`, given the `query_bounds` provided as input. It is employed to generate test data
    /// without the need to build an actual test tree
    pub(crate) fn sample_consecutive_row<R: Rng>(
        &self,
        rng: &mut R,
        query_bounds: &QueryBounds,
    ) -> Self {
        if self.row_node_info.successor_info.is_found
            && self.row_node_info.successor_info.value
                <= *query_bounds.max_query_secondary().value()
        {
            // the successor must be in the same rows tree
            let row_node_info =
                self.row_node_info
                    .sample_successor_in_tree(rng, query_bounds, false);
            Self {
                row_node_info,
                index_node_info: self.index_node_info.clone(),
            }
        } else {
            // the successor must be in a different rows tree
            let end_node_hash = gen_random_field_hash();
            // predecessor value must be out of range in this case
            let [predecessor_value] = gen_values_in_range(
                rng,
                U256::ZERO,
                query_bounds
                    .min_query_secondary()
                    .value()
                    .checked_sub(U256::from(1))
                    .unwrap_or(U256::ZERO),
            );
            let predecessor_info = NeighborInfo::sample(rng, predecessor_value, None);
            let [successor_value] = gen_values_in_range(
                rng,
                predecessor_value.max(*query_bounds.min_query_secondary().value()), // successor value must
                // always be greater than min_secondary in circuit
                U256::MAX,
            );
            let successor_info = NeighborInfo::sample(rng, successor_value, None);
            let row_node_info = BoundaryRowNodeInfo {
                end_node_hash,
                predecessor_info,
                successor_info,
            };
            // index tree node must be a successor of `self.index_node`
            let index_node_info =
                self.index_node_info
                    .sample_successor_in_tree(rng, query_bounds, true);
            Self {
                row_node_info,
                index_node_info,
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use mp2_common::{
        utils::ToFields,
        F,
    };
    use plonky2::{
        field::types::Field,
        hash::hash_types::HashOut,
    };

    use crate::query::universal_circuit::universal_query_gadget::OutputValues;

    use super::BoundaryRowData;

    #[derive(Clone, Debug)]
    pub(crate) struct RowChunkData<const MAX_NUM_RESULTS: usize>
    where
        [(); MAX_NUM_RESULTS - 1]:,
    {
        pub(crate) left_boundary_row: BoundaryRowData,
        pub(crate) right_boundary_row: BoundaryRowData,
        pub(crate) chunk_tree_hash: HashOut<F>,
        pub(crate) output_values: OutputValues<MAX_NUM_RESULTS>,
        pub(crate) num_overflows: u64,
        pub(crate) count: u64,
    }

    impl<const MAX_NUM_RESULTS: usize> ToFields<F> for RowChunkData<MAX_NUM_RESULTS>
    where
        [(); MAX_NUM_RESULTS - 1]:,
    {
        fn to_fields(&self) -> Vec<F> {
            self.left_boundary_row
                .to_fields()
                .into_iter()
                .chain(self.right_boundary_row.to_fields())
                .chain(self.chunk_tree_hash.to_fields())
                .chain(self.output_values.to_fields())
                .chain([
                    F::from_canonical_u64(self.count),
                    F::from_canonical_u64(self.num_overflows),
                ])
                .collect()
        }
    }
}
