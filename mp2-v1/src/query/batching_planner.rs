use anyhow::Result;
use std::{collections::BTreeSet, fmt::Debug, hash::Hash};

use alloy::primitives::U256;
use futures::{stream, StreamExt};
use hashbrown::HashMap;
use itertools::Itertools;
use parsil::symbols::ContextProvider;
use ryhope::{
    storage::{pgsql::DbBackend, updatetree::UpdateTree, WideLineage},
    Epoch,
};
use serde::{Deserialize, Serialize};
use verifiable_db::query::{
    api::{NodePath, RowInput, TreePathInputs},
    computational_hash_ids::ColumnIDs,
    universal_circuit::universal_circuit_inputs::{ColumnCell, RowCells},
};

use crate::{
    indexing::{
        block::{BlockPrimaryIndex, BlockTreeKey},
        index::IndexNode,
        row::{RowPayload, RowTreeKey},
    },
    query::planner::TreeFetcher,
};

use super::planner::NonExistenceInput;

async fn compute_input_for_row<T: TreeFetcher<RowTreeKey, RowPayload<BlockPrimaryIndex>>>(
    tree: &T,
    row_key: &RowTreeKey,
    index_value: BlockPrimaryIndex,
    index_path: &TreePathInputs,
    column_ids: &ColumnIDs,
) -> RowInput {
    let row_path = tree
        .compute_path(row_key, index_value as Epoch)
        .await
        .unwrap_or_else(|| panic!("node with key {:?} not found in cache", row_key));
    let path = NodePath::new(row_path, index_path.clone());
    let (_, row_payload) = tree
        .fetch_ctx_and_payload_at(row_key, index_value as Epoch)
        .await
        .unwrap_or_else(|| panic!("node with key {:?} not found in cache", row_key));
    // build row cells
    let primary_index_cell = ColumnCell::new(column_ids.primary_column(), U256::from(index_value));
    let secondary_index_cell = ColumnCell::new(
        column_ids.secondary_column(),
        row_payload.secondary_index_value(),
    );
    let non_indexed_cells = column_ids
        .non_indexed_columns()
        .into_iter()
        .filter_map(|id| {
            row_payload
                .cells
                .find_by_column(id)
                .map(|info| ColumnCell::new(id, info.value))
        })
        .collect::<Vec<_>>();
    let row_cells = RowCells::new(primary_index_cell, secondary_index_cell, non_indexed_cells);
    RowInput::new(&row_cells, &path)
}

/// Given the subtree built from the rows satisyfing the query ranges on primary and
/// secondary indexes, this method splits the rows in chunks of `CHUNK_SIZE` consecutive
/// rows, with all the rows in the same chunk being proven all together in the same
/// circuit. The method also builds the `UpdateTree` that specifies how to recursively
/// aggregate all these chunks, using the chunk aggregation circuit. The `NUM_CHUNKS`
/// constant corresponds to the maximum number of chunks that can be aggregated by such
/// circuit, and will thus correspond to the arity of the constructed `UpdateTree`.
/// The method requires the following inputs:
/// - `row_cache` : Wide lineage of rows tree nodes in the subtree build from the rows
///     satisfying the the query ranges on primary and secondary indexes
/// - `index_cache` : Wide lineage of index tree nodes in the subtree build from the rows
///     satisfying the the query ranges on primary and secondary indexes
/// - `column_ids` : Identifiers of the columns of the table, including primary and
///     secondary indexes columns
/// - `non_existence_inputs` : This set of data is employed to find the proper row to be
///     proven for a rows tree that contains no rows with a secondary index value lying
///     in the query range over secondary index, which still needs to be proven for
///     completeness (i.e., proving that we are not skipping potentially matching rows
///     for the query); this data structure can be instantiated with its own `new` method
/// - `epoch` : Last epoch inserted in the index tree
pub async fn generate_chunks_and_update_tree<
    const CHUNK_SIZE: usize,
    const NUM_CHUNKS: usize,
    C: ContextProvider,
    B: DbBackend,
>(
    row_cache: WideLineage<RowTreeKey, RowPayload<BlockPrimaryIndex>>,
    index_cache: WideLineage<BlockTreeKey, IndexNode<BlockPrimaryIndex>>,
    column_ids: &ColumnIDs,
    non_existence_inputs: NonExistenceInput<'_, C, B>,
    epoch: Epoch,
) -> Result<(
    HashMap<UTKey<NUM_CHUNKS>, Vec<RowInput>>,
    UTForChunks<NUM_CHUNKS>,
)> {
    let chunks = generate_chunks::<CHUNK_SIZE, C, B>(
        row_cache,
        index_cache,
        column_ids,
        non_existence_inputs,
    )
    .await?;
    Ok(UTForChunksBuilder { chunks }.build_update_tree_with_base_chunks(epoch))
}

async fn generate_chunks<const CHUNK_SIZE: usize, C: ContextProvider, B: DbBackend>(
    row_cache: WideLineage<RowTreeKey, RowPayload<BlockPrimaryIndex>>,
    index_cache: WideLineage<BlockTreeKey, IndexNode<BlockPrimaryIndex>>,
    column_ids: &ColumnIDs,
    non_existence_inputs: NonExistenceInput<'_, C, B>,
) -> Result<Vec<Vec<RowInput>>> {
    let index_keys_by_epochs = index_cache.keys_by_epochs();
    assert_eq!(index_keys_by_epochs.len(), 1);
    let row_keys_by_epochs = row_cache.keys_by_epochs();
    let current_epoch = *index_keys_by_epochs.keys().next().unwrap() as Epoch;
    let sorted_index_values = index_keys_by_epochs[&current_epoch]
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();

    let prove_rows = async |index_value| {
        let index_path = index_cache
            .compute_path(&index_value, current_epoch)
            .await
            .unwrap_or_else(|| panic!("node with key {index_value} not found in index tree cache"));
        let proven_rows = if let Some(matching_rows) =
            row_keys_by_epochs.get(&(index_value as Epoch))
        {
            let sorted_rows = matching_rows.iter().collect::<BTreeSet<_>>();
            stream::iter(sorted_rows.iter())
                .then(async |&row_key| {
                    compute_input_for_row(&row_cache, row_key, index_value, &index_path, column_ids)
                        .await
                })
                .collect::<Vec<RowInput>>()
                .await
        } else {
            let proven_node = non_existence_inputs
                .find_row_node_for_non_existence(index_value)
                .await
                .unwrap_or_else(|_| {
                    panic!("node for non-existence not found for index value {index_value}")
                });
            let row_input = compute_input_for_row(
                non_existence_inputs.row_tree,
                &proven_node,
                index_value,
                &index_path,
                column_ids,
            )
            .await;
            vec![row_input]
        };
        proven_rows
    };

    // TODO: This implementation causes an error in DQ:
    // `implementation of `std::marker::Send` is not general enough`
    /*
        let chunks = stream::iter(sorted_index_values.into_iter())
            .then(prove_rows)
            .concat()
            .await
    */
    let mut chunks = vec![];
    for index_value in sorted_index_values {
        let chunk = prove_rows(index_value).await;
        chunks.extend(chunk);
    }

    let chunks = chunks
        .chunks(CHUNK_SIZE)
        .map(|chunk| chunk.to_vec())
        .collect_vec();

    Ok(chunks)
}

/// Key for nodes of the `UTForChunks<NUM_CHUNKS>` employed to
/// prove chunks of rows.
/// The key is composed by 2 integers:
/// - The `level` of the node in the `UpdateTree`, that is the number of
///   ancestor nodes between the node and the root of the tree
/// - The `position` of the node in the tree among the nodes with the same
///   `level`. The position is basically an identifier to uniquely identify
///   a node among all the nodes in the same level. It is computed recursively
///   from the position `parent_pos` of the parent node and the number of left
///   siblings `num_left` of the node as `parent_pos*ARITY + num_left`
///
/// For instance, consider the following tree, with arity 3:
/// ```text
///                 A
///
///     B           C           D
///
/// E   F   G       H   I
/// ```
/// The nodes in this tree will be identified by the following keys:
/// ```text
///                             (0,0)
///
///        (1,0)                (1,1)               (1,2)
///
/// (2,0)  (2,1)  (2,2)         (2,3)  (2,4)
/// ```
#[derive(
    Clone, Copy, Debug, Default, PartialEq, PartialOrd, Ord, Eq, Hash, Serialize, Deserialize,
)]
pub struct UTKey<const ARITY: usize>(pub (usize, usize));

impl<const ARITY: usize> UTKey<ARITY> {
    /// Compute the key of the child node of `self` that has `num_left_siblings`
    /// left siblings
    fn children_key(&self, num_left_siblings: usize) -> Self {
        let Self((parent_level, parent_pos)) = self;
        Self((*parent_level + 1, *parent_pos * ARITY + num_left_siblings))
    }
}

/// `UpdateTree` employed to prove chunks and aggregate chunks of rows
/// into a single proof. The tree is built employing a `ProvingTree<NUM_CHUNKS>`
/// as the skeleton tree, which determines the structure of the tree.
pub type UTForChunks<const NUM_CHUNKS: usize> = UpdateTree<UTKey<NUM_CHUNKS>>;

/// Data atructure employed to build the `UpdateTreeForChunks` for the set of chunks
#[derive(Clone, Debug)]
struct UTForChunksBuilder<const NUM_CHUNKS: usize> {
    chunks: Vec<Vec<RowInput>>,
}

/// Convenience trait, used just to implement the public methods to be exposed
/// for the `UpdateTreeForChunks` type alias
pub trait UTForChunkProofs<const NUM_CHUNKS: usize> {
    type K: Clone + Debug + Eq + PartialEq + Hash;

    /// Get the keys of the children nodes in the update tree
    /// of the node with key `node_key`
    fn get_children_keys(&self, node_key: &Self::K) -> Vec<Self::K>;
}

impl<const NUM_CHUNKS: usize> UTForChunkProofs<NUM_CHUNKS> for UTForChunks<NUM_CHUNKS> {
    type K = UTKey<NUM_CHUNKS>;

    fn get_children_keys(&self, node_key: &Self::K) -> Vec<Self::K> {
        (0..NUM_CHUNKS)
            .filter_map(|i| {
                // first, compute the child key for the i-th potential child
                let child_key = node_key.children_key(i);
                // then, return the computed key only if the i-th child exists in the tree
                self.node_from_key(&child_key).map(|_| child_key)
            })
            .collect_vec()
    }
}

/// Tree employed as a skeleton to build the `UTForChunks`, which is
/// employed to prove and aggregate rows chunks. Each node in the tree corresponds
/// to a proof being generated:
/// - Leaf nodes are associated to the proving of a single row chunk
/// - Internal nodes are associated to the proving of aggregation of multiple row chunks,
///   and so ARITY of the tree corresponds to the maximum number of chunks that can be
///   aggregated in a single proof
///
/// Given the number of leaves `n`, which correspond to the number of chunks to be aggregated,
/// the tree is built in such a way to minimize the number of internal nodes, hereby
/// minimzing the number of proofs to be generated. The overall idea is:
/// - Place as many leaves as possible in `full` subtrees. A full subtree is defined as
///   a subtree containing `ARITY^exp` leaves, for an `exp >= 0`. In particular, it is
///   always possible to build at least one full subtree with `exp = ceil(log_{ARITY}(n))-1`.
///   Note that, depending on `n`, it might be possible to build from one up to `ARITY` full
///   subtrees, each containing `ARITY^exp` number of leaves
/// - If there are leaves that cannot be placed inside a full subtree, then by construction
///   at most `ARITY-1` full subtrees have been built and placed as child nodes of the root,
///   and so there are still `m >= 1` spots available among the children of the root.
///   So, up to `m-1` remaining leaves are placed as direct children of the root; if there
///   are more than `m-1` remaining leaves, they are placed in a subtree, built
///   recursively using the same logic, which is placed as a further child of the root
///
/// More details on the algorithm to construct a tree can be found in the `build_subtree`
/// method
#[derive(Clone, Debug)]
struct ProvingTree<const ARITY: usize> {
    // all the nodes of the tree, indexed by the key of the node
    nodes: HashMap<UTKey<ARITY>, ProvingTreeNode<ARITY>>,
    // leaves of the tree, identified by their key. The leaves are inserted in
    // this vector in order (i.e, from left to right in the tree) when building
    // the tree. The position of a leaf in this vector is referred to as
    // `leaf_index`
    leaves: Vec<UTKey<ARITY>>,
}

/// Node of the proving tree, containing the keys of the parent node and
/// of the children
#[derive(Clone, Debug)]
struct ProvingTreeNode<const ARITY: usize> {
    parent_key: Option<UTKey<ARITY>>,
    children_keys: Vec<UTKey<ARITY>>,
}

impl<const ARITY: usize> ProvingTree<ARITY> {
    /// Build a new `ProvingTree` with `num_leaves` leaf nodes
    fn new(num_leaves: usize) -> Self {
        let mut tree = ProvingTree {
            nodes: HashMap::new(),
            leaves: vec![],
        };
        if num_leaves > 0 {
            // build a subtree for `num_leaves`
            tree.build_subtree(num_leaves, None);
        }

        tree
    }

    /// Insert a node as a child node of the node with key `parent_node_key`.
    /// The node is inserted as root if `parent_node_key` is `None`
    fn insert_as_child_of(&mut self, parent_node_key: Option<&UTKey<ARITY>>) -> UTKey<ARITY> {
        if let Some(parent_key) = parent_node_key {
            // get parent node
            let parent_node = self.nodes.get_mut(parent_key).unwrap_or_else(|| {
                panic!(
                    "Providing a non-existing parent key for insertion: {:?}",
                    parent_key
                )
            });
            // get number of existing children for the parent node, which is needed to compute
            // the key of the child to be inserted
            let num_childrens = parent_node.children_keys.len();
            let new_child_key = parent_key.children_key(num_childrens);
            let child_node = ProvingTreeNode {
                parent_key: Some(*parent_key),
                children_keys: vec![],
            };
            // insert new child in the set of children of the parent
            parent_node.children_keys.push(new_child_key);
            assert!(
                self.nodes.insert(new_child_key, child_node).is_none(),
                "Node with key {:?} already found in the tree",
                new_child_key
            );
            new_child_key
        } else {
            // insert as root
            let root = ProvingTreeNode {
                parent_key: None,
                children_keys: vec![],
            };
            let root_key = UTKey((0, 0));
            assert!(
                self.nodes.insert(root_key, root).is_none(),
                "Error: root node inserted multiple times"
            );
            root_key
        }
    }

    /// Build a full subtree containing `num_leaves` leaf nodes. The subtree
    /// is full since `num_leaves` is expected to be `ARITY^exp`, for `exp >= 0`.
    /// `parent_node_key` is the key of the parent node of the root of the subtree
    fn build_full_subtree(&mut self, num_leaves: usize, parent_node_key: &UTKey<ARITY>) {
        let root_key = self.insert_as_child_of(Some(parent_node_key));
        if num_leaves > 1 {
            for _ in 0..ARITY {
                self.build_full_subtree(num_leaves / ARITY, &root_key);
            }
        } else {
            // it's a leaf node, so we add it to leaves
            self.leaves.push(root_key);
        }
    }

    /// Build a subtree containing `num_leaves` leaf nodes.
    /// `parent_node_key` is the key of the parent node of the root of the subtree, if any
    fn build_subtree(&mut self, num_leaves: usize, parent_node_key: Option<&UTKey<ARITY>>) {
        let root_key = self.insert_as_child_of(parent_node_key);
        if num_leaves == 1 {
            // we are done, we just add the root node as a leaf
            return self.leaves.push(root_key);
        }
        // we compute the number of full subtrees we can employ to place leaves.
        // A full subtree is a subtree that contains ARITY^exp leaves for some exp >= 0.
        // Given `num_leaves`, we know we can always build at least 1 full subtree
        // for `exp =ceil(log_{ARITY}(num_leaves))-1`, i.e., a full subtree
        // containing `ARITY^exp` leaves.
        let num_leaves_in_subtree = smallest_greater_power::<ARITY>(num_leaves) / ARITY;
        let num_full_subtrees = num_leaves / num_leaves_in_subtree;
        for _ in 0..num_full_subtrees {
            self.build_full_subtree(num_leaves_in_subtree, &root_key);
        }
        // overall number of leaves placed in the `num_full_subtrees` full subtrees
        let inserted_leaves = num_leaves_in_subtree * num_full_subtrees;
        let remaining_leaves = num_leaves - inserted_leaves;
        // number of nodes still available at the current level
        let available_nodes_at_level = ARITY - num_full_subtrees;
        // compute the number of leaves to be placed at the current level
        let num_leaves_at_level = if remaining_leaves > available_nodes_at_level {
            // we place `available_nodes_at_level - 1` leaf nodes in this level,
            // while all the other remaining nodes are placed in a subtree, which is built
            // recursively
            let num_leaves_at_level = available_nodes_at_level - 1;
            self.build_subtree(remaining_leaves - num_leaves_at_level, Some(&root_key));
            num_leaves_at_level
        } else {
            // we can place all remaining nodes at this level as leaf nodes
            remaining_leaves
        };
        // place the leaves at the current level
        for _ in 0..num_leaves_at_level {
            let leaf_key = self.insert_as_child_of(Some(&root_key));
            self.leaves.push(leaf_key);
        }
    }

    /// Compute the path, from root to leaf, for the leaf with index `leaf_index`
    /// in `self` tree
    fn compute_path_for_leaf(&self, leaf_index: usize) -> Vec<UTKey<ARITY>> {
        let leaf_key = &self.leaves[leaf_index];
        let mut path = vec![];
        let mut node_key = Some(leaf_key);
        while node_key.is_some() {
            // place node key in the path
            let key = node_key.unwrap();
            path.push(*key);
            // fetch key of the parent node, if any
            node_key = self
                .nodes
                .get(key)
                .unwrap_or_else(|| panic!("Node with key {:?} not found", key))
                .parent_key
                .as_ref();
        }

        path.reverse();
        path
    }
}

impl<const NUM_CHUNKS: usize> UTForChunksBuilder<NUM_CHUNKS> {
    /// This method builds an `UpdateTree` to prove and aggregate the set of chunks
    /// provided as input. It also returns the set of chunks to be proven, with each
    /// chunk being associated to the key of the node in the `UpdateTree` corresponding
    /// to the proving task for that chunk
    fn build_update_tree_with_base_chunks(
        self,
        epoch: Epoch,
    ) -> (
        HashMap<UTKey<NUM_CHUNKS>, Vec<RowInput>>,
        UTForChunks<NUM_CHUNKS>,
    ) {
        let num_chunks = self.chunks.len();
        let tree = ProvingTree::<NUM_CHUNKS>::new(num_chunks);
        let (chunks_with_keys, paths): (HashMap<_, _>, Vec<_>) = self
            .chunks
            .into_iter()
            .enumerate()
            .map(|(node_index, chunk)| {
                let path = tree.compute_path_for_leaf(node_index);
                (
                    (
                        *path.last().unwrap(), // chunk node is always a leaf of the tree, so it is the last node
                        // in the path
                        chunk,
                    ),
                    path,
                )
            })
            .unzip();
        (chunks_with_keys, UpdateTree::from_paths(paths, epoch))
    }
}

// Method to compute the smallest power of `BASE` greater than the provided `input`.
// In other words, it computes `BASE^ceil(log_BASE(input))``
fn smallest_greater_power<const BASE: usize>(input: usize) -> usize {
    let mut pow = 1usize;
    while pow < input {
        pow *= BASE;
    }
    pow
}
