//! Module to handle the block number as a primary index
use anyhow::anyhow;
use ryhope::{
    storage::{pgsql::PgsqlStorage, RoEpochKvStorage},
    tree::{sbbst, TreeTopology},
    MerkleTreeKvDb,
};

use crate::query::planner::TreeFetcher;

use super::index::IndexNode;

/// The index tree when the primary index is an epoch in a time-series DB, like the block number for a blockchain.
/// It is a sbbst since it is a highly optimized tree for monotonically increasing index.
/// It produces very little tree-manipulating operations on update, and therefore, requires the least amount
/// of reproving when adding a new index.
/// NOTE: it is still required that monotonically increasing indexes are inserted in the tree,
/// i.e. a general index such as what can happen on a result table wouldn't work with this tree.
pub type BlockTree = sbbst::EpochTree;
/// The key used to refer to a table where the block number is the primary index.
pub type BlockTreeKey = <BlockTree as TreeTopology>::Key;
/// Just an alias that give more meaning depending on the context
pub type BlockPrimaryIndex = BlockTreeKey;

pub type IndexStorage = PgsqlStorage<BlockTree, IndexNode<BlockPrimaryIndex>, false>;
pub type MerkleIndexTree = MerkleTreeKvDb<BlockTree, IndexNode<BlockPrimaryIndex>, IndexStorage>;

/// Get the previous epoch of `epoch` in `tree`
pub async fn get_previous_epoch(
    tree: &MerkleIndexTree,
    epoch: BlockPrimaryIndex,
) -> anyhow::Result<Option<BlockPrimaryIndex>> {
    let current_epoch = tree.current_epoch().await?;
    let epoch_ctx = tree
        .node_context(&epoch)
        .await?
        .ok_or(anyhow!("epoch {epoch} not found in the tree"))?;

    Ok(tree
        .get_predecessor(&epoch_ctx, current_epoch)
        .await
        .map(|(ctx, _)| ctx.node_id))
}

/// Get the next epoch of `epoch` in `tree`
pub async fn get_next_epoch(
    tree: &MerkleIndexTree,
    epoch: BlockPrimaryIndex,
) -> anyhow::Result<Option<BlockPrimaryIndex>> {
    let current_epoch = tree.current_epoch().await?;
    let epoch_ctx = tree
        .node_context(&epoch)
        .await?
        .ok_or(anyhow!("epoch {epoch} not found in the tree"))?;

    Ok(tree
        .get_successor(&epoch_ctx, current_epoch)
        .await
        .map(|(ctx, _)| ctx.node_id))
}
