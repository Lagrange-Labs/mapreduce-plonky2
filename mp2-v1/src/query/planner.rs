use alloy::primitives::U256;
use anyhow::Context;
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use itertools::Itertools;
use mp2_common::types::HashOutput;
use parsil::{
    assembler::DynamicCircuitPis, bracketer::bracket_secondary_index, symbols::ContextProvider,
    ParsilSettings,
};
use ryhope::{
    storage::{
        pgsql::{PgsqlStorage, ToFromBytea},
        updatetree::UpdateTree,
        FromSettings, PayloadStorage, TransactionalStorage, TreeStorage,
    },
    tree::{MutableTree, NodeContext, TreeTopology},
    Epoch, MerkleTreeKvDb, NodePayload,
};
use std::fmt::Debug;
use tokio_postgres::{row::Row as PsqlRow, types::ToSql, NoTls};
use verifiable_db::query::aggregation::{NodeInfo, QueryBounds};

use crate::indexing::{
    block::BlockPrimaryIndex,
    row::{RowPayload, RowTree, RowTreeKey},
    LagrangeNode,
};

/// There is only the PSQL storage fully supported for the non existence case since one needs to
/// executor particular requests on the DB in this case.
pub type DBRowStorage = PgsqlStorage<RowTree, RowPayload<BlockPrimaryIndex>>;
/// The type of connection to psql backend
pub type DBPool = Pool<PostgresConnectionManager<NoTls>>;

pub struct NonExistenceInfo<K: Clone + std::hash::Hash + std::cmp::Eq> {
    pub node_key: K,
    pub node_info: NodeInfo,
    pub right_child_info: Option<NodeInfo>,
    pub left_child_info: Option<NodeInfo>,
    pub proving_plan: UpdateTree<K>,
}

/// Returns the information necessary to prove that a secondary index value / range doesn't exist
/// in a row tree
///
/// The row tree is given and specialized to psql storage since that is the only official storage
/// supported.
/// The  `table_name` must be the one given to parsil settings, it is the human friendly table
/// name, i.e. the vTable name.
/// The pool is to issue specific query
/// Primary is indicating the primary index over which this row tree is looked at.
/// Settings are the parsil settings corresponding to the current SQL and current table looked at.
/// Pis contain the bounds and placeholders values.
/// TODO: we should extend ryhope to offer this API directly on the tree since it's very related.
pub async fn find_row_node_for_non_existence<C>(
    row_tree: &MerkleTreeKvDb<RowTree, RowPayload<BlockPrimaryIndex>, DBRowStorage>,
    table_name: String,
    pool: &DBPool,
    primary: BlockPrimaryIndex,
    settings: &ParsilSettings<C>,
    bounds: &QueryBounds,
) -> anyhow::Result<NonExistenceInfo<RowTreeKey>>
where
    C: ContextProvider,
{
    let (query_for_min, query_for_max) =
        bracket_secondary_index(&table_name, settings, primary as Epoch, &bounds);

    // try first with lower node than secondary min query bound
    let to_be_proven_node =
        match find_node_for_proof(pool, row_tree, query_for_min, primary, true).await? {
            Some(node) => node,
            None => find_node_for_proof(pool, row_tree, query_for_max, primary, false)
                .await?
                .expect("No valid node found to prove non-existence, something is wrong"),
        };
    let (node_info, left_child_info, right_child_info) =
        get_node_info(&row_tree, &to_be_proven_node, primary as Epoch).await;

    let path = row_tree
        // since the epoch starts at genesis we can directly give the block number !
        .lineage_at(&to_be_proven_node, primary as Epoch)
        .await
        .expect("node doesn't have a lineage?")
        .into_full_path()
        .collect_vec();
    let proving_tree = UpdateTree::from_paths([path], primary as Epoch);
    Ok(NonExistenceInfo {
        node_key: to_be_proven_node.clone(),
        node_info,
        right_child_info,
        left_child_info,
        proving_plan: proving_tree,
    })
}

// this method returns the `NodeContext` of the successor of the node provided as input,
// if the successor exists in the row tree and it stores the same value of the input node (i.e., `value`);
// returns `None` otherwise, as it means that the input node can be used to prove non-existence
async fn get_successor_node_with_same_value(
    row_tree: &MerkleTreeKvDb<RowTree, RowPayload<BlockPrimaryIndex>, DBRowStorage>,
    node_ctx: &NodeContext<RowTreeKey>,
    value: U256,
    primary: BlockPrimaryIndex,
) -> Option<NodeContext<RowTreeKey>> {
    if node_ctx.right.is_some() {
        let (right_child_ctx, payload) = row_tree
            .fetch_with_context_at(node_ctx.right.as_ref().unwrap(), primary as Epoch)
            .await;
        // the value of the successor in this case is `payload.min`, since the successor is the
        // minimum of the subtree rooted in the right child
        if payload.min() != value {
            // the value of successor is different from `value`, so we don't return the
            // successor node
            return None;
        }
        // find successor in the subtree rooted in the right child: it is
        // the leftmost node in such a subtree
        let mut successor_ctx = right_child_ctx;
        while successor_ctx.left.is_some() {
            successor_ctx = row_tree
                .node_context_at(successor_ctx.left.as_ref().unwrap(), primary as Epoch)
                .await
                .expect(
                    format!(
                        "Node context not found for left child of node {:?}",
                        successor_ctx.node_id
                    )
                    .as_str(),
                );
        }
        Some(successor_ctx)
    } else {
        // find successor among the ancestors of current node: we go up in the path
        // until we either found a node whose left child is the previous node in the
        // path, or we get to the root of the tree
        let (mut candidate_successor_ctx, mut candidate_successor_val) = (node_ctx.clone(), value);
        let mut successor_found = false;
        while candidate_successor_ctx.parent.is_some() {
            let (parent_ctx, parent_payload) = row_tree
                .fetch_with_context_at(
                    candidate_successor_ctx.parent.as_ref().unwrap(),
                    primary as Epoch,
                )
                .await;
            candidate_successor_val = parent_payload.value();
            if parent_ctx
                .iter_children()
                .find_position(|child| {
                    child.is_some() && child.unwrap().clone() == candidate_successor_ctx.node_id
                })
                .unwrap()
                .0
                == 0
            {
                // successor_ctx.node_id is left child of parent_ctx node, so parent_ctx is
                // the successor
                candidate_successor_ctx = parent_ctx;
                successor_found = true;
                break;
            } else {
                candidate_successor_ctx = parent_ctx;
            }
        }
        if successor_found {
            if candidate_successor_val != value {
                // the value of successor is different from `value`, so we don't return the
                // successor node
                return None;
            }
            Some(candidate_successor_ctx)
        } else {
            // We got up to the root of the tree without finding the successor,
            // which means that the input node has no successor;
            // so we don't return any node
            None
        }
    }
}

// this method returns the `NodeContext` of the predecessor of the node provided as input,
// if the predecessor exists in the row tree and it stores the same value of the input node (i.e., `value`);
// returns `None` otherwise, as it means that the input node can be used to prove non-existence
async fn get_predecessor_node_with_same_value(
    row_tree: &MerkleTreeKvDb<RowTree, RowPayload<BlockPrimaryIndex>, DBRowStorage>,
    node_ctx: &NodeContext<RowTreeKey>,
    value: U256,
    primary: BlockPrimaryIndex,
) -> Option<NodeContext<RowTreeKey>> {
    if node_ctx.left.is_some() {
        let (left_child_ctx, payload) = row_tree
            .fetch_with_context_at(node_ctx.right.as_ref().unwrap(), primary as Epoch)
            .await;
        // the value of the predecessor in this case is `payload.max`, since the predecessor is the
        // maximum of the subtree rooted in the left child
        if payload.max() != value {
            // the value of predecessor is different from `value`, so we don't return the
            // predecessor node
            return None;
        }
        // find predecessor in the subtree rooted in the left child: it is
        // the rightmost node in such a subtree
        let mut predecessor_ctx = left_child_ctx;
        while predecessor_ctx.right.is_some() {
            predecessor_ctx = row_tree
                .node_context_at(predecessor_ctx.right.as_ref().unwrap(), primary as Epoch)
                .await
                .expect(
                    format!(
                        "Node context not found for right child of node {:?}",
                        predecessor_ctx.node_id
                    )
                    .as_str(),
                );
        }
        Some(predecessor_ctx)
    } else {
        // find successor among the ancestors of current node: we go up in the path
        // until we either found a node whose right child is the previous node in the
        // path, or we get to the root of the tree
        let (mut candidate_predecessor_ctx, mut candidate_predecessor_val) =
            (node_ctx.clone(), value);
        let mut predecessor_found = false;
        while candidate_predecessor_ctx.parent.is_some() {
            let (parent_ctx, parent_payload) = row_tree
                .fetch_with_context_at(
                    candidate_predecessor_ctx.parent.as_ref().unwrap(),
                    primary as Epoch,
                )
                .await;
            candidate_predecessor_val = parent_payload.value();
            if parent_ctx
                .iter_children()
                .find_position(|child| {
                    child.is_some() && child.unwrap().clone() == candidate_predecessor_ctx.node_id
                })
                .unwrap()
                .0
                == 1
            {
                // predecessor_ctx.node_id is right child of parent_ctx node, so parent_ctx is
                // the predecessor
                candidate_predecessor_ctx = parent_ctx;
                predecessor_found = true;
                break;
            } else {
                candidate_predecessor_ctx = parent_ctx;
            }
        }
        if predecessor_found {
            if candidate_predecessor_val != value {
                // the value of predecessor is different from `value`, so we don't return the
                // predecessor node
                return None;
            }
            Some(candidate_predecessor_ctx)
        } else {
            // We got up to the root of the tree without finding the predecessor,
            // which means that the input node has no predecessor;
            // so we don't return any node
            None
        }
    }
}

async fn find_node_for_proof(
    db: &DBPool,
    row_tree: &MerkleTreeKvDb<RowTree, RowPayload<BlockPrimaryIndex>, DBRowStorage>,
    query: Option<String>,
    primary: BlockPrimaryIndex,
    is_min_query: bool,
) -> anyhow::Result<Option<RowTreeKey>> {
    if query.is_none() {
        return Ok(None);
    }
    let rows = execute_row_query(db, &query.unwrap(), &[]).await?;
    if rows.is_empty() {
        // no node found, return None
        return Ok(None);
    }
    let row_key = rows[0]
        .get::<_, Option<Vec<u8>>>(0)
        .map(RowTreeKey::from_bytea)
        .context("unable to parse row key tree")
        .expect("");
    // among the nodes with the same index value of the node with `row_key`, we need to find
    // the one that satisfies the following property: all its successor nodes have values bigger
    // than `max_query_secondary`, and all its predecessor nodes have values smaller than
    // `min_query_secondary`. Such a node can be found differently, depending on the case:
    // - if `is_min_query = true`, then we are looking among nodes with the highest value smaller
    //   than `min_query_secondary` bound (call this value `min_value`);
    //   therefore, we need to find the "last" node among the nodes with value `min_value`, that
    //   is the node whose successor (if exists) has a value bigger than `min_value`. Since there
    //   are no nodes in the tree in the range [`min_query_secondary, max_query_secondary`], then
    //   the value of the successor of the "last" node is necessarily bigger than `max_query_secondary`,
    //   and so it implies that we found the node satisfying the property mentioned above
    // - if `is_min_query = false`, then we are looking among nodes with the smallest value higher
    //   than `max_query_secondary` bound (call this value `max_value`);
    //   therefore, we need to find the "first" node among the nodes with value `max_value`, that
    //   is the node whose predecessor (if exists) has a value smaller than `max_value`. Since there
    //   are no nodes in the tree in the range [`min_query_secondary, max_query_secondary`], then
    //   the value of the predecessor of the "first" node is necessarily smaller than `min_query_secondary`,
    //   and so it implies that we found the node satisfying the property mentioned above
    let (mut node_ctx, node_value) = row_tree
        .fetch_with_context_at(&row_key, primary as Epoch)
        .await;
    let value = node_value.value();

    if is_min_query {
        // starting from the node with key `row_key`, we iterate over its successor nodes in the tree,
        // until we found a node that either has no successor or whose successor stores a value different
        // from the value `value` stored in the node with key `row_key`; the node found is the one to be
        // employed to generate the non-existence proof
        let mut successor_ctx =
            get_successor_node_with_same_value(&row_tree, &node_ctx, value, primary).await;
        while successor_ctx.is_some() {
            node_ctx = successor_ctx.unwrap();
            successor_ctx =
                get_successor_node_with_same_value(&row_tree, &node_ctx, value, primary).await;
        }
    } else {
        // starting from the node with key `row_key`, we iterate over its predecessor nodes in the tree,
        // until we found a node that either has no predecessor or whose predecessor stores a value different
        // from the value `value` stored in the node with key `row_key`; the node found is the one to be
        // employed to generate the non-existence proof
        let mut predecessor_ctx =
            get_predecessor_node_with_same_value(&row_tree, &node_ctx, value, primary).await;
        while predecessor_ctx.is_some() {
            node_ctx = predecessor_ctx.unwrap();
            predecessor_ctx =
                get_predecessor_node_with_same_value(&row_tree, &node_ctx, value, primary).await;
        }
    }

    Ok(Some(node_ctx.node_id))
}

pub async fn execute_row_query(
    pool: &DBPool,
    query: &str,
    params: &[U256],
) -> anyhow::Result<Vec<PsqlRow>> {
    // introduce this closure to coerce each param to have type `dyn ToSql + Sync` (required by pgSQL APIs)
    let prepare_param = |param: U256| -> Box<dyn ToSql + Sync> { Box::new(param) };
    let query_params = params
        .iter()
        .map(|param| prepare_param(*param))
        .collect_vec();
    let connection = pool.get().await.unwrap();
    let res = connection
        .query(
            query,
            &query_params
                .iter()
                .map(|param| param.as_ref())
                .collect_vec(),
        )
        .await
        .context("while fetching current epoch")?;
    Ok(res)
}

async fn get_node_info<T, V, S>(
    lookup: &MerkleTreeKvDb<T, V, S>,
    k: &T::Key,
    at: Epoch,
) -> (NodeInfo, Option<NodeInfo>, Option<NodeInfo>)
where
    T: TreeTopology + MutableTree + Send,
    V: NodePayload + Send + Sync + LagrangeNode,
    S: TransactionalStorage + TreeStorage<T> + PayloadStorage<T::Key, V> + FromSettings<T::State>,
    T::Key: Debug,
{
    // look at the left child first then right child, then build the node info
    let (ctx, node_payload) = lookup
        .try_fetch_with_context_at(k, at)
        .await
        .expect("cache not filled");
    // this looks at the value of a child node (left and right), and fetches the grandchildren
    // information to be able to build their respective node info.
    let fetch_ni = async |k: Option<T::Key>| -> (Option<NodeInfo>, Option<HashOutput>) {
        match k {
            None => (None, None),
            Some(child_k) => {
                let (child_ctx, child_payload) = lookup
                    .try_fetch_with_context_at(&child_k, at)
                    .await
                    .expect("cache not filled");
                // we need the grand child hashes for constructing the node info of the
                // children of the node in argument
                let child_left_hash = match child_ctx.left {
                    Some(left_left_k) => {
                        let (_, payload) = lookup
                            .try_fetch_with_context_at(&left_left_k, at)
                            .await
                            .expect("cache not filled");
                        Some(payload.hash())
                    }
                    None => None,
                };
                let child_right_hash = match child_ctx.right {
                    Some(left_right_k) => {
                        let (_, payload) = lookup
                            .try_fetch_with_context_at(&left_right_k, at)
                            .await
                            .expect("cache not full");
                        Some(payload.hash())
                    }
                    None => None,
                };
                let left_ni = NodeInfo::new(
                    &child_payload.embedded_hash(),
                    child_left_hash.as_ref(),
                    child_right_hash.as_ref(),
                    child_payload.value(),
                    child_payload.min(),
                    child_payload.max(),
                );
                (Some(left_ni), Some(child_payload.hash()))
            }
        }
    };
    let (left_node, left_hash) = fetch_ni(ctx.left).await;
    let (right_node, right_hash) = fetch_ni(ctx.right).await;
    (
        NodeInfo::new(
            &node_payload.embedded_hash(),
            left_hash.as_ref(),
            right_hash.as_ref(),
            node_payload.value(),
            node_payload.min(),
            node_payload.max(),
        ),
        left_node,
        right_node,
    )
}
