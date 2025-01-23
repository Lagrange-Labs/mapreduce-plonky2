use alloy::primitives::U256;
use anyhow::Context;
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use core::hash::Hash;
use futures::stream::TryStreamExt;
use itertools::Itertools;
use mp2_common::types::HashOutput;
use parsil::{bracketer::bracket_secondary_index, symbols::ContextProvider, ParsilSettings};
use ryhope::{
    storage::{
        pgsql::{PgsqlStorage, ToFromBytea},
        updatetree::UpdateTree,
        FromSettings, PayloadStorage, TransactionalStorage, TreeStorage, WideLineage,
    },
    tree::{MutableTree, NodeContext, TreeTopology},
    Epoch, MerkleTreeKvDb, NodePayload,
};
use std::{fmt::Debug, future::Future};
use tokio_postgres::{row::Row as PsqlRow, types::ToSql, NoTls};
use verifiable_db::query::{
    api::TreePathInputs,
    utils::{ChildPosition, NodeInfo, QueryBounds},
};

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
    pub proving_plan: UpdateTree<K>,
}

#[derive(Clone)]
pub struct NonExistenceInput<'a, C: ContextProvider> {
    pub(crate) row_tree: &'a MerkleTreeKvDb<RowTree, RowPayload<BlockPrimaryIndex>, DBRowStorage>,
    pub(crate) table_name: String,
    pub(crate) pool: &'a DBPool,
    pub(crate) settings: &'a ParsilSettings<C>,
    pub(crate) bounds: QueryBounds,
}

impl<'a, C: ContextProvider> NonExistenceInput<'a, C> {
    pub fn new(
        row_tree: &'a MerkleTreeKvDb<RowTree, RowPayload<BlockPrimaryIndex>, DBRowStorage>,
        table_name: String,
        pool: &'a DBPool,
        settings: &'a ParsilSettings<C>,
        bounds: &'a QueryBounds,
    ) -> Self {
        Self {
            row_tree,
            table_name,
            pool,
            settings,
            bounds: bounds.clone(),
        }
    }

    pub async fn find_row_node_for_non_existence(
        &self,
        primary: BlockPrimaryIndex,
    ) -> anyhow::Result<RowTreeKey> {
        let (query_for_min, query_for_max) = bracket_secondary_index(
            &self.table_name,
            self.settings,
            primary as Epoch,
            &self.bounds,
        );

        // try first with lower node than secondary min query bound
        let to_be_proven_node =
            match find_node_for_proof(self.pool, self.row_tree, query_for_min, primary, true)
                .await?
            {
                Some(node) => node,
                None => {
                    find_node_for_proof(self.pool, self.row_tree, query_for_max, primary, false)
                        .await?
                        .expect("No valid node found to prove non-existence, something is wrong")
                }
            };

        Ok(to_be_proven_node)
    }
}

pub trait TreeFetcher<K: Debug + Clone + Eq + PartialEq, V: LagrangeNode>: Sized {
    /// Constant flag specifying whether the implementor is a `WideLineage` or not
    const IS_WIDE_LINEAGE: bool;

    fn fetch_ctx_and_payload_at(
        &self,
        k: &K,
        epoch: Epoch,
    ) -> impl Future<Output = Option<(NodeContext<K>, V)>> + Send;

    fn compute_path(
        &self,
        node_key: &K,
        epoch: Epoch,
    ) -> impl Future<Output = Option<TreePathInputs>> {
        async move {
            let (node_ctx, node_payload) = self.fetch_ctx_and_payload_at(node_key, epoch).await?;
            let mut current_node_key = node_ctx.parent.clone();
            let mut previous_node_key = node_key.clone();
            let mut path = vec![];
            while current_node_key.is_some() {
                let (ctx, payload) = self
                    .fetch_ctx_and_payload_at(current_node_key.as_ref().unwrap(), epoch)
                    .await
                    .unwrap_or_else(|| {
                        panic!("node with key {:?} not found in tree", current_node_key)
                    });
                let child_position = match ctx
                    .iter_children()
                    .find_position(|child| {
                        child.is_some() && child.unwrap().clone() == previous_node_key
                    })
                    .unwrap()
                    .0
                {
                    0 => ChildPosition::Left,
                    1 => ChildPosition::Right,
                    _ => unreachable!(),
                };
                previous_node_key = current_node_key.unwrap();
                current_node_key = ctx.parent.clone();
                let node_info = self.compute_node_info(ctx, payload, epoch).await;
                path.push((node_info, child_position));
            }
            let (node_info, left_child, right_child) =
                get_node_info_from_ctx_and_payload(self, node_ctx, node_payload, epoch).await;

            Some(TreePathInputs::new(
                node_info,
                path,
                [left_child, right_child],
            ))
        }
    }

    fn compute_node_info(
        &self,
        node_ctx: NodeContext<K>,
        node_payload: V,
        at: Epoch,
    ) -> impl Future<Output = NodeInfo> {
        async move {
            let child_hash = async |k: Option<K>| -> Option<HashOutput> {
                match k {
                    Some(child_key) => self
                        .fetch_ctx_and_payload_at(&child_key, at)
                        .await
                        .map(|(_ctx, payload)| payload.hash()),
                    None => None,
                }
            };

            let left_child_hash = child_hash(node_ctx.left).await;
            let right_child_hash = child_hash(node_ctx.right).await;
            NodeInfo::new(
                &node_payload.embedded_hash(),
                left_child_hash.as_ref(),
                right_child_hash.as_ref(),
                node_payload.value(),
                node_payload.min(),
                node_payload.max(),
            )
        }
    }

    /// This method computes the successor of the node with context `node_ctx` in the input `tree`
    /// at the given `epoch`. It returns the context of the successor node and its payload
    fn get_successor(
        &self,
        node_ctx: &NodeContext<K>,
        epoch: Epoch,
    ) -> impl Future<Output = Option<(NodeContext<K>, V)>>
    where
        K: Clone + Debug + Eq + PartialEq,
    {
        async move {
            if node_ctx.right.is_some() {
                if let Some((right_child_ctx, right_child_payload)) =
                    fetch_existing_node_from_tree(self, node_ctx.right.as_ref().unwrap(), epoch)
                        .await
                {
                    // find successor in the subtree rooted in the right child: it is
                    // the leftmost node in such a subtree
                    let (mut successor_ctx, mut successor_payload) =
                        (right_child_ctx, right_child_payload);
                    while successor_ctx.left.is_some() {
                        let Some((ctx, payload)) = fetch_existing_node_from_tree(
                            self,
                            successor_ctx.left.as_ref().unwrap(),
                            epoch,
                        )
                        .await
                        else {
                            // we don't found the left child node in the tree, which means that the
                            // successor might be out of range, so we return None
                            return None;
                        };
                        successor_ctx = ctx;
                        successor_payload = payload;
                    }
                    Some((successor_ctx, successor_payload))
                } else {
                    // we don't found the right child node in the tree, which means that the
                    // successor might be out of range, so we return None
                    return None;
                }
            } else {
                // find successor among the ancestors of current node: we go up in the path
                // until we either found a node whose left child is the previous node in the
                // path, or we get to the root of the tree
                let mut candidate_successor_ctx = node_ctx.clone();
                let mut successor = None;
                while candidate_successor_ctx.parent.is_some() {
                    let (parent_ctx, parent_payload) = self
                        .fetch_ctx_and_payload_at(
                            candidate_successor_ctx.parent.as_ref().unwrap(),
                            epoch,
                        )
                        .await
                        .unwrap_or_else(|| {
                            panic!(
                                "Node context not found for parent of node {:?}",
                                candidate_successor_ctx.node_id
                            )
                        });
                    if parent_ctx
                        .iter_children()
                        .find_position(|child| {
                            child.is_some()
                                && child.unwrap().clone() == candidate_successor_ctx.node_id
                        })
                        .unwrap()
                        .0
                        == 0
                    {
                        // successor_ctx.node_id is left child of parent_ctx node, so parent_ctx is
                        // the successor
                        successor = Some((parent_ctx, parent_payload));
                        break;
                    } else {
                        candidate_successor_ctx = parent_ctx;
                    }
                }
                successor
            }
        }
    }

    fn get_predecessor(
        &self,
        node_ctx: &NodeContext<K>,
        epoch: Epoch,
    ) -> impl Future<Output = Option<(NodeContext<K>, V)>>
    where
        K: Clone + Debug + Eq + PartialEq,
    {
        async move {
            if node_ctx.left.is_some() {
                if let Some((left_child_ctx, left_child_payload)) =
                    fetch_existing_node_from_tree(self, node_ctx.left.as_ref().unwrap(), epoch)
                        .await
                {
                    // find predecessor in the subtree rooted in the left child: it is
                    // the rightmost node in such a subtree
                    let (mut predecessor_ctx, mut predecessor_payload) =
                        (left_child_ctx, left_child_payload);
                    while predecessor_ctx.right.is_some() {
                        let Some((ctx, payload)) = fetch_existing_node_from_tree(
                            self,
                            predecessor_ctx.right.as_ref().unwrap(),
                            epoch,
                        )
                        .await
                        else {
                            // we don't found the right child node in the tree, which means that the
                            // predecessor might be out of range, so we return None
                            return None;
                        };
                        predecessor_ctx = ctx;
                        predecessor_payload = payload;
                    }
                    Some((predecessor_ctx, predecessor_payload))
                } else {
                    // we don't found the left child node in the tree, which means that the
                    // predecessor might be out of range, so we return None
                    return None;
                }
            } else {
                // find predecessor among the ancestors of current node: we go up in the path
                // until we either found a node whose right child is the previous node in the
                // path, or we get to the root of the tree
                let mut candidate_predecessor_ctx = node_ctx.clone();
                let mut predecessor = None;
                while candidate_predecessor_ctx.parent.is_some() {
                    let (parent_ctx, parent_payload) = self
                        .fetch_ctx_and_payload_at(
                            candidate_predecessor_ctx.parent.as_ref().unwrap(),
                            epoch,
                        )
                        .await
                        .unwrap_or_else(|| {
                            panic!(
                                "Node context not found for parent of node {:?}",
                                candidate_predecessor_ctx.node_id
                            )
                        });
                    if parent_ctx
                        .iter_children()
                        .find_position(|child| {
                            child.is_some()
                                && child.unwrap().clone() == candidate_predecessor_ctx.node_id
                        })
                        .unwrap()
                        .0
                        == 1
                    {
                        // predecessor_ctx.node_id is right child of parent_ctx node, so parent_ctx is
                        // the predecessor
                        predecessor = Some((parent_ctx, parent_payload));
                        break;
                    } else {
                        candidate_predecessor_ctx = parent_ctx;
                    }
                }
                predecessor
            }
        }
    }
}

impl<K, V: Clone + Send + Sync + LagrangeNode> TreeFetcher<K, V> for WideLineage<K, V>
where
    K: Debug + Hash + Eq + Clone + Sync + Send,
{
    const IS_WIDE_LINEAGE: bool = true;

    async fn fetch_ctx_and_payload_at(&self, k: &K, epoch: Epoch) -> Option<(NodeContext<K>, V)> {
        self.ctx_and_payload_at(epoch, k)
    }
}

impl<
        V: NodePayload + Send + Sync + LagrangeNode,
        T: TreeTopology + MutableTree + 'static,
        S: TransactionalStorage
            + TreeStorage<T>
            + PayloadStorage<T::Key, V>
            + FromSettings<T::State>
            + 'static,
    > TreeFetcher<T::Key, V> for MerkleTreeKvDb<T, V, S>
{
    const IS_WIDE_LINEAGE: bool = false;

    async fn fetch_ctx_and_payload_at(
        &self,
        k: &T::Key,
        epoch: Epoch,
    ) -> Option<(NodeContext<T::Key>, V)> {
        self.try_fetch_with_context_at(k, epoch)
            .await
            .expect("Failed to fetch context")
    }
}

/// Fetch a key `k` from a tree, assuming that the key is in the
/// tree. Therefore, it handles differently the case when `k` is not found:
/// - If `T::WIDE_LINEAGE` is true, then `k` might not be found because the
///   node associated to key `k` is in the tree, but not in the lineage
/// - Otherwise, it panics because it's not expected to happen, as we are
///   assuming to call this method only on keys which are in the tree
async fn fetch_existing_node_from_tree<K, V: LagrangeNode, T: TreeFetcher<K, V>>(
    tree: &T,
    k: &K,
    epoch: Epoch,
) -> Option<(NodeContext<K>, V)>
where
    K: Clone + Debug + Eq + PartialEq,
{
    if T::IS_WIDE_LINEAGE {
        // we simply return the result, since in case of `WideLineage`
        // fetching might fail because the node was not in the lineage
        tree.fetch_ctx_and_payload_at(k, epoch).await
    } else {
        // Otherwise, we are fetching from an entire tree, so
        Some(
            tree.fetch_ctx_and_payload_at(k, epoch)
                .await
                .unwrap_or_else(|| panic!("Node context not found for node {:?}", k)),
        )
    }
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
    row_tree
        .get_successor(node_ctx, primary as Epoch)
        .await
        .and_then(|(successor_ctx, successor_payload)| {
            if successor_payload.value() != value {
                // the value of successor is different from `value`, so we don't return the
                // successor node
                None
            } else {
                Some(successor_ctx)
            }
        })
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
    row_tree
        .get_predecessor(node_ctx, primary as Epoch)
        .await
        .and_then(|(predecessor_ctx, predecessor_payload)| {
            if predecessor_payload.value() != value {
                // the value of successor is different from `value`, so we don't return the
                // successor node
                None
            } else {
                Some(predecessor_ctx)
            }
        })
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
        .await?
        .unwrap();
    let value = node_value.value();

    if is_min_query {
        // starting from the node with key `row_key`, we iterate over its successor nodes in the tree,
        // until we found a node that either has no successor or whose successor stores a value different
        // from the value `value` stored in the node with key `row_key`; the node found is the one to be
        // employed to generate the non-existence proof
        let mut successor_ctx =
            get_successor_node_with_same_value(row_tree, &node_ctx, value, primary).await;
        while successor_ctx.is_some() {
            node_ctx = successor_ctx.unwrap();
            successor_ctx =
                get_successor_node_with_same_value(row_tree, &node_ctx, value, primary).await;
        }
    } else {
        // starting from the node with key `row_key`, we iterate over its predecessor nodes in the tree,
        // until we found a node that either has no predecessor or whose predecessor stores a value different
        // from the value `value` stored in the node with key `row_key`; the node found is the one to be
        // employed to generate the non-existence proof
        let mut predecessor_ctx =
            get_predecessor_node_with_same_value(row_tree, &node_ctx, value, primary).await;
        while predecessor_ctx.is_some() {
            node_ctx = predecessor_ctx.unwrap();
            predecessor_ctx =
                get_predecessor_node_with_same_value(row_tree, &node_ctx, value, primary).await;
        }
    }

    Ok(Some(node_ctx.node_id))
}
pub async fn execute_row_query2(
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
pub async fn execute_row_query(
    pool: &DBPool,
    query: &str,
    params: &[U256],
) -> anyhow::Result<Vec<PsqlRow>> {
    let connection = pool.get().await.unwrap();
    let res = connection
        .query_raw(query, params)
        .await
        .context("while fetching current epoch")?;
    let rows: Vec<PsqlRow> = res.try_collect().await?;
    Ok(rows)
}

async fn get_node_info_from_ctx_and_payload<
    K: Debug + Clone + Eq + PartialEq,
    V: LagrangeNode,
    T: TreeFetcher<K, V>,
>(
    tree: &T,
    node_ctx: NodeContext<K>,
    node_payload: V,
    at: Epoch,
) -> (NodeInfo, Option<NodeInfo>, Option<NodeInfo>) {
    // this looks at the value of a child node (left and right), and fetches the grandchildren
    // information to be able to build their respective node info.
    let fetch_ni = async |k: Option<K>| -> (Option<NodeInfo>, Option<HashOutput>) {
        match k {
            None => (None, None),
            Some(child_k) => {
                let (child_ctx, child_payload) = tree
                    .fetch_ctx_and_payload_at(&child_k, at)
                    .await
                    .unwrap_or_else(|| panic!("key {:?} not found in the tree", child_k));
                // we need the grand child hashes for constructing the node info of the
                // children of the node in argument
                let child_left_hash = match child_ctx.left {
                    Some(left_left_k) => {
                        let (_, payload) = tree
                            .fetch_ctx_and_payload_at(&left_left_k, at)
                            .await
                            .unwrap_or_else(|| {
                                panic!("key {:?} not found in the tree", left_left_k)
                            });
                        Some(payload.hash())
                    }
                    None => None,
                };
                let child_right_hash = match child_ctx.right {
                    Some(left_right_k) => {
                        let (_, payload) = tree
                            .fetch_ctx_and_payload_at(&left_right_k, at)
                            .await
                            .unwrap_or_else(|| {
                                panic!("key {:?} not found in the tree", left_right_k)
                            });
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
    let (left_node, left_hash) = fetch_ni(node_ctx.left).await;
    let (right_node, right_hash) = fetch_ni(node_ctx.right).await;
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

pub async fn get_node_info<
    K: Debug + Clone + Eq + PartialEq,
    V: LagrangeNode,
    T: TreeFetcher<K, V>,
>(
    tree: &T,
    k: &K,
    at: Epoch,
) -> (NodeInfo, Option<NodeInfo>, Option<NodeInfo>) {
    let (node_ctx, node_payload) = tree
        .fetch_ctx_and_payload_at(k, at)
        .await
        .unwrap_or_else(|| panic!("key {:?} not found in the tree", k));
    get_node_info_from_ctx_and_payload(tree, node_ctx, node_payload, at).await
}
