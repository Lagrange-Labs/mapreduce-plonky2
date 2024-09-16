use std::{collections::HashSet, future::Future};

use alloy::{primitives::U256, rpc::types::Block};
use anyhow::Result;
use log::info;
use mp2_v1::indexing::{
    block::BlockPrimaryIndex,
    index::IndexNode,
    row::{RowPayload, RowTreeKey},
};
use parsil::{assembler::DynamicCircuitPis, ParsilSettings};
use ryhope::{storage::WideLineage, tree::NodeContext, Epoch, NodePayload};
use verifiable_db::query::aggregation::QueryBounds;

use crate::common::{
    cases::query::prove_non_existence_row,
    index_tree::MerkleIndexTree,
    proof_storage::{PlaceholderValues, ProofKey, ProofStorage, QueryID},
    rowtree::MerkleRowTree,
    table::{Table, TableColumns},
    TestContext,
};

use super::query::{prove_single_row, QueryCooking};

pub(crate) struct QueryPlanner<'a> {
    pub(crate) query: QueryCooking,
    pub(crate) pis: &'a DynamicCircuitPis,
    pub(crate) ctx: &'a mut TestContext,
    pub(crate) settings: &'a ParsilSettings<&'a Table>,
    // useful for non existence since we need to search in both trees the places to prove
    // the fact a given node doesn't exist
    pub(crate) table: &'a Table,
    pub(crate) columns: TableColumns,
}

pub trait TreeInfo<K, V> {
    fn is_row_tree(&self) -> bool;
    fn is_satisfying_query(&self, k: &K) -> bool;
    fn load_proof(
        &self,
        ctx: &TestContext,
        query_id: &QueryID,
        primary: BlockPrimaryIndex,
        key: &K,
        placeholder_values: PlaceholderValues,
    ) -> Result<Vec<u8>>;
    fn save_proof(
        &self,
        ctx: &mut TestContext,
        query_id: &QueryID,
        primary: BlockPrimaryIndex,
        key: &K,
        placeholder_values: PlaceholderValues,
        proof: Vec<u8>,
    ) -> Result<()>;

    async fn load_or_prove_embedded<'a>(
        &self,
        planner: &mut QueryPlanner<'a>,
        primary: BlockPrimaryIndex,
        k: &K,
        v: &V,
    ) -> Result<Option<Vec<u8>>>;

    fn fetch_ctx_and_payload_at(
        &self,
        epoch: Epoch,
        key: &K,
    ) -> impl Future<Output = Option<(NodeContext<K>, V)>> + Send;
}

impl TreeInfo<RowTreeKey, RowPayload<BlockPrimaryIndex>>
    for WideLineage<RowTreeKey, RowPayload<BlockPrimaryIndex>>
{
    fn is_row_tree(&self) -> bool {
        true
    }

    fn is_satisfying_query(&self, k: &RowTreeKey) -> bool {
        self.is_touched_key(k)
    }

    fn load_proof(
        &self,
        ctx: &TestContext,
        query_id: &QueryID,
        primary: BlockPrimaryIndex,
        key: &RowTreeKey,
        placeholder_values: PlaceholderValues,
    ) -> Result<Vec<u8>> {
        // TODO export that in single function
        let proof_key = ProofKey::QueryAggregateRow((
            query_id.clone(),
            placeholder_values,
            primary,
            key.clone(),
        ));
        ctx.storage.get_proof_exact(&proof_key)
    }

    fn save_proof(
        &self,
        ctx: &mut TestContext,
        query_id: &QueryID,
        primary: BlockPrimaryIndex,
        key: &RowTreeKey,
        placeholder_values: PlaceholderValues,
        proof: Vec<u8>,
    ) -> Result<()> {
        // TODO export that in single function
        let proof_key = ProofKey::QueryAggregateRow((
            query_id.clone(),
            placeholder_values,
            primary,
            key.clone(),
        ));
        ctx.storage.store_proof(proof_key, proof)
    }

    async fn load_or_prove_embedded<'a>(
        &self,
        planner: &mut QueryPlanner<'a>,
        primary: BlockPrimaryIndex,
        k: &RowTreeKey,
        v: &RowPayload<BlockPrimaryIndex>,
    ) -> Result<Option<Vec<u8>>> {
        // TODO export that in single function
        Ok(if self.is_satisfying_query(k) {
            let ctx = &mut planner.ctx;
            Some(
                prove_single_row(
                    ctx,
                    self,
                    &planner.columns,
                    primary,
                    &k,
                    &planner.pis,
                    &planner.query,
                )
                .await?,
            )
        } else {
            None
        })
    }

    fn fetch_ctx_and_payload_at(
        &self,
        epoch: Epoch,
        key: &RowTreeKey,
    ) -> impl Future<Output = Option<(NodeContext<RowTreeKey>, RowPayload<BlockPrimaryIndex>)>> + Send
    {
        async move { self.ctx_and_payload_at(epoch, key) }
    }
}

pub struct RowInfo<'a> {
    pub(crate) satisfiying_rows: HashSet<RowTreeKey>,
    pub(crate) tree: &'a MerkleRowTree,
}

impl<'a> RowInfo<'a> {
    pub fn no_satisfying_rows(tree: &'a MerkleRowTree) -> Self {
        Self {
            satisfiying_rows: Default::default(),
            tree,
        }
    }
}

impl<'b> TreeInfo<RowTreeKey, RowPayload<BlockPrimaryIndex>> for RowInfo<'b> {
    fn is_row_tree(&self) -> bool {
        true
    }

    fn is_satisfying_query(&self, k: &RowTreeKey) -> bool {
        self.satisfiying_rows.contains(k)
    }

    fn load_proof(
        &self,
        ctx: &TestContext,
        query_id: &QueryID,
        primary: BlockPrimaryIndex,
        key: &RowTreeKey,
        placeholder_values: PlaceholderValues,
    ) -> Result<Vec<u8>> {
        let proof_key = ProofKey::QueryAggregateRow((
            query_id.clone(),
            placeholder_values,
            primary,
            key.clone(),
        ));
        ctx.storage.get_proof_exact(&proof_key)
    }

    fn save_proof(
        &self,
        ctx: &mut TestContext,
        query_id: &QueryID,
        primary: BlockPrimaryIndex,
        key: &RowTreeKey,
        placeholder_values: PlaceholderValues,
        proof: Vec<u8>,
    ) -> Result<()> {
        let proof_key = ProofKey::QueryAggregateRow((
            query_id.clone(),
            placeholder_values,
            primary,
            key.clone(),
        ));
        ctx.storage.store_proof(proof_key, proof)
    }

    async fn load_or_prove_embedded<'a>(
        &self,
        planner: &mut QueryPlanner<'a>,
        primary: BlockPrimaryIndex,
        k: &RowTreeKey,
        _v: &RowPayload<BlockPrimaryIndex>,
    ) -> Result<Option<Vec<u8>>> {
        Ok(if self.is_satisfying_query(k) {
            let ctx = &mut planner.ctx;
            Some(
                prove_single_row(
                    ctx,
                    self,
                    &planner.columns,
                    primary,
                    &k,
                    &planner.pis,
                    &planner.query,
                )
                .await?,
            )
        } else {
            None
        })
    }

    fn fetch_ctx_and_payload_at(
        &self,
        epoch: Epoch,
        key: &RowTreeKey,
    ) -> impl Future<Output = Option<(NodeContext<RowTreeKey>, RowPayload<BlockPrimaryIndex>)>> + Send
    {
        async move { self.tree.try_fetch_with_context_at(key, epoch).await }
    }
}

impl TreeInfo<BlockPrimaryIndex, IndexNode<BlockPrimaryIndex>>
    for WideLineage<BlockPrimaryIndex, IndexNode<BlockPrimaryIndex>>
{
    fn is_row_tree(&self) -> bool {
        false
    }

    fn is_satisfying_query(&self, k: &BlockPrimaryIndex) -> bool {
        self.is_touched_key(k)
    }

    fn load_proof(
        &self,
        ctx: &TestContext,
        query_id: &QueryID,
        primary: BlockPrimaryIndex,
        key: &BlockPrimaryIndex,
        placeholder_values: PlaceholderValues,
    ) -> Result<Vec<u8>> {
        // TODO export that in single function - repetition
        info!("loading proof for {primary} -> {key:?}");
        let proof_key = ProofKey::QueryAggregateIndex((query_id.clone(), placeholder_values, *key));
        ctx.storage.get_proof_exact(&proof_key)
    }

    fn save_proof(
        &self,
        ctx: &mut TestContext,
        query_id: &QueryID,
        primary: BlockPrimaryIndex,
        key: &BlockPrimaryIndex,
        placeholder_values: PlaceholderValues,
        proof: Vec<u8>,
    ) -> Result<()> {
        // TODO export that in single function
        let proof_key = ProofKey::QueryAggregateIndex((query_id.clone(), placeholder_values, *key));
        ctx.storage.store_proof(proof_key, proof)
    }

    async fn load_or_prove_embedded<'a>(
        &self,
        planner: &mut QueryPlanner<'a>,
        primary: BlockPrimaryIndex,
        k: &BlockPrimaryIndex,
        v: &IndexNode<BlockPrimaryIndex>,
    ) -> Result<Option<Vec<u8>>> {
        load_or_prove_embedded_index(self, planner, primary, k, v).await
    }

    fn fetch_ctx_and_payload_at(
        &self,
        epoch: Epoch,
        key: &BlockPrimaryIndex,
    ) -> impl Future<Output = Option<(NodeContext<BlockPrimaryIndex>, IndexNode<BlockPrimaryIndex>)>>
           + Send {
        async move { self.ctx_and_payload_at(epoch, key) }
    }
}

pub struct IndexInfo<'a> {
    pub(crate) bounds: (BlockPrimaryIndex, BlockPrimaryIndex),
    pub(crate) tree: &'a MerkleIndexTree,
}

impl<'a> IndexInfo<'a> {
    pub fn non_satisfying_info(tree: &'a MerkleIndexTree) -> Self {
        Self {
            // so it never returns true to is satisfying query
            bounds: (BlockPrimaryIndex::MAX, BlockPrimaryIndex::MIN),
            tree,
        }
    }
}

impl<'b> TreeInfo<BlockPrimaryIndex, IndexNode<BlockPrimaryIndex>> for IndexInfo<'b> {
    fn is_row_tree(&self) -> bool {
        false
    }

    fn is_satisfying_query(&self, k: &BlockPrimaryIndex) -> bool {
        self.bounds.0 <= *k && *k <= self.bounds.1
    }

    fn load_proof(
        &self,
        ctx: &TestContext,
        query_id: &QueryID,
        primary: BlockPrimaryIndex,
        key: &BlockPrimaryIndex,
        placeholder_values: PlaceholderValues,
    ) -> Result<Vec<u8>> {
        //assert_eq!(primary, *key);
        info!("loading proof for {primary} -> {key:?}");
        let proof_key = ProofKey::QueryAggregateIndex((query_id.clone(), placeholder_values, *key));
        ctx.storage.get_proof_exact(&proof_key)
    }

    fn save_proof(
        &self,
        ctx: &mut TestContext,
        query_id: &QueryID,
        primary: BlockPrimaryIndex,
        key: &BlockPrimaryIndex,
        placeholder_values: PlaceholderValues,
        proof: Vec<u8>,
    ) -> Result<()> {
        //assert_eq!(primary, *key);
        let proof_key = ProofKey::QueryAggregateIndex((query_id.clone(), placeholder_values, *key));
        ctx.storage.store_proof(proof_key, proof)
    }

    async fn load_or_prove_embedded<'a>(
        &self,
        planner: &mut QueryPlanner<'a>,
        primary: BlockPrimaryIndex,
        k: &BlockPrimaryIndex,
        v: &IndexNode<BlockPrimaryIndex>,
    ) -> Result<Option<Vec<u8>>> {
        load_or_prove_embedded_index(self, planner, primary, k, v).await
    }

    fn fetch_ctx_and_payload_at(
        &self,
        epoch: Epoch,
        key: &BlockPrimaryIndex,
    ) -> impl Future<Output = Option<(NodeContext<BlockPrimaryIndex>, IndexNode<BlockPrimaryIndex>)>>
           + Send {
        async move { self.tree.try_fetch_with_context_at(key, epoch).await }
    }
}

async fn load_or_prove_embedded_index<
    'a,
    T: TreeInfo<BlockPrimaryIndex, IndexNode<BlockPrimaryIndex>>,
>(
    info: &T,
    planner: &mut QueryPlanner<'a>,
    primary: BlockPrimaryIndex,
    k: &BlockPrimaryIndex,
    v: &IndexNode<BlockPrimaryIndex>,
) -> Result<Option<Vec<u8>>> {
    //assert_eq!(primary, *k);
    info!("loading embedded proof for node {primary} -> {k:?}");
    Ok(if info.is_satisfying_query(k) {
        // load the proof of the row root for this query, if it is already proven;
        // otherwise, it means that there are no rows in the rows tree embedded in this
        // node that satisfies the query bounds on secondary index, so we need to
        // generate a non-existence proof for the row tree
        let row_root_proof_key = ProofKey::QueryAggregateRow((
            planner.query.query.clone(),
            planner.query.placeholders.placeholder_values(),
            k.clone(),
            v.row_tree_root_key.clone(),
        ));
        let proof = match planner.ctx.storage.get_proof_exact(&row_root_proof_key) {
            Ok(proof) => proof,
            Err(_) => {
                prove_non_existence_row(planner, *k).await?;
                info!("non existence proved for {primary} -> {k:?}");
                // fetch again the generated proof
                planner
                    .ctx
                    .storage
                    .get_proof_exact(&row_root_proof_key)
                    .expect(
                        format!(
                            "non-existence root proof not found for key {row_root_proof_key:?}"
                        )
                        .as_str(),
                    )
            }
        };
        Some(proof)
    } else {
        None
    })
}
