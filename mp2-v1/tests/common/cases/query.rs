use plonky2::{
    field::types::{Field, PrimeField64},
    hash::hash_types::HashOut,
    plonk::config::GenericHashOut,
};
use std::{
    collections::{HashMap, HashSet},
    iter::once,
    process::Child,
};

use crate::common::{
    cases::indexing::BLOCK_COLUMN_NAME,
    index_tree::{IndexStorage, MerkleIndexTree},
    proof_storage::ProofKey,
    rowtree::{MerkleRowTree, RowStorage},
    table::TableColumns,
};

use super::super::{context::TestContext, proof_storage::ProofStorage, table::Table};
use alloy::{primitives::U256, rpc::types::Block};
use anyhow::{Context, Result};
use futures::{future::BoxFuture, io::empty, stream, FutureExt, StreamExt};
use itertools::Itertools;
use log::{debug, info, warn};
use mp2_common::{
    array::ToField,
    poseidon::empty_poseidon_hash,
    proof::{deserialize_proof, ProofWithVK},
    types::HashOutput,
    C, D, F,
};
use mp2_v1::{
    indexing::{
        self,
        block::{BlockPrimaryIndex, BlockTree},
        cell::MerkleCell,
        index::IndexNode,
        row::{Row, RowPayload, RowTree, RowTreeKey},
    },
    values_extraction::identifier_block_column,
};
use parsil::{
    circuit::CircuitPis, parse_and_validate, symbols::ContextProvider, ParsilSettings,
    PlaceholderSettings, DEFAULT_MAX_BLOCK_PLACEHOLDER, DEFAULT_MIN_BLOCK_PLACEHOLDER,
};
use ryhope::{
    storage::{
        pgsql::ToFromBytea,
        updatetree::{Next, UpdateTree},
        EpochKvStorage, FromSettings, PayloadStorage, RoEpochKvStorage, TransactionalStorage,
        TreeStorage, TreeTransactionalStorage,
    },
    tree::{MutableTree, NodeContext, TreeTopology},
    Epoch, MerkleTreeKvDb, NodePayload,
};
use sqlparser::ast::Query;
use tokio_postgres::Row as PsqlRow;
use verifiable_db::{
    ivc::PublicInputs as IndexingPIS,
    query::{
        self,
        aggregation::{ChildPosition, NodeInfo, QueryBoundSource, QueryBounds, SubProof},
        computational_hash_ids::{ColumnIDs, Identifiers},
        universal_circuit::universal_circuit_inputs::{
            ColumnCell, PlaceholderId, Placeholders, RowCells,
        },
    },
    revelation::PublicInputs,
};

pub const MAX_NUM_RESULT_OPS: usize = 20;
pub const MAX_NUM_RESULTS: usize = 10;
pub const MAX_NUM_OUTPUTS: usize = 3;
pub const MAX_NUM_ITEMS_PER_OUTPUT: usize = 5;
pub const MAX_NUM_PLACEHOLDERS: usize = 15;
pub const MAX_NUM_COLUMNS: usize = 20;
pub const MAX_NUM_PREDICATE_OPS: usize = 20;

pub type GlobalCircuitInput = verifiable_db::api::QueryCircuitInput<
    MAX_NUM_COLUMNS,
    MAX_NUM_PREDICATE_OPS,
    MAX_NUM_RESULT_OPS,
    MAX_NUM_OUTPUTS,
    MAX_NUM_ITEMS_PER_OUTPUT,
    MAX_NUM_PLACEHOLDERS,
>;

pub type QueryCircuitInput = verifiable_db::query::api::CircuitInput<
    MAX_NUM_COLUMNS,
    MAX_NUM_PREDICATE_OPS,
    MAX_NUM_RESULT_OPS,
    MAX_NUM_ITEMS_PER_OUTPUT,
>;

pub type RevelationCircuitInput = verifiable_db::revelation::api::CircuitInput<
    MAX_NUM_OUTPUTS,
    MAX_NUM_ITEMS_PER_OUTPUT,
    MAX_NUM_PLACEHOLDERS,
    { QueryCircuitInput::num_placeholders_ids() },
>;

pub type RevelationPublicInputs<'a> =
    PublicInputs<'a, F, MAX_NUM_OUTPUTS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_PLACEHOLDERS>;

pub enum TableType {
    Mapping,
    Single,
}

pub async fn test_query(ctx: &mut TestContext, table: Table, t: TableType) -> Result<()> {
    match t {
        TableType::Mapping => query_mapping(ctx, &table).await?,
        _ => unimplemented!("yet"),
    }
    Ok(())
}
/// Run a test query on the mapping table such as created during the indexing phase
async fn query_mapping(ctx: &mut TestContext, table: &Table) -> Result<()> {
    let settings = ParsilSettings {
        context: table,
        placeholders: PlaceholderSettings::with_freestanding(2),
    };
    let query_info = cook_query(table).await?;
    info!("QUERY on the testcase: {}", query_info.query);
    let mut parsed = parse_and_validate(&query_info.query, &settings)?;
    println!("QUERY table columns -> {:?}", table.columns.to_zkcolumns());
    info!(
        "BOUNDS found on query: min {}, max {} - table.genesis_block {}",
        query_info.min_block, query_info.max_block, table.genesis_block
    );

    // the query to use to actually get the outputs expected
    let exec_query = parsil::executor::generate_query_execution(&mut parsed, &settings)?;
    let res = table
        .execute_row_query(
            &exec_query.query.to_string(),
            query_info.min_block, // - table.genesis_block as BlockPrimaryIndex + 1,
            query_info.max_block, //- table.genesis_block as BlockPrimaryIndex + 1,
        )
        .await?;
    info!(
        "Found {} results from query {}",
        res.len(),
        exec_query.query.to_string()
    );
    print_vec_sql_rows(&res, SqlType::Numeric);
    // the query to use to fetch all the rows keys involved in the result tree.
    let pis = parsil::circuit::assemble(&parsed, &settings, &query_info.placeholders)?;
    prove_query(ctx, table, query_info, parsed, pis, &settings, res)
        .await
        .expect("unable to run universal query proof");
    Ok(())
}

/// Execute a query to know all the touched rows, and then call the universal circuit on all rows
async fn prove_query(
    ctx: &mut TestContext,
    table: &Table,
    query: QueryCooking,
    mut parsed: Query,
    pis: CircuitPis,
    settings: &ParsilSettings<&Table>,
    res: Vec<PsqlRow>,
) -> Result<()> {
    let rows_query = parsil::executor::generate_query_keys(&mut parsed, settings)?;
    let all_touched_rows = table
        .execute_row_query(&rows_query.to_string(), query.min_block, query.max_block)
        .await?;
    // group the rows per block number
    let touched_rows = all_touched_rows
        .into_iter()
        .map(|r| {
            let row_key = r
                .get::<_, Option<Vec<u8>>>(0)
                .map(RowTreeKey::from_bytea)
                .context("unable to parse row key tree")
                .expect("");
            let block: Epoch = r.get::<_, i64>(1);
            (block as BlockPrimaryIndex, row_key)
        })
        .fold(
            HashMap::<BlockPrimaryIndex, HashSet<RowTreeKey>>::new(),
            |mut acc, (block, row_key)| {
                acc.entry(block).or_default().insert(row_key);
                acc
            },
        );
    info!(
        "Found {} ROW KEYS to process during proving time -> {:?}",
        touched_rows.len(),
        touched_rows.keys(),
    );

    // prove the whole tree for each of the involved rows for each block
    for (primary_value, row_keys) in &touched_rows {
        let all_paths = stream::iter(row_keys)
            .then(|row_key| async {
                // would be nice to make it work directly with async returning impl but seems
                // difficult
                table
                    .row
                    // since the epoch starts at genesis we can directly give the block number !
                    .lineage_at(row_key, *primary_value as Epoch)
                    .await
                    .expect("node doesn't have a lineage?")
                    .into_full_path()
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
            .await;
        let proving_tree = UpdateTree::from_paths(all_paths, *primary_value as Epoch);
        let planner = QueryPlanner {
            ctx,
            genesis: table.genesis_block,
            query: query.clone(),
            pis: &pis,
            tree: &table.row,
            columns: table.columns.clone(),
        };
        let info = RowInfo {
            satisfiying_rows: row_keys.clone(),
        };
        prove_query_on_tree(planner, info, proving_tree, *primary_value).await?;
    }
    // do the same for the single index tree now
    let current_epoch = table.index.current_epoch();
    let all_paths = stream::iter(touched_rows.keys())
        .then(|primary| async {
            // NOTE : it is important to fetch the data at fixed epoch ! and this key fetched can be
            // different
            table
                .index
                .lineage_at(primary, current_epoch)
                .await
                .expect("index node doesn't have lineage?")
                .into_full_path()
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
        .await;
    let proving_tree = UpdateTree::from_paths(all_paths, current_epoch);
    let planner = QueryPlanner {
        ctx,
        query: query.clone(),
        genesis: table.genesis_block,
        pis: &pis,
        tree: &table.index,
        columns: table.columns.clone(),
    };
    let info = IndexInfo {
        bounds: pis.bounds.clone(),
    };
    prove_query_on_tree(
        planner,
        info,
        proving_tree,
        current_epoch as BlockPrimaryIndex,
    )
    .await?;
    let proof = prove_revelation(ctx, table, &query, &pis, current_epoch).await?;
    info!("Revelation proof done! Checking public inputs...");
    check_final_outputs(
        proof,
        ctx,
        table,
        &query,
        &pis,
        current_epoch,
        touched_rows.len(),
        res,
    )?;
    info!("Revelation done!");
    Ok(())
}

async fn prove_revelation(
    ctx: &TestContext,
    table: &Table,
    query: &QueryCooking,
    pis: &CircuitPis,
    tree_epoch: Epoch,
) -> Result<Vec<u8>> {
    // load the query proof, which is at the root of the tree
    let query_proof = {
        let root_key = table.index.root_at(tree_epoch).await.unwrap();
        let proof_key = ProofKey::QueryAggregateIndex(root_key);
        ctx.storage.get_proof_exact(&proof_key)?
    };
    // load the preprocessing proof at the same epoch
    let indexing_proof = {
        let pk = ProofKey::IVC(tree_epoch as BlockPrimaryIndex);
        ctx.storage.get_proof_exact(&pk)?
    };
    let pis_hash = QueryCircuitInput::ids_for_placeholder_hash(
        &pis.predication_operations,
        &pis.result,
        &query.placeholders,
        &pis.bounds,
    )?;
    let input = RevelationCircuitInput::new_revelation_no_results_tree(
        query_proof,
        indexing_proof,
        &pis.bounds,
        &query.placeholders,
        pis_hash,
    )?;
    let proof = ctx.run_query_proof(GlobalCircuitInput::Revelation(input))?;
    Ok(proof)
}

fn check_final_outputs(
    revelation_proof: Vec<u8>,
    ctx: &TestContext,
    table: &Table,
    query: &QueryCooking,
    pis: &CircuitPis,
    tree_epoch: Epoch,
    num_touched_rows: usize,
    res: Vec<PsqlRow>,
) -> Result<()> {
    // fetch indexing proof, whose public inputs are needed to check correctness of revelation proof outputs
    let indexing_proof = {
        let pk = ProofKey::IVC(tree_epoch as BlockPrimaryIndex);
        ctx.storage.get_proof_exact(&pk)?
    };
    let deserialized_indexing_proof = ProofWithVK::deserialize(&indexing_proof)?;
    let indexing_pis = IndexingPIS::from_slice(&deserialized_indexing_proof.proof().public_inputs);

    let deserialized_proof = deserialize_proof::<F, C, D>(&revelation_proof)?;
    let revelation_pis = RevelationPublicInputs::from_slice(&deserialized_proof.public_inputs);
    // check original blockchain hash. ToDo: access it from Anvil
    assert_eq!(
        indexing_pis.block_hash_fields(),
        revelation_pis.original_block_hash(),
    );
    // check computational hash
    let metadata_hash = HashOutput::try_from(
        HashOut::<F>::from_vec(indexing_pis.metadata_hash().to_vec()).to_bytes(),
    )?;
    let column_ids = ColumnIDs::new(
        table.columns.primary.identifier,
        table.columns.secondary.identifier,
        table
            .columns
            .non_indexed_columns()
            .into_iter()
            .map(|column| column.identifier)
            .collect_vec(),
    );
    let expected_computational_hash = Identifiers::computational_hash(
        &column_ids,
        &pis.predication_operations,
        &pis.result,
        &metadata_hash,
        Some(QueryBoundSource::Constant(query.example_row.value)), //ToDo: need to get this from parsil
        Some(QueryBoundSource::Constant(query.example_row.value)),
    )?;
    assert_eq!(
        HashOutput::try_from(revelation_pis.computational_hash().to_bytes())?,
        expected_computational_hash,
    );
    // check num placeholders
    let expected_num_placeholders = query.placeholders.len();
    assert_eq!(
        expected_num_placeholders as u64,
        revelation_pis.num_placeholders().to_canonical_u64(),
    );
    // check placeholder values
    let expected_placeholder_values = query.placeholders.placeholder_values();
    assert_eq!(
        expected_placeholder_values,
        revelation_pis.placeholder_values()[..expected_num_placeholders], // consider only the valid placeholders
    );
    // check entry count
    assert_eq!(
        num_touched_rows as u64,
        revelation_pis.entry_count().to_canonical_u64(),
    );
    // check there were no overflow errors
    assert!(!revelation_pis.overflow_flag(),);
    // check number of results
    assert_eq!(
        res.len() as u64,
        revelation_pis.num_results().to_canonical_u64(),
    );
    // check results
    res.into_iter()
        .zip(revelation_pis.result_values().into_iter())
        .for_each(|(expected_res, res)| {
            (0..expected_res.len()).for_each(|i| {
                let SqlReturn::Numeric(expected_res) = SqlType::Numeric.extract(&expected_res, i);
                assert_eq!(
                    U256::from_str_radix(&expected_res.to_string(), 10).unwrap(),
                    res[i],
                );
            })
        });

    Ok(())
}

/// Generic function as to how to handle the aggregation. It handles both aggregation in the row
/// tree as well as in the index tree the same way. The TreeInfo trait is just here to bring some
/// context, so savign and loading the proof at the right location depending if it's a row or index
/// tree
/// clippy doesn't see that it can not be done
#[allow(clippy::needless_lifetimes)]
async fn prove_query_on_tree<'a, T, V, S, I>(
    mut planner: QueryPlanner<'a, T, V, S>,
    info: I,
    update: UpdateTree<<T as TreeTopology>::Key>,
    primary: BlockPrimaryIndex,
) -> Result<Vec<u8>>
where
    I: TreeInfo<T, V, S>,
    <T as TreeTopology>::Key: std::hash::Hash,
    T: TreeTopology + MutableTree,
    // NOTICE the ToValue here to get the value associated to a node
    V: NodePayload + Send + Sync + LagrangeNode,
    S: TransactionalStorage
        + TreeStorage<T>
        + PayloadStorage<T::Key, V>
        + FromSettings<T::State>
        + Send
        + Sync,
{
    let mut workplan = update.into_workplan();
    let mut proven_nodes = HashSet::new();
    let fetch_only_proven_child = |nctx: NodeContext<<T as TreeTopology>::Key>,
                                   cctx: &TestContext,
                                   proven: &HashSet<<T as TreeTopology>::Key>|
     -> (ChildPosition, Vec<u8>) {
        let (child_key, pos) = match (nctx.left, nctx.right) {
            (Some(left), Some(right)) => {
                assert!(
                    proven.contains(&left) ^ proven.contains(&right),
                    "only one child should be already proven, not both"
                );
                if proven.contains(&left) {
                    (left, ChildPosition::Left)
                } else {
                    (right, ChildPosition::Right)
                }
            }
            (Some(left), None) if proven.contains(&left) => (left, ChildPosition::Left),
            (None, Some(right)) if proven.contains(&right) => (right, ChildPosition::Right),
            _ => panic!("stg's wrong in the tree"),
        };
        let child_proof = info
            .load_proof(cctx, primary, &child_key)
            .expect("key should already been proven");
        (pos, child_proof)
    };
    while let Some(Next::Ready(wk)) = workplan.next() {
        let k = wk.k.clone();
        let (node_ctx, node_payload) = planner
            .tree
            // since epoch starts at genesis now, we can directly give the value of the block
            // number as epoch number
            .fetch_with_context_at(&k, primary as Epoch)
            .await;
        let is_satisfying_query = info.is_satisfying_query(&k);
        let embedded_proof = info
            .load_or_prove_embedded(&mut planner, primary, &k, &node_payload)
            .await;
        if node_ctx.is_leaf() && info.is_row_tree() {
            // NOTE: if it is a leaf of the row tree, then there is no need to prove anything,
            // since we're not "aggregating" any from below. So in this test, we just copy the
            // proof to the expected aggregation location and move on.
            // For the index tree however, we need to always generate an aggregate proof
            // unwrap is safe since we are a leaf and therefore there is an embedded proof since we
            // are guaranteed the row is satisfying the query
            info.save_proof(&mut planner.ctx, primary, &k, embedded_proof.unwrap())?;
            proven_nodes.insert(k);
            workplan.done(&wk)?;
            continue;
        }

        // In the case we haven't proven anything under this node, it's the single path case
        // It is sufficient to check if this node is one of the leaves we in this update tree.Note
        // it is not the same meaning as a "leaf of a tree", here it just means is it the first
        // node in the merkle path.
        let input = if wk.is_path_end {
            info!("node {primary}:{k:?} is at path end");
            assert!(
                info.is_satisfying_query(&k),
                "first node in merkle path should always be a valid query one"
            );
            let (node_info, left_info, right_info) =
            // we can use primary as epoch now that tree stores epoch from genesis
                get_node_info(&planner.tree, &k, primary as Epoch).await;
            QueryCircuitInput::new_single_path(
                SubProof::new_embedded_tree_proof(embedded_proof.unwrap())?,
                left_info,
                right_info,
                node_info,
                info.is_row_tree(),
                &planner.pis.bounds,
            )
            .expect("can't create leaf input")
        } else {
            // here we are guaranteed there is a node below that we have already proven
            // It can not be a single path with the embedded tree only since that falls into the
            // previous category ("is_path_end" == true) since update plan starts by the "leaves"
            // of all the paths it has been given.
            // So it means There is at least one child of this node that we have proven before.
            // If this node is satisfying query, then we use One/TwoProvenChildNode,
            // If this node is not in the query touched rows, we use a SinglePath with proven child tree.
            //
            if !is_satisfying_query {
                let (child_pos, child_proof) =
                    fetch_only_proven_child(node_ctx, planner.ctx, &proven_nodes);
                let (node_info, left_info, right_info) = get_node_info(
                    planner.tree,
                    &k,
                    // we can use primary as epoch since storage starts epoch at genesis
                    primary as Epoch,
                )
                .await;
                // we look which child is the one to load from storage, the one we already proved
                QueryCircuitInput::new_single_path(
                    SubProof::new_child_proof(child_proof, child_pos)?,
                    left_info,
                    right_info,
                    node_info,
                    info.is_row_tree(),
                    &planner.pis.bounds,
                )
                .expect("can't create leaf input")
            } else {
                // this case is easy, since all that's left is partial or full where both
                // child(ren) and current node belong to query
                if node_ctx.left.is_some() && node_ctx.right.is_some() {
                    // full node case
                    let left_proof =
                        info.load_proof(planner.ctx, primary, node_ctx.left.as_ref().unwrap())?;
                    let right_proof =
                        info.load_proof(planner.ctx, primary, node_ctx.right.as_ref().unwrap())?;
                    QueryCircuitInput::new_full_node(
                        left_proof,
                        right_proof,
                        embedded_proof.expect("should be a embedded_proof here"),
                        info.is_row_tree(),
                        &planner.pis.bounds,
                    )
                    .expect("can't create full node circuit input")
                } else {
                    // partial case
                    let (child_pos, child_proof) =
                        fetch_only_proven_child(node_ctx, planner.ctx, &proven_nodes);
                    let (_, left_info, right_info) =
                        get_node_info(planner.tree, &k, primary as Epoch).await;
                    let unproven = match child_pos {
                        ChildPosition::Left => right_info,
                        ChildPosition::Right => left_info,
                    };
                    QueryCircuitInput::new_partial_node(
                        child_proof,
                        embedded_proof.expect("should be an embedded_proof here too"),
                        unproven,
                        child_pos,
                        info.is_row_tree(),
                        &planner.pis.bounds,
                    )
                    .expect("can't build new partial node input")
                }
            }
        };
        info!("AGGREGATE query proof RUNNING for {primary} -> {k:?} ");
        debug!(
            "node info for {primary}, {k:?}: {:?}",
            get_node_info(&planner.tree, &k, primary as Epoch).await
        );
        //debug!("input for {primary}, {k:?}: {:?}", input);
        let proof = planner
            .ctx
            .run_query_proof(GlobalCircuitInput::Query(input))?;
        info.save_proof(planner.ctx, primary, &k, proof)?;
        info!("Universal query proof DONE for {primary} -> {k:?} ");
        workplan.done(&wk)?;
        proven_nodes.insert(k);
    }
    Ok(vec![])
}

struct QueryPlanner<'a, T, V, S>
where
    T: TreeTopology + MutableTree,
    // NOTICE the ToValue here to get the value associated to a node
    V: NodePayload + Send + Sync + LagrangeNode,
    S: TransactionalStorage
        + TreeStorage<T>
        + PayloadStorage<T::Key, V>
        + FromSettings<T::State>
        + Send
        + Sync,
{
    query: QueryCooking,
    genesis: BlockPrimaryIndex,
    pis: &'a parsil::circuit::CircuitPis,
    ctx: &'a mut TestContext,
    tree: &'a MerkleTreeKvDb<T, V, S>,
    columns: TableColumns,
}

trait TreeInfo<T, V, S>
where
    T: TreeTopology + MutableTree,
    <T as TreeTopology>::Key: std::hash::Hash,
    // NOTICE the ToValue here to get the value associated to a node
    V: NodePayload + Send + Sync + LagrangeNode,
    S: TransactionalStorage
        + TreeStorage<T>
        + PayloadStorage<T::Key, V>
        + FromSettings<T::State>
        + Send
        + Sync,
{
    fn is_row_tree(&self) -> bool;
    fn is_satisfying_query(&self, k: &<T as TreeTopology>::Key) -> bool;
    fn load_proof(
        &self,
        ctx: &TestContext,
        primary: BlockPrimaryIndex,
        key: &<T as TreeTopology>::Key,
    ) -> Result<Vec<u8>>;
    fn save_proof(
        &self,
        ctx: &mut TestContext,
        primary: BlockPrimaryIndex,
        key: &<T as TreeTopology>::Key,
        proof: Vec<u8>,
    ) -> Result<()>;
    async fn load_or_prove_embedded<'a>(
        &self,
        planner: &mut QueryPlanner<'a, T, V, S>,
        primary: BlockPrimaryIndex,
        k: &<T as TreeTopology>::Key,
        v: &V,
    ) -> Option<Vec<u8>>;
}

struct IndexInfo {
    bounds: QueryBounds,
}

impl TreeInfo<BlockTree, IndexNode<BlockPrimaryIndex>, IndexStorage> for IndexInfo {
    fn is_row_tree(&self) -> bool {
        false
    }

    fn is_satisfying_query(&self, k: &BlockPrimaryIndex) -> bool {
        let primary = U256::from(*k);
        self.bounds.is_primary_in_range(&primary)
    }

    fn load_proof(
        &self,
        ctx: &TestContext,
        primary: BlockPrimaryIndex,
        key: &BlockPrimaryIndex,
    ) -> Result<Vec<u8>> {
        //assert_eq!(primary, *key);
        let proof_key = ProofKey::QueryAggregateIndex(*key);
        ctx.storage.get_proof_exact(&proof_key)
    }

    fn save_proof(
        &self,
        ctx: &mut TestContext,
        primary: BlockPrimaryIndex,
        key: &BlockPrimaryIndex,
        proof: Vec<u8>,
    ) -> Result<()> {
        //assert_eq!(primary, *key);
        let proof_key = ProofKey::QueryAggregateIndex(*key);
        ctx.storage.store_proof(proof_key, proof)
    }

    async fn load_or_prove_embedded<'a>(
        &self,
        planner: &mut QueryPlanner<'a, BlockTree, IndexNode<BlockPrimaryIndex>, IndexStorage>,
        primary: BlockPrimaryIndex,
        k: &BlockPrimaryIndex,
        v: &IndexNode<BlockPrimaryIndex>,
    ) -> Option<Vec<u8>> {
        //assert_eq!(primary, *k);
        if self.is_satisfying_query(k) {
            // load the proof of the row root for this query
            // We assume it is already proven, otherwise, there is a flaw in the logic
            let row_root_proof_key =
                ProofKey::QueryAggregateRow((k.clone(), v.row_tree_root_key.clone()));
            let proof = planner
                .ctx
                .storage
                .get_proof_exact(&row_root_proof_key)
                .expect("row root proof for query should already have been proven");
            Some(proof)
        } else {
            None
        }
    }
}

struct RowInfo {
    satisfiying_rows: HashSet<RowTreeKey>,
}

impl TreeInfo<RowTree, RowPayload<BlockPrimaryIndex>, RowStorage> for RowInfo {
    fn is_row_tree(&self) -> bool {
        true
    }

    fn is_satisfying_query(&self, k: &RowTreeKey) -> bool {
        self.satisfiying_rows.contains(k)
    }

    fn load_proof(
        &self,
        ctx: &TestContext,
        primary: BlockPrimaryIndex,
        key: &RowTreeKey,
    ) -> Result<Vec<u8>> {
        let proof_key = ProofKey::QueryAggregateRow((primary, key.clone()));
        ctx.storage.get_proof_exact(&proof_key)
    }

    fn save_proof(
        &self,
        ctx: &mut TestContext,
        primary: BlockPrimaryIndex,
        key: &RowTreeKey,
        proof: Vec<u8>,
    ) -> Result<()> {
        let proof_key = ProofKey::QueryAggregateRow((primary, key.clone()));
        ctx.storage.store_proof(proof_key, proof)
    }

    async fn load_or_prove_embedded<'a>(
        &self,
        planner: &mut QueryPlanner<'a, RowTree, RowPayload<BlockPrimaryIndex>, RowStorage>,
        primary: BlockPrimaryIndex,
        k: &RowTreeKey,
        _v: &RowPayload<BlockPrimaryIndex>,
    ) -> Option<Vec<u8>> {
        let ctx = &mut planner.ctx;
        if self.is_satisfying_query(k) {
            Some(
                prove_single_row(
                    ctx,
                    &planner.tree,
                    &planner.columns,
                    primary,
                    &k,
                    &planner.pis,
                    &planner.query,
                )
                .await
                .unwrap(),
            )
        } else {
            None
        }
    }
}

// TODO: make it recursive with async - tentative in `fetch_child_info` but  it doesn't work,
// recursion with async is weird.
async fn get_node_info<T, V, S>(
    tree: &MerkleTreeKvDb<T, V, S>,
    k: &T::Key,
    at: Epoch,
) -> (NodeInfo, Option<NodeInfo>, Option<NodeInfo>)
where
    T: TreeTopology + MutableTree,
    // NOTICE the ToValue here to get the value associated to a node
    V: NodePayload + Send + Sync + LagrangeNode,
    S: TransactionalStorage
        + TreeStorage<T>
        + PayloadStorage<T::Key, V>
        + FromSettings<T::State>
        + Send
        + Sync,
{
    // look at the left child first then right child, then build the node info
    let (ctx, node_payload) = tree.fetch_with_context_at(k, at).await;
    // this looks at the value of a child node (left and right), and fetches the grand child
    // information to be able to build their respective node info.
    let fetch_ni = async |k: Option<T::Key>| -> (Option<NodeInfo>, Option<HashOutput>) {
        match k {
            None => (None, None),
            Some(child_k) => {
                let (child_ctx, child_payload) = tree.fetch_with_context_at(&child_k, at).await;
                // we need the grand child hashes for constructing the node info of the
                // children of the node in argument
                let child_left_hash = match child_ctx.left {
                    Some(left_left_k) => Some(tree.fetch_at(&left_left_k, at).await.hash()),
                    None => None,
                };
                let child_right_hash = match child_ctx.right {
                    Some(left_right_k) => Some(tree.fetch_at(&left_right_k, at).await.hash()),
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

async fn prove_single_row(
    ctx: &mut TestContext,
    tree: &MerkleRowTree,
    columns: &TableColumns,
    primary: BlockPrimaryIndex,
    row_key: &RowTreeKey,
    pis: &CircuitPis,
    query: &QueryCooking,
) -> Result<Vec<u8>> {
    // 1. Get the all the cells including primary and secondary index
    // Note we can use the primary as epoch since now epoch == primary in the storage
    let (row_ctx, row_payload) = tree.fetch_with_context_at(row_key, primary as Epoch).await;

    // API is gonna change on this but right now, we have to sort all the "rest" cells by index
    // in the tree, and put the primary one and secondary one in front
    let rest_cells = columns
        .non_indexed_columns()
        .iter()
        .map(|tc| tc.identifier)
        .filter_map(|id| {
            row_payload
                .cells
                .find_by_column(id)
                .map(|info| ColumnCell::new(id, info.value))
        })
        .collect::<Vec<_>>();

    let secondary_cell = ColumnCell::new(
        row_payload.secondary_index_column,
        row_payload.secondary_index_value(),
    );
    let primary_cell = ColumnCell::new(identifier_block_column(), U256::from(primary));
    let row = RowCells::new(primary_cell, secondary_cell, rest_cells);
    // 2. create input
    let input = QueryCircuitInput::new_universal_circuit(
        &row,
        &pis.predication_operations,
        &pis.result,
        &query.placeholders,
        row_ctx.is_leaf(),
        &pis.bounds,
    )
    .expect("unable to create universal query circuit inputs");
    // 3. run proof if not ran already
    let proof_key = ProofKey::QueryUniversal((primary, row_key.clone()));
    let proof = {
        info!("Universal query proof RUNNING for {primary} -> {row_key:?} ");
        let proof = ctx
            .run_query_proof(GlobalCircuitInput::Query(input))
            .expect("unable to generate universal proof for {epoch} -> {row_key:?}");
        info!("Universal query proof DONE for {primary} -> {row_key:?} ");
        ctx.storage.store_proof(proof_key, proof.clone())?;
        proof
    };
    Ok(proof)
}

#[derive(Clone, Debug)]
struct QueryCooking {
    query: String,
    placeholders: Placeholders,
    min_block: BlockPrimaryIndex,
    max_block: BlockPrimaryIndex,
    // At the moment it returns the row key selected and the epochs to run the circuit on
    // This will get removed once we can serach through JSON in PSQL directly.
    example_row: RowTreeKey,
    epochs: Vec<Epoch>,
}

// cook up a SQL query on the secondary index. For that we just iterate on mapping keys and
// take the one that exist for most blocks
async fn cook_query(table: &Table) -> Result<QueryCooking> {
    let mut all_table = HashMap::new();
    let max = table.row.current_epoch();
    let min = table.row.initial_epoch() + 1;
    for block in (min..=max).rev() {
        println!("Querying for block {block}");
        let rows = collect_all_at(&table.row, block).await?;
        debug!(
            "Collecting {} rows at epoch {} (rows_keys {:?})",
            rows.len(),
            block,
            rows.iter().map(|r| r.k.value).collect::<Vec<_>>()
        );
        for row in rows {
            let blocks = all_table.entry(row.k.clone()).or_insert(Vec::new());
            blocks.push(block);
        }
    }
    // sort the epochs
    let all_table: HashMap<_, _> = all_table
        .into_iter()
        .map(|(k, mut epochs)| {
            epochs.sort_unstable();
            (k, epochs)
        })
        .collect();
    // find the longest running row
    let (longest_key, epochs) = all_table
        .iter()
        .max_by_key(|(k, epochs)| {
            // simplification here to start at first epoch where this row was. Otherwise need to do
            // longest consecutive sequence etc...
            let (l, _start) = find_longest_consecutive_sequence(epochs.to_vec());
            debug!("finding sequence of {l} blocks for key {k:?} (epochs {epochs:?}");
            l
        })
        .unwrap_or_else(|| {
            panic!(
                "unable to find longest row? -> length all _table {}, max {}",
                all_table.len(),
                max
            )
        });
    let key_value = hex::encode(longest_key.value.to_be_bytes_trimmed_vec());
    info!(
        "Longest sequence is for key {longest_key:?} -> sequence of {:?} (sequence:  {:?}), hex -> {}",
        find_longest_consecutive_sequence(epochs.clone()),
        epochs,
        key_value
    );
    // now we can fetch the key that we want
    let key_column = table.columns.secondary.name.clone();
    // Assuming this is mapping with only two columns !
    let value_column = table.columns.rest[0].name.clone();
    let table_name = table.row_table_name();
    // we set the block bounds
    let (longest_sequence, starting) = find_longest_consecutive_sequence(epochs.to_vec());
    // TODO: careful about off by one error. -1 because tree epoch starts at 1
    let min_block = starting as BlockPrimaryIndex;
    let max_block = min_block + longest_sequence;
    // primary_min_placeholder = ".."
    // primary_max_placeholder = ".."
    // Address == $3 --> placeholders.hashmap empty, put in query bounds secondary_min = secondary_max = "$3""
    // adddress IN ($3,$4,$5) -> min "$3" max "$5", put in query bounds
    // secondary_min = $3, and secondary_max = "$5", placeholders.put(generic, "$4")
    // placeholders.generic(("generic", $3)),(generic,$4), (generic,$5))
    // WHERE price > $3 AND price < $4 <--
    // placeholders _values = [min_block,max_block,sec_address];
    // "$3" = secondary min placeholder
    // "$4" = secondary max placeholder
    // "secondary_column < $3 || secondary_column > $3 || secondary_column == $3" <-- then it can
    // Ok iv'e seen < for $3,
    //  * if i see > $4 it's ok,
    //  * if i see sec_index < $4 , then it's worng because i already have seen an < for sec. index
    // go to QueryBounds, so we need to know that $3 is being used for secondary index
    // "secondary_column + price < $3 * 9" <--- it NEVER goes into range stuff not QUeryBounds
    // * secondary_column < $3 AND secondary_column + price < $3 * 9 AND secondary_column > $4" -->
    //     secondary placeholder usage = min = $3, max = $4
    //     basic operations = secondary_column + Price < $3 * 9
    //  * secondary_column < $3 AND secondary_column < $4
    // secondary_index In [1,2,4,5] -> sec >= 1 AND sec <= 5 AND (sec=1 OR sec = 2 OR sec = 4 OR sec=5)
    // WHERE something() OR sec_index > $4 <-- we dont use range, it's expensive
    // WHERE something() AND sec_index OP [$1] <-- we use range
    // WHERE something() AND sec_index >= [$1] AND sec_index + price < 3*quantity <-- not optimized
    // (AND (< sec_ind $4) (OR (something) (< sec_ind (+ price 3)))
    // something1 AND (sec_indx < $4 AND (something OR $4 < price  + 3)) <-- al right stuff goes into basic
    // operation --> transformation to ?
    // something1 AND (1 AND (something OR sec_ind < price  + 3)) <-- al right stuff goes into basic
    // parseil needs to take as input
    // * placeholder namings for ranges
    //      "$1" => primary_index_min, "$2" => primary_index_max
    //      max number of placeholders supported
    //  * parsil needs to output as well
    //      * Option<"$3"=> secondary_index_min >
    //      * Option<"$4"=> secondary_index_max >
    //  * parsil restrictions
    //      * block number will always be "block >= $1 AND block =< $2"
    //      * secondary_index to be used in optimuzed query needs to be of form "sec_index OP $3"
    //      with only AND with similar formats (range format)
    //          * we can't have "sec_index < $3" OR "sec_index > $4"
    //          * but we can have "sec_index < $3 AND (price < $3 -10 OR sec_index * price < $4 + 20")
    //              * only the first predicate is used in range query
    let placeholders = Placeholders::new_empty(U256::from(min_block), U256::from(max_block));

    let query_str = format!(
        "SELECT AVG({value_column})
                FROM {table_name}
                WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER} 
                AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER}
                AND {key_column} = '0x{key_value}';"
    );
    Ok(QueryCooking {
        min_block: min_block as BlockPrimaryIndex,
        max_block: max_block as BlockPrimaryIndex,
        query: query_str,
        placeholders,
        example_row: longest_key.clone(),
        epochs: epochs.clone(),
    })
}

async fn collect_all_at(tree: &MerkleRowTree, at: Epoch) -> Result<Vec<Row<BlockPrimaryIndex>>> {
    let root_key = tree.root_at(at).await.unwrap();
    let (ctx, payload) = tree.try_fetch_with_context_at(&root_key, at).await.unwrap();
    let root_row = Row {
        k: root_key,
        payload,
    };
    let mut all_rows = vec![root_row];
    let mut to_inspect = vec![ctx];
    while !to_inspect.is_empty() {
        let local = to_inspect.clone();
        let (local_rows, local_ctx): (Vec<_>, Vec<_>) = stream::iter(local.iter())
            .then(|ctx| async {
                let lctx = ctx.clone();
                let mut local_rows = Vec::new();
                let mut local_ctx = Vec::new();
                for child_k in lctx.iter_children().flatten() {
                    let (child_ctx, child_payload) =
                        tree.try_fetch_with_context_at(child_k, at).await.unwrap();
                    local_rows.push(Row {
                        k: child_k.clone(),
                        payload: child_payload,
                    });
                    local_ctx.push(child_ctx.clone())
                }
                (local_rows, local_ctx)
            })
            .unzip()
            .await;
        all_rows.extend(local_rows.into_iter().flatten().collect::<Vec<_>>());
        to_inspect = local_ctx.into_iter().flatten().collect::<Vec<_>>();
    }
    Ok(all_rows)
}

fn find_longest_consecutive_sequence(v: Vec<i64>) -> (usize, i64) {
    let mut longest = 0;
    let mut starting_idx = 0;
    for i in 0..v.len() - 1 {
        if v[i] + 1 == v[i + 1] {
            longest += 1;
        } else {
            longest = 0;
            starting_idx = i + 1;
        }
    }
    (longest, v[starting_idx])
}

async fn check_correct_cells_tree(
    all_cells: &[ColumnCell],
    payload: &RowPayload<BlockPrimaryIndex>,
) -> Result<()> {
    let local_cells = all_cells.iter().cloned().collect::<Vec<_>>();
    let expected_cells_root = payload
        .cell_root_hash
        .clone()
        .or(Some(HashOutput::from(*empty_poseidon_hash())))
        .unwrap();
    let mut tree = indexing::cell::new_tree().await;
    tree.in_transaction(|t| {
        async move {
            for (i, cell) in local_cells[2..].into_iter().enumerate() {
                // putting 0 for primary index as it doesn't matter in the hash computation
                t.store(
                    i + 1,
                    MerkleCell::new(cell.id.to_canonical_u64(), cell.value, 0),
                )
                .await?;
            }
            Ok(())
        }
        .boxed()
    })
    .await
    .expect("can't update cell tree");
    let found_hash = tree.root_data().await.unwrap().hash;
    assert_eq!(
        expected_cells_root, found_hash,
        "cells root hash not the same when given to circuit"
    );
    Ok(())
}

pub enum SqlType {
    Numeric,
}

impl SqlType {
    pub fn extract(&self, row: &PsqlRow, idx: usize) -> SqlReturn {
        match self {
            SqlType::Numeric => SqlReturn::Numeric(row.get::<_, rust_decimal::Decimal>(idx)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum SqlReturn {
    Numeric(rust_decimal::Decimal),
}

fn print_vec_sql_rows(rows: &[PsqlRow], types: SqlType) {
    if rows.len() == 0 {
        println!("no rows returned");
    }
    let columns = rows.first().as_ref().unwrap().columns();
    println!(
        "{:?}",
        columns.iter().map(|c| c.name().to_string()).join(" | ")
    );
    for row in rows {
        println!("{:?}", types.extract(row, 0));
    }
}

// NOTE this might be good to have on public API ?
// cc/ @andrus
pub trait LagrangeNode {
    fn value(&self) -> U256;
    fn hash(&self) -> HashOutput;
    fn min(&self) -> U256;
    fn max(&self) -> U256;
    fn embedded_hash(&self) -> HashOutput;
}

impl<T: Eq + Default + std::fmt::Debug + Clone> LagrangeNode for RowPayload<T> {
    fn value(&self) -> U256 {
        self.secondary_index_value()
    }

    fn hash(&self) -> HashOutput {
        self.hash.clone()
    }

    fn min(&self) -> U256 {
        self.min
    }

    fn max(&self) -> U256 {
        self.max
    }

    fn embedded_hash(&self) -> HashOutput {
        self.cell_root_hash.clone().unwrap()
    }
}

impl<T> LagrangeNode for IndexNode<T> {
    fn value(&self) -> U256 {
        self.value.0
    }

    fn hash(&self) -> HashOutput {
        self.node_hash.clone()
    }

    fn min(&self) -> U256 {
        self.min
    }

    fn max(&self) -> U256 {
        self.max
    }

    fn embedded_hash(&self) -> HashOutput {
        self.row_tree_hash.clone()
    }
}
