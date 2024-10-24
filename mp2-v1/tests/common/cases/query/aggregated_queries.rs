use plonky2::{
    field::types::PrimeField64, hash::hash_types::HashOut, plonk::config::GenericHashOut,
};
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
};

use crate::common::{
    cases::{
        indexing::BLOCK_COLUMN_NAME,
        planner::{IndexInfo, QueryPlanner, RowInfo, TreeInfo},
        query::{QueryCooking, SqlReturn, SqlType},
        table_source::BASE_VALUE,
    },
    proof_storage::{ProofKey, ProofStorage},
    rowtree::MerkleRowTree,
    table::{Table, TableColumns},
    TableInfo,
};

use crate::context::TestContext;
use alloy::primitives::U256;
use anyhow::{bail, Context, Result};
use futures::{future::BoxFuture, stream, FutureExt, StreamExt};

use itertools::Itertools;
use log::*;
use mp2_common::{
    poseidon::empty_poseidon_hash,
    proof::{deserialize_proof, ProofWithVK},
    types::HashOutput,
    C, D, F,
};
use mp2_v1::{
    api::MetadataHash,
    indexing::{
        self,
        block::BlockPrimaryIndex,
        cell::MerkleCell,
        row::{Row, RowPayload, RowTreeKey},
        LagrangeNode,
    },
    values_extraction::identifier_block_column,
};
use parsil::{
    assembler::{DynamicCircuitPis, StaticCircuitPis},
    bracketer::bracket_secondary_index,
    queries::{core_keys_for_index_tree, core_keys_for_row_tree},
    ParsilSettings, DEFAULT_MAX_BLOCK_PLACEHOLDER, DEFAULT_MIN_BLOCK_PLACEHOLDER,
};
use ryhope::{
    storage::{
        pgsql::ToFromBytea,
        updatetree::{Next, UpdateTree, WorkplanItem},
        EpochKvStorage, RoEpochKvStorage, TreeTransactionalStorage, WideLineage,
    },
    tree::NodeContext,
    Epoch, NodePayload,
};
use sqlparser::ast::Query;
use tokio_postgres::Row as PsqlRow;
use verifiable_db::{
    ivc::PublicInputs as IndexingPIS,
    query::{
        aggregation::{ChildPosition, NodeInfo, QueryHashNonExistenceCircuits, SubProof},
        computational_hash_ids::{ColumnIDs, Identifiers},
        universal_circuit::universal_circuit_inputs::{
            ColumnCell, PlaceholderId, Placeholders, RowCells,
        },
    },
    revelation::PublicInputs,
    row_tree,
};

use super::{
    GlobalCircuitInput, QueryCircuitInput, RevelationCircuitInput, INDEX_TREE_MAX_DEPTH,
    MAX_NUM_COLUMNS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_OUTPUTS, MAX_NUM_PLACEHOLDERS,
    MAX_NUM_PREDICATE_OPS, MAX_NUM_RESULT_OPS, ROW_TREE_MAX_DEPTH,
};

pub type RevelationPublicInputs<'a> =
    PublicInputs<'a, F, MAX_NUM_OUTPUTS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_PLACEHOLDERS>;

/// Execute a query to know all the touched rows, and then call the universal circuit on all rows
pub(crate) async fn prove_query(
    ctx: &mut TestContext,
    table: &Table,
    query: QueryCooking,
    mut parsed: Query,
    settings: &ParsilSettings<&Table>,
    res: Vec<PsqlRow>,
    metadata: MetadataHash,
    pis: DynamicCircuitPis,
) -> Result<()> {
    let row_cache = table
        .row
        .wide_lineage_between(
            table.row.current_epoch(),
            &core_keys_for_row_tree(&query.query, &settings, &pis.bounds, &query.placeholders)?,
            (query.min_block as Epoch, query.max_block as Epoch),
        )
        .await?;
    // the query to use to fetch all the rows keys involved in the result tree.
    let mut row_keys_per_epoch = row_cache.keys_by_epochs();
    let all_epochs = query.min_block as Epoch..=query.max_block as Epoch;
    let mut planner = QueryPlanner {
        ctx,
        query: query.clone(),
        settings: &settings,
        pis: &pis,
        table: &table,
        columns: table.columns.clone(),
    };

    // prove the different versions of the row tree for each of the involved rows for each block
    for (epoch, keys) in row_keys_per_epoch {
        let up = row_cache
            .update_tree_for(epoch as Epoch)
            .expect("this epoch should exist");
        let info = RowInfo {
            tree: &table.row,
            satisfiying_rows: keys,
        };
        prove_query_on_tree(&mut planner, info, up, epoch as BlockPrimaryIndex).await?;
    }

    // prove the index tree, on a single version. Both path can be taken depending if we do have
    // some nodes or not
    let initial_epoch = table.index.initial_epoch() as BlockPrimaryIndex;
    let current_epoch = table.index.current_epoch() as BlockPrimaryIndex;
    let block_range = query.min_block.max(initial_epoch + 1)..=query.max_block.min(current_epoch);
    info!(
        "found {} blocks in range: {:?}",
        block_range.clone().count(),
        block_range
    );
    if block_range.is_empty() {
        info!("Running INDEX TREE proving for EMPTY query");
        // no valid blocks in the query range, so we need to choose a block to prove
        // non-existence. Either the one after genesis or the last one
        let to_be_proven_node = if query.max_block < initial_epoch {
            initial_epoch + 1
        } else if query.min_block > current_epoch {
            current_epoch
        } else {
            bail!(
                "Empty block range to be proven for query bounds {}, {}, but no node
                    to be proven with non-existence circuit was found. Something is wrong",
                query.min_block,
                query.max_block
            );
        } as BlockPrimaryIndex;
        prove_non_existence_index(&mut planner, to_be_proven_node).await?;
        // we get the lineage of the node that proves the non existence of the index nodes
        // required for the query. We specify the epoch at which we want to get this lineage as
        // of the current epoch.
        let lineage = table
            .index
            .lineage_at(&to_be_proven_node, current_epoch as Epoch)
            .await
            .expect("can't get lineage")
            .into_full_path()
            .collect();
        let up = UpdateTree::from_path(lineage, current_epoch as Epoch);
        let info = IndexInfo {
            tree: &table.index,
            bounds: (query.min_block, query.max_block),
        };
        prove_query_on_tree(
            &mut planner,
            info,
            up,
            table.index.current_epoch() as BlockPrimaryIndex,
        )
        .await?;
    } else {
        info!("Running INDEX tree proving from cache");
        // Only here we can run the SQL query for index so it doesn't crash
        let index_query =
            core_keys_for_index_tree(current_epoch as Epoch, (query.min_block, query.max_block))?;
        let big_index_cache = table
            .index
            // The bounds here means between which versions of the tree should we look. For index tree,
            // we only look at _one_ version of the tree.
            .wide_lineage_between(
                current_epoch as Epoch,
                &index_query,
                (current_epoch as Epoch, current_epoch as Epoch),
            )
            .await?;
        // since we only analyze the index tree for one epoch
        assert_eq!(big_index_cache.keys_by_epochs().len(), 1);
        // This is ok because the cache only have the block that are in the range so the
        // filter_check is gonna return the same thing
        // TOOD: @franklin is that correct ?
        let up = big_index_cache
            // this is the epoch we choose how to prove
            .update_tree_for(current_epoch as Epoch)
            .expect("this epoch should exist");
        prove_query_on_tree(
            &mut planner,
            big_index_cache,
            up,
            table.index.current_epoch() as BlockPrimaryIndex,
        )
        .await?;
    }

    info!("Query proofs done! Generating revelation proof...");
    let proof = prove_revelation(ctx, table, &query, &pis, table.index.current_epoch()).await?;
    info!("Revelation proof done! Checking public inputs...");
    // get `StaticPublicInputs`, i.e., the data about the query available only at query registration time,
    // to check the public inputs
    let pis = parsil::assembler::assemble_static(&parsed, &settings)?;

    // get number of matching rows
    let mut exec_query = parsil::executor::generate_query_keys(&mut parsed, &settings)?;
    let query_params = exec_query.convert_placeholders(&query.placeholders);
    let num_touched_rows = table
        .execute_row_query(
            &exec_query
                .normalize_placeholder_names()
                .to_pgsql_string_with_placeholder(),
            &query_params,
        )
        .await?
        .len();

    check_final_outputs(
        proof,
        ctx,
        table,
        &query,
        &pis,
        table.index.current_epoch(),
        num_touched_rows,
        res,
        metadata,
    )?;
    info!("Revelation done!");
    Ok(())
}

async fn prove_revelation(
    ctx: &TestContext,
    table: &Table,
    query: &QueryCooking,
    pis: &DynamicCircuitPis,
    tree_epoch: Epoch,
) -> Result<Vec<u8>> {
    // load the query proof, which is at the root of the tree
    let query_proof = {
        let root_key = table.index.root_at(tree_epoch).await.unwrap();
        let proof_key = ProofKey::QueryAggregateIndex((
            query.query.clone(),
            query.placeholders.placeholder_values(),
            root_key,
        ));
        ctx.storage.get_proof_exact(&proof_key)?
    };
    // load the preprocessing proof at the same epoch
    let indexing_proof = {
        let pk = ProofKey::IVC(tree_epoch as BlockPrimaryIndex);
        ctx.storage.get_proof_exact(&pk)?
    };
    let input = RevelationCircuitInput::new_revelation_no_results_tree(
        query_proof,
        indexing_proof,
        &pis.bounds,
        &query.placeholders,
        &pis.predication_operations,
        &pis.result,
    )?;
    let proof = ctx.run_query_proof(
        "querying::revelation",
        GlobalCircuitInput::Revelation(input),
    )?;
    Ok(proof)
}

pub(crate) fn check_final_outputs(
    revelation_proof: Vec<u8>,
    ctx: &TestContext,
    table: &Table,
    query: &QueryCooking,
    pis: &StaticCircuitPis,
    tree_epoch: Epoch,
    num_touched_rows: usize,
    res: Vec<PsqlRow>,
    offcircuit_md: MetadataHash,
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
    assert_eq!(
        offcircuit_md, metadata_hash,
        "metadata hash computed by circuit and offcircuit is not the same"
    );

    let column_ids = ColumnIDs::from(&table.columns);
    let expected_computational_hash = Identifiers::computational_hash(
        &column_ids,
        &pis.predication_operations,
        &pis.result,
        &metadata_hash,
        pis.bounds.min_query_secondary.clone(),
        pis.bounds.max_query_secondary.clone(),
    )?;
    assert_eq!(
        HashOutput::try_from(
            revelation_pis
                .flat_computational_hash()
                .iter()
                .flat_map(|f| u32::try_from(f.to_canonical_u64()).unwrap().to_be_bytes())
                .collect_vec()
        )?,
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
    assert!(!revelation_pis.overflow_flag());
    // check number of results
    assert_eq!(
        res.len() as u64,
        revelation_pis.num_results().to_canonical_u64(),
    );
    // check results
    res.into_iter()
        .zip(revelation_pis.result_values())
        .for_each(|(expected_res, res)| {
            (0..expected_res.len()).for_each(|i| {
                let SqlReturn::Numeric(expected_res) =
                    SqlType::Numeric.extract(&expected_res, i).unwrap();
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
async fn prove_query_on_tree<'a, I, K, V>(
    mut planner: &mut QueryPlanner<'a>,
    info: I,
    update: UpdateTree<K>,
    primary: BlockPrimaryIndex,
) -> Result<Vec<u8>>
where
    I: TreeInfo<K, V>,
    V: NodePayload + Send + Sync + LagrangeNode + Clone,
    K: Debug + Hash + Clone + Eq + Sync + Send,
{
    let query_id = planner.query.query.clone();
    let placeholder_values = planner.query.placeholders.placeholder_values();
    let mut workplan = update.into_workplan();
    let mut proven_nodes = HashSet::new();
    let fetch_only_proven_child = |nctx: NodeContext<K>,
                                   cctx: &TestContext,
                                   proven: &HashSet<K>|
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
            .load_proof(
                cctx,
                &query_id,
                primary,
                &child_key,
                placeholder_values.clone(),
            )
            .expect("key should already been proven");
        (pos, child_proof)
    };
    while let Some(Next::Ready(wk)) = workplan.next() {
        let k = wk.k();
        // closure performing all the operations necessary beofre jumping to the next iteration
        let mut end_iteration = |proven_nodes: &mut HashSet<K>| -> Result<()> {
            proven_nodes.insert(k.clone());
            workplan.done(&wk)?;
            Ok(())
        };
        // since epoch starts at genesis now, we can directly give the value of the block
        // number as epoch number
        let (node_ctx, node_payload) = info
            .fetch_ctx_and_payload_at(primary as Epoch, k)
            .await
            .expect("cache is not full");
        let is_satisfying_query = info.is_satisfying_query(k);
        let embedded_proof = info
            .load_or_prove_embedded(&mut planner, primary, k, &node_payload)
            .await;
        if node_ctx.is_leaf() && info.is_row_tree() {
            // NOTE: if it is a leaf of the row tree, then there is no need to prove anything,
            // since we're not "aggregating" any from below. For the index tree however, we
            // need to always generate an aggregate proof. Therefore, in this test, we just copy the
            // proof to the expected aggregation location and move on. Note that we need to
            // save the proof only if the current row is satisfying the query: indeed, if
            // this not the case, then the proof should have already been generated and stored
            // with the non-existence circuit
            if is_satisfying_query {
                // unwrap is safe since we are guaranteed the row is satisfying the query
                info.save_proof(
                    &mut planner.ctx,
                    &query_id,
                    primary,
                    &k,
                    placeholder_values.clone(),
                    embedded_proof?.unwrap(),
                )?;
            }

            end_iteration(&mut proven_nodes)?;
            continue;
        }

        // In the case we haven't proven anything under this node, it's the single path case
        // It is sufficient to check if this node is one of the leaves we in this update tree.Note
        // it is not the same meaning as a "leaf of a tree", here it just means is it the first
        // node in the merkle path.
        let (k, is_path_end) = if let WorkplanItem::Node { k, is_path_end } = &wk {
            (k, *is_path_end)
        } else {
            unreachable!("this update tree has been created with a batch size of 1")
        };

        let (name, input) = if is_path_end {
            info!("node {primary} -> {k:?} is at path end");
            if !is_satisfying_query {
                // if the node of the key does not satisfy the query, but this node is at the end of
                // a path to be proven, then it means we are in a tree with no satisfying nodes, and
                // so the current node is the node chosen to be proven with non-existence circuits.
                // Since the node has already been proven, we just save the proof and we continue
                end_iteration(&mut proven_nodes)?;
                continue;
            }
            assert!(
                info.is_satisfying_query(&k),
                "first node in merkle path should always be a valid query one"
            );
            let (node_info, left_info, right_info) =
            // we can use primary as epoch now that tree stores epoch from genesis
                get_node_info(&info, &k, primary as Epoch).await;
            (
                "querying::aggregation::single",
                QueryCircuitInput::new_single_path(
                    SubProof::new_embedded_tree_proof(embedded_proof?.unwrap())?,
                    left_info,
                    right_info,
                    node_info,
                    info.is_row_tree(),
                    &planner.pis.bounds,
                )
                .expect("can't create leaf input"),
            )
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
                    &info,
                    &k,
                    // we can use primary as epoch since storage starts epoch at genesis
                    primary as Epoch,
                )
                .await;
                // we look which child is the one to load from storage, the one we already proved
                (
                    "querying::aggregation::single",
                    QueryCircuitInput::new_single_path(
                        SubProof::new_child_proof(child_proof, child_pos)?,
                        left_info,
                        right_info,
                        node_info,
                        info.is_row_tree(),
                        &planner.pis.bounds,
                    )
                    .expect("can't create leaf input"),
                )
            } else {
                // this case is easy, since all that's left is partial or full where both
                // child(ren) and current node belong to query
                let is_correct_left = node_ctx.left.is_some()
                    && proven_nodes.contains(node_ctx.left.as_ref().unwrap());
                let is_correct_right = node_ctx.right.is_some()
                    && proven_nodes.contains(node_ctx.right.as_ref().unwrap());
                if is_correct_left && is_correct_right {
                    // full node case
                    let left_proof = info.load_proof(
                        planner.ctx,
                        &query_id,
                        primary,
                        node_ctx.left.as_ref().unwrap(),
                        placeholder_values.clone(),
                    )?;
                    let right_proof = info.load_proof(
                        planner.ctx,
                        &query_id,
                        primary,
                        node_ctx.right.as_ref().unwrap(),
                        placeholder_values.clone(),
                    )?;
                    (
                        "querying::aggregation::full",
                        QueryCircuitInput::new_full_node(
                            left_proof,
                            right_proof,
                            embedded_proof?.expect("should be a embedded_proof here"),
                            info.is_row_tree(),
                            &planner.pis.bounds,
                        )
                        .expect("can't create full node circuit input"),
                    )
                } else {
                    // partial case
                    let (child_pos, child_proof) =
                        fetch_only_proven_child(node_ctx, planner.ctx, &proven_nodes);
                    let (_, left_info, right_info) =
                        get_node_info(&info, &k, primary as Epoch).await;
                    let unproven = match child_pos {
                        ChildPosition::Left => right_info,
                        ChildPosition::Right => left_info,
                    };
                    (
                        "querying::aggregation::partial",
                        QueryCircuitInput::new_partial_node(
                            child_proof,
                            embedded_proof?.expect("should be an embedded_proof here too"),
                            unproven,
                            child_pos,
                            info.is_row_tree(),
                            &planner.pis.bounds,
                        )
                        .expect("can't build new partial node input"),
                    )
                }
            }
        };
        info!("AGGREGATE query proof RUNNING for {primary} -> {k:?} ");
        let proof = planner
            .ctx
            .run_query_proof(name, GlobalCircuitInput::Query(input))?;
        info.save_proof(
            planner.ctx,
            &query_id,
            primary,
            &k,
            placeholder_values.clone(),
            proof,
        )?;
        info!("query proof DONE for {primary} -> {k:?} ");
        end_iteration(&mut proven_nodes)?;
    }
    Ok(vec![])
}

// TODO: make it recursive with async - tentative in `fetch_child_info` but  it doesn't work,
// recursion with async is weird.
pub(crate) async fn get_node_info<K, V, T: TreeInfo<K, V>>(
    lookup: &T,
    k: &K,
    at: Epoch,
) -> (NodeInfo, Option<NodeInfo>, Option<NodeInfo>)
where
    K: Debug + Hash + Clone + Send + Sync + Eq,
    // NOTICE the ToValue here to get the value associated to a node
    V: NodePayload + Send + Sync + LagrangeNode + Clone,
{
    // look at the left child first then right child, then build the node info
    let (ctx, node_payload) = lookup
        .fetch_ctx_and_payload_at(at, k)
        .await
        .expect("cache not filled");
    // this looks at the value of a child node (left and right), and fetches the grandchildren
    // information to be able to build their respective node info.
    let fetch_ni = async |k: Option<K>| -> (Option<NodeInfo>, Option<HashOutput>) {
        match k {
            None => (None, None),
            Some(child_k) => {
                let (child_ctx, child_payload) = lookup
                    .fetch_ctx_and_payload_at(at, &child_k)
                    .await
                    .expect("cache not filled");
                // we need the grand child hashes for constructing the node info of the
                // children of the node in argument
                let child_left_hash = match child_ctx.left {
                    Some(left_left_k) => {
                        let (_, payload) = lookup
                            .fetch_ctx_and_payload_at(at, &left_left_k)
                            .await
                            .expect("cache not filled");
                        Some(payload.hash())
                    }
                    None => None,
                };
                let child_right_hash = match child_ctx.right {
                    Some(left_right_k) => {
                        let (_, payload) = lookup
                            .fetch_ctx_and_payload_at(at, &left_right_k)
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

pub fn generate_non_existence_proof<'a>(
    node_info: NodeInfo,
    left_child_info: Option<NodeInfo>,
    right_child_info: Option<NodeInfo>,
    primary: BlockPrimaryIndex,
    planner: &mut QueryPlanner<'a>,
    is_rows_tree_node: bool,
) -> Result<Vec<u8>> {
    let index_ids = [
        planner.table.columns.primary_column().identifier(),
        planner.table.columns.secondary_column().identifier(),
    ];
    assert_eq!(index_ids[0], identifier_block_column());
    let column_ids = ColumnIDs::new(
        index_ids[0],
        index_ids[1],
        planner
            .table
            .columns
            .non_indexed_columns()
            .iter()
            .map(|column| column.identifier())
            .collect_vec(),
    );
    let query_hashes = QueryHashNonExistenceCircuits::new::<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_ITEMS_PER_OUTPUT,
    >(
        &column_ids,
        &planner.pis.predication_operations,
        &planner.pis.result,
        &planner.query.placeholders,
        &planner.pis.bounds,
        is_rows_tree_node,
    )?;
    let input = QueryCircuitInput::new_non_existence_input(
        node_info,
        left_child_info,
        right_child_info,
        U256::from(primary),
        &index_ids,
        &planner.pis.query_aggregations,
        query_hashes,
        is_rows_tree_node,
        &planner.pis.bounds,
        &planner.query.placeholders,
    )?;
    planner
        .ctx
        .run_query_proof("querying::non_existence", GlobalCircuitInput::Query(input))
}

/// Generate a proof for a node of the index tree which is outside of the query bounds
async fn prove_non_existence_index<'a>(
    planner: &mut QueryPlanner<'a>,
    primary: BlockPrimaryIndex,
) -> Result<()> {
    let tree = &planner.table.index;
    let current_epoch = tree.current_epoch();
    let (node_info, left_child_info, right_child_info) = get_node_info(
        &IndexInfo::non_satisfying_info(tree),
        &primary,
        current_epoch,
    )
    .await;
    let proof_key = ProofKey::QueryAggregateIndex((
        planner.query.query.clone(),
        planner.query.placeholders.placeholder_values(),
        primary,
    ));
    info!("Non-existence circuit proof RUNNING for {current_epoch} -> {primary} ");
    let proof = generate_non_existence_proof(
        node_info,
        left_child_info,
        right_child_info,
        primary,
        planner,
        false,
    )
    .expect(
        format!("unable to generate non-existence proof for {current_epoch} -> {primary}").as_str(),
    );
    info!("Non-existence circuit proof DONE for {current_epoch} -> {primary} ");
    planner.ctx.storage.store_proof(proof_key, proof.clone())?;

    Ok(())
}

pub async fn prove_non_existence_row<'a>(
    planner: &mut QueryPlanner<'a>,
    primary: BlockPrimaryIndex,
) -> Result<()> {
    let row_tree = &planner.table.row;
    let (query_for_min, query_for_max) = bracket_secondary_index(
        &planner.table.public_name,
        &planner.settings,
        primary as Epoch,
        &planner.pis.bounds,
    );

    // this method returns the `NodeContext` of the successor of the node provided as input,
    // if the successor exists in the row tree and it stores the same value of the input node (i.e., `value`);
    // returns `None` otherwise, as it means that the input node can be used to prove non-existence
    async fn get_successor_node_with_same_value(
        node_ctx: &NodeContext<RowTreeKey>,
        value: U256,
        table: &Table,
        primary: BlockPrimaryIndex,
    ) -> Option<NodeContext<RowTreeKey>> {
        let row_tree = &table.row;
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
            let (mut candidate_successor_ctx, mut candidate_successor_val) =
                (node_ctx.clone(), value);
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
        node_ctx: &NodeContext<RowTreeKey>,
        value: U256,
        table: &Table,
        primary: BlockPrimaryIndex,
    ) -> Option<NodeContext<RowTreeKey>> {
        let row_tree = &table.row;
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
                        child.is_some()
                            && child.unwrap().clone() == candidate_predecessor_ctx.node_id
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

    let find_node_for_proof = async |query: Option<String>,
                                     is_min_query: bool|
           -> Result<Option<RowTreeKey>> {
        if query.is_none() {
            return Ok(None);
        }
        let rows = planner
            .table
            .execute_row_query(&query.unwrap(), &[])
            .await?;
        if rows.len() == 0 {
            // no node found, return None
            info!("Search node for non-existence circuit: no node found");
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
                get_successor_node_with_same_value(&node_ctx, value, &planner.table, primary).await;
            while successor_ctx.is_some() {
                node_ctx = successor_ctx.unwrap();
                successor_ctx =
                    get_successor_node_with_same_value(&node_ctx, value, &planner.table, primary)
                        .await;
            }
        } else {
            // starting from the node with key `row_key`, we iterate over its predecessor nodes in the tree,
            // until we found a node that either has no predecessor or whose predecessor stores a value different
            // from the value `value` stored in the node with key `row_key`; the node found is the one to be
            // employed to generate the non-existence proof
            let mut predecessor_ctx =
                get_predecessor_node_with_same_value(&node_ctx, value, &planner.table, primary)
                    .await;
            while predecessor_ctx.is_some() {
                node_ctx = predecessor_ctx.unwrap();
                predecessor_ctx =
                    get_predecessor_node_with_same_value(&node_ctx, value, &planner.table, primary)
                        .await;
            }
        }

        Ok(Some(node_ctx.node_id))
    };
    // try first with lower node than secondary min query bound
    let to_be_proven_node = match find_node_for_proof(query_for_min, true).await? {
        Some(node) => node,
        None => find_node_for_proof(query_for_max, false)
            .await?
            .expect("No valid node found to prove non-existence, something is wrong"),
    };
    let (node_info, left_child_info, right_child_info) = get_node_info(
        &RowInfo::no_satisfying_rows(row_tree),
        &to_be_proven_node,
        primary as Epoch,
    )
    .await;

    let proof_key = ProofKey::QueryAggregateRow((
        planner.query.query.clone(),
        planner.query.placeholders.placeholder_values(),
        primary,
        to_be_proven_node.clone(),
    ));
    info!("Non-existence circuit proof RUNNING for {primary} -> {to_be_proven_node:?} ");
    let proof = generate_non_existence_proof(
        node_info,
        left_child_info,
        right_child_info,
        primary,
        planner,
        true,
    )
    .expect(
        format!("unable to generate non-existence proof for {primary} -> {to_be_proven_node:?}")
            .as_str(),
    );
    info!("Non-existence circuit proof DONE for {primary} -> {to_be_proven_node:?} ");
    planner.ctx.storage.store_proof(proof_key, proof.clone())?;

    // now generate the path up to the root of the row tree for the current epoch, as all nodes in such a path
    // need to be proven
    let path = planner
        .table
        .row
        // since the epoch starts at genesis we can directly give the block number !
        .lineage_at(&to_be_proven_node, primary as Epoch)
        .await
        .expect("node doesn't have a lineage?")
        .into_full_path()
        .collect_vec();
    let proving_tree = UpdateTree::from_paths([path], primary as Epoch);
    let info = RowInfo::no_satisfying_rows(&planner.table.row);
    let mut planner = QueryPlanner {
        ctx: planner.ctx,
        table: planner.table,
        query: planner.query.clone(),
        pis: planner.pis,
        columns: planner.columns.clone(),
        settings: &planner.settings,
    };
    prove_query_on_tree(&mut planner, info, proving_tree, primary).await?;

    Ok(())
}

pub async fn prove_single_row<T: TreeInfo<RowTreeKey, RowPayload<BlockPrimaryIndex>>>(
    ctx: &mut TestContext,
    tree: &T,
    columns: &TableColumns,
    primary: BlockPrimaryIndex,
    row_key: &RowTreeKey,
    pis: &DynamicCircuitPis,
    query: &QueryCooking,
) -> Result<Vec<u8>> {
    // 1. Get the all the cells including primary and secondary index
    // Note we can use the primary as epoch since now epoch == primary in the storage
    let (row_ctx, row_payload) = tree
        .fetch_ctx_and_payload_at(primary as Epoch, row_key)
        .await
        .expect("cache not full");

    // API is gonna change on this but right now, we have to sort all the "rest" cells by index
    // in the tree, and put the primary one and secondary one in front
    let rest_cells = columns
        .non_indexed_columns()
        .iter()
        .map(|tc| tc.identifier())
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
    let proof_key = ProofKey::QueryUniversal((
        query.query.clone(),
        query.placeholders.placeholder_values(),
        primary,
        row_key.clone(),
    ));
    let proof = {
        info!("Universal query proof RUNNING for {primary} -> {row_key:?} ");
        let proof = ctx
            .run_query_proof("querying::universal", GlobalCircuitInput::Query(input))
            .expect("unable to generate universal proof for {epoch} -> {row_key:?}");
        info!("Universal query proof DONE for {primary} -> {row_key:?} ");
        ctx.storage.store_proof(proof_key, proof.clone())?;
        proof
    };
    Ok(proof)
}

type BlockRange = (BlockPrimaryIndex, BlockPrimaryIndex);

pub(crate) async fn cook_query_between_blocks(
    table: &Table,
    info: &TableInfo,
) -> Result<QueryCooking> {
    let max = table.row.current_epoch();
    let min = max - 1;

    let value_column = &info.value_column;
    let table_name = &table.public_name;
    let placeholders = Placeholders::new_empty(U256::from(min), U256::from(max));

    let query_str = format!(
        "SELECT AVG({value_column})
                FROM {table_name}
                WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER};"
    );
    Ok(QueryCooking {
        min_block: min as BlockPrimaryIndex,
        max_block: max as BlockPrimaryIndex,
        query: query_str,
        placeholders,
        limit: None,
        offset: None,
    })
}

pub(crate) async fn cook_query_secondary_index_nonexisting_placeholder(
    table: &Table,
    info: &TableInfo,
) -> Result<QueryCooking> {
    let (longest_key, (min_block, max_block)) = find_longest_lived_key(table, false).await?;
    let key_value = hex::encode(longest_key.value.to_be_bytes_trimmed_vec());
    info!(
        "Longest sequence is for key {longest_key:?} -> from block {:?} to  {:?}, hex -> {}",
        min_block, max_block, key_value
    );
    // now we can fetch the key that we want
    let key_column = table.columns.secondary.name.clone();
    // Assuming this is mapping with only two columns !
    let value_column = &info.value_column;
    let table_name = &table.public_name;

    let filtering_value = *BASE_VALUE + U256::from(5);

    let random_value = U256::from(1234567890);
    let placeholders = Placeholders::from((
        vec![
            (PlaceholderId::Generic(1), random_value),
            (PlaceholderId::Generic(2), filtering_value),
        ],
        U256::from(min_block),
        U256::from(max_block),
    ));

    let query_str = format!(
        "SELECT AVG({value_column})
                FROM {table_name}
                WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER}
                AND {key_column} = $1 AND {value_column} >= $2;"
    );
    Ok(QueryCooking {
        min_block: min_block as BlockPrimaryIndex,
        max_block: max_block as BlockPrimaryIndex,
        query: query_str,
        placeholders,
        limit: None,
        offset: None,
    })
}

// cook up a SQL query on the secondary index and with a predicate on the non-indexed column.
// we just iterate on mapping keys and take the one that exist for most blocks. We also choose
// a value to filter over the non-indexed column
pub(crate) async fn cook_query_secondary_index_placeholder(
    table: &Table,
    info: &TableInfo,
) -> Result<QueryCooking> {
    let (longest_key, (min_block, max_block)) = find_longest_lived_key(table, false).await?;
    let key_value = hex::encode(longest_key.value.to_be_bytes_trimmed_vec());
    info!(
        "Longest sequence is for key {longest_key:?} -> from block {:?} to  {:?}, hex -> {}",
        min_block, max_block, key_value
    );
    // now we can fetch the key that we want
    let key_column = table.columns.secondary.name.clone();
    let value_column = &info.value_column;
    let table_name = &table.public_name;

    let filtering_value = *BASE_VALUE + U256::from(5);

    let placeholders = Placeholders::from((
        vec![
            (PlaceholderId::Generic(1), longest_key.value),
            (PlaceholderId::Generic(2), filtering_value),
        ],
        U256::from(min_block),
        U256::from(max_block),
    ));

    let query_str = format!(
        "SELECT AVG({value_column})
                FROM {table_name}
                WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER}
                AND {key_column} = $1 AND {value_column} >= $2;"
    );
    Ok(QueryCooking {
        min_block: min_block as BlockPrimaryIndex,
        max_block: max_block as BlockPrimaryIndex,
        query: query_str,
        placeholders,
        limit: None,
        offset: None,
    })
}

// cook up a SQL query on the secondary index. For that we just iterate on mapping keys and
// take the one that exist for most blocks
pub(crate) async fn cook_query_unique_secondary_index(
    table: &Table,
    info: &TableInfo,
) -> Result<QueryCooking> {
    let (longest_key, (min_block, max_block)) = find_longest_lived_key(table, false).await?;
    let key_value = hex::encode(longest_key.value.to_be_bytes_trimmed_vec());
    info!(
        "Longest sequence is for key {longest_key:?} -> from block {:?} to  {:?}, hex -> {}",
        min_block, max_block, key_value
    );
    // now we can fetch the key that we want
    let key_column = table.columns.secondary.name.clone();
    let value_column = &info.value_column;
    let table_name = &table.public_name;
    let max_block = min_block + 1;
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
        limit: None,
        offset: None,
    })
}

pub(crate) async fn cook_query_partial_block_range(
    table: &Table,
    info: &TableInfo,
) -> Result<QueryCooking> {
    let (longest_key, (min_block, max_block)) = find_longest_lived_key(table, false).await?;
    let key_value = hex::encode(longest_key.value.to_be_bytes_trimmed_vec());
    info!(
        "Longest sequence is for key {longest_key:?} -> from block {:?} to  {:?}, hex -> {}",
        min_block, max_block, key_value
    );
    // now we can fetch the key that we want
    let key_column = table.columns.secondary.name.clone();
    let value_column = info.value_column.clone();
    let table_name = &table.public_name;
    let initial_epoch = table.row.initial_epoch();
    // choose a min query bound smaller than initial epoch
    let min_block = initial_epoch - 1;
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
        limit: None,
        offset: None,
    })
}

pub(crate) async fn cook_query_no_matching_entries(
    table: &Table,
    info: &TableInfo,
) -> Result<QueryCooking> {
    let initial_epoch = table.row.initial_epoch();
    // choose query bounds outside of the range [initial_epoch, last_epoch]
    let min_block = 0;
    let max_block = initial_epoch - 1;
    // now we can fetch the key that we want
    let value_column = &info.value_column;
    let table_name = &table.public_name;
    let placeholders = Placeholders::new_empty(U256::from(min_block), U256::from(max_block));

    let query_str = format!(
        "SELECT SUM({value_column})
                FROM {table_name}
                WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER};"
    );

    Ok(QueryCooking {
        query: query_str,
        placeholders,
        min_block,
        max_block: max_block as usize,
        limit: None,
        offset: None,
    })
}

/// Cook a query where there are no entries satisying the secondary query bounds only for some
/// blocks of the primary index bounds (not for all the blocks)
pub(crate) async fn cook_query_non_matching_entries_some_blocks(
    table: &Table,
    info: &TableInfo,
) -> Result<QueryCooking> {
    let (longest_key, (min_block, max_block)) = find_longest_lived_key(table, true).await?;
    let key_value = hex::encode(longest_key.value.to_be_bytes_trimmed_vec());
    info!(
        "Longest sequence is for key {longest_key:?} -> from block {:?} to  {:?}, hex -> {}",
        min_block, max_block, key_value
    );
    // now we can fetch the key that we want
    let key_column = &table.columns.secondary.name;
    let value_column = &info.value_column;
    let table_name = &table.public_name;
    // in this query we set query bounds on block numbers to the widest range, so that we
    // are sure that there are blocks where the chosen key is not alive
    let min_block = table.row.initial_epoch() + 1;
    let max_block = table.row.current_epoch();
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
        limit: None,
        offset: None,
    })
}

/// Utility function to associated to each row in the tree, the blocks where the row
/// was valid
async fn extract_row_liveness(table: &Table) -> Result<HashMap<RowTreeKey, Vec<Epoch>>> {
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
    all_table
        .iter_mut()
        .for_each(|(_, epochs)| epochs.sort_unstable());
    Ok(all_table)
}

/// Find the the key of the node that lives the longest across all the blocks. If the
/// `must_not_be_alive_in_some_blocks` flag is true, then the method considers only nodes
/// that aren't live for all the blocks
pub(crate) async fn find_longest_lived_key(
    table: &Table,
    must_not_be_alive_in_some_blocks: bool,
) -> Result<(RowTreeKey, BlockRange)> {
    let initial_epoch = table.row.initial_epoch() + 1;
    let last_epoch = table.row.current_epoch();
    let all_table = extract_row_liveness(table).await?;
    // find the longest running row
    let (longest_key, longest_sequence, starting) = all_table
        .iter()
        .filter_map(|(k, epochs)| {
            // simplification here to start at first epoch where this row was. Otherwise need to do
            // longest consecutive sequence etc...
            let (l, start) = find_longest_consecutive_sequence(epochs.to_vec());
            debug!("finding sequence of {l} blocks for key {k:?} (epochs {epochs:?}");
            if must_not_be_alive_in_some_blocks {
                if start > initial_epoch || (start + l as i64) < last_epoch {
                    Some((k, l, start))
                } else {
                    None // it's live for all blocks, so we drop this row
                }
            } else {
                Some((k, l, start))
            }
        })
        .max_by_key(|(k, l, start)| *l)
        .unwrap_or_else(|| {
            panic!(
                "unable to find longest row? -> length all _table {}, max {}",
                all_table.len(),
                last_epoch,
            )
        });
    // we set the block bounds
    let min_block = starting as BlockPrimaryIndex;
    let max_block = min_block + longest_sequence;
    Ok((longest_key.clone(), (min_block, max_block)))
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
