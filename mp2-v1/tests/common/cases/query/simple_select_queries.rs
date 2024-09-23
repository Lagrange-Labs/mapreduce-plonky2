use std::collections::HashMap;

use alloy::primitives::U256;
use anyhow::{Error, Result};
use futures::{stream, StreamExt, TryStreamExt};
use itertools::Itertools;
use log::info;
use mp2_common::types::HashOutput;
use mp2_v1::{
    api::MetadataHash,
    indexing::{block::BlockPrimaryIndex, row::RowTreeKey, LagrangeNode},
};
use parsil::{
    assembler::DynamicCircuitPis,
    executor::{generate_query_execution_with_keys, generate_query_keys},
    ParsilSettings, DEFAULT_MAX_BLOCK_PLACEHOLDER, DEFAULT_MIN_BLOCK_PLACEHOLDER,
};
use ryhope::{
    storage::{pgsql::ToFromBytea, RoEpochKvStorage},
    Epoch, NodePayload,
};
use sqlparser::ast::Query;
use std::{fmt::Debug, hash::Hash};
use tokio_postgres::Row as PgSqlRow;
use verifiable_db::{
    query::{
        aggregation::{ChildPosition, NodeInfo},
        computational_hash_ids::ColumnIDs,
        universal_circuit::universal_circuit_inputs::{PlaceholderId, Placeholders},
    },
    revelation::{api::MatchingRow, RowPath},
    test_utils::MAX_NUM_OUTPUTS,
};

use crate::common::{
    cases::{
        indexing::BLOCK_COLUMN_NAME,
        planner::{IndexInfo, QueryPlanner, RowInfo, TreeInfo},
        query::{
            aggregated_queries::{
                check_final_outputs, find_longest_lived_key, get_node_info, prove_single_row,
            },
            GlobalCircuitInput, QueryCircuitInput, RevelationCircuitInput, SqlReturn, SqlType,
        },
    },
    proof_storage::{ProofKey, ProofStorage},
    table::Table,
    TestContext,
};

use super::QueryCooking;

pub(crate) async fn prove_query<'a>(
    mut parsed: Query,
    table_hash: &MetadataHash,
    planner: &mut QueryPlanner<'a>,
    results: Vec<PgSqlRow>,
) -> Result<()> {
    let mut exec_query = generate_query_execution_with_keys(&mut parsed, &planner.settings)?;
    let query_params = exec_query.convert_placeholders(&planner.query.placeholders);
    let res = planner
        .table
        .execute_row_query(
            &exec_query
                .normalize_placeholder_names()
                .to_pgsql_string_with_placeholder(),
            &query_params,
        )
        .await?;
    let matching_rows = res
        .iter()
        .map(|row| {
            let key = RowTreeKey::from_bytea(row.try_get::<_, &[u8]>(0)?.to_vec());
            let epoch = row.try_get::<_, Epoch>(1)?;
            // all the other items are query results
            let result = (2..row.len())
                .filter_map(|i| {
                    SqlType::Numeric.extract(&row, i).map(|res| match res {
                        SqlReturn::Numeric(uint) => uint,
                    })
                })
                .collect_vec();
            Ok((key, epoch, result))
        })
        .collect::<Result<Vec<_>>>()?;
    // compute input for each matching row
    let row_tree_info = RowInfo {
        satisfiying_rows: matching_rows
            .iter()
            .map(|(key, _, _)| key)
            .cloned()
            .collect(),
        tree: &planner.table.row,
    };
    let index_tree_info = IndexInfo {
        bounds: (planner.query.min_block, planner.query.max_block),
        tree: &planner.table.index,
    };
    let current_epoch = index_tree_info.tree.current_epoch();
    let mut matching_rows_input = vec![];
    for (key, epoch, result) in matching_rows.into_iter() {
        let row_proof = prove_single_row(
            planner.ctx,
            &row_tree_info,
            &planner.columns,
            epoch as BlockPrimaryIndex,
            &key,
            &planner.pis,
            &planner.query,
        )
        .await?;
        let (row_node_info, _, _) = get_node_info(&row_tree_info, &key, epoch).await;
        let (row_tree_path, row_tree_siblings) = get_path_info(&key, &row_tree_info, epoch).await?;
        let index_node_key = epoch as BlockPrimaryIndex;
        let (index_node_info, _, _) =
            get_node_info(&index_tree_info, &index_node_key, current_epoch).await;
        let (index_tree_path, index_tree_siblings) =
            get_path_info(&index_node_key, &index_tree_info, current_epoch).await?;
        let path = RowPath::new(
            row_node_info,
            row_tree_path,
            row_tree_siblings,
            index_node_info,
            index_tree_path,
            index_tree_siblings,
        );
        matching_rows_input.push(MatchingRow::new(row_proof, path, result));
    }
    // load the preprocessing proof at the same epoch
    let indexing_proof = {
        let pk = ProofKey::IVC(current_epoch as BlockPrimaryIndex);
        planner.ctx.storage.get_proof_exact(&pk)?
    };
    let pis_hash = QueryCircuitInput::ids_for_placeholder_hash(
        &planner.pis.predication_operations,
        &planner.pis.result,
        &planner.query.placeholders,
        &planner.pis.bounds,
    )?;
    let column_ids = ColumnIDs::from(&planner.table.columns);
    let num_matching_rows = matching_rows_input.len();
    let input = RevelationCircuitInput::new_revelation_unproven_offset(
        indexing_proof,
        matching_rows_input,
        &planner.pis.bounds,
        &planner.query.placeholders,
        pis_hash,
        &column_ids,
        &planner.pis.predication_operations,
        &planner.pis.result,
        planner.query.limit.unwrap(),
        planner.query.offset.unwrap(),
        false,
    )?;
    info!("Generating revelation proof");
    let final_proof = planner.ctx.run_query_proof(
        "querying::revelation",
        GlobalCircuitInput::Revelation(input),
    )?;
    // get `StaticPublicInputs`, i.e., the data about the query available only at query registration time,
    // to check the public inputs
    let pis = parsil::assembler::assemble_static(&parsed, planner.settings)?;
    check_final_outputs(
        final_proof,
        &planner.ctx,
        &planner.table,
        &planner.query,
        &pis,
        current_epoch,
        num_matching_rows,
        results,
        table_hash.clone(),
    )?;
    info!("Revelation done!");
    Ok(())
}

async fn get_path_info<K, V, T: TreeInfo<K, V>>(
    key: &K,
    tree_info: &T,
    epoch: Epoch,
) -> Result<(Vec<(NodeInfo, ChildPosition)>, Vec<Option<HashOutput>>)>
where
    K: Debug + Hash + Clone + Send + Sync + Eq,
    V: NodePayload + Send + Sync + LagrangeNode + Clone,
{
    let mut tree_path = vec![];
    let mut siblings = vec![];
    let (mut node_ctx, mut node_payload) = tree_info
        .fetch_ctx_and_payload_at(epoch, key)
        .await
        .ok_or(Error::msg(format!("Node not found for key {:?}", key)))?;
    let mut previous_node_hash = node_payload.hash();
    let mut previous_node_key = key.clone();
    while node_ctx.parent.is_some() {
        let parent_key = node_ctx.parent.unwrap();
        (node_ctx, node_payload) = tree_info
            .fetch_ctx_and_payload_at(epoch, &parent_key)
            .await
            .ok_or(Error::msg(format!(
                "Node not found for key {:?}",
                parent_key
            )))?;
        let child_pos = node_ctx
            .iter_children()
            .find_position(|child| child.is_some() && child.unwrap() == &previous_node_key);
        let is_left_child = child_pos.unwrap().0 == 0; // unwrap is safe
        let (left_child_hash, right_child_hash) = if is_left_child {
            (
                Some(previous_node_hash),
                match node_ctx.right {
                    Some(k) => {
                        let (_, payload) = tree_info
                            .fetch_ctx_and_payload_at(epoch, &k)
                            .await
                            .ok_or(Error::msg(format!("Node not found for key {:?}", k)))?;
                        Some(payload.hash())
                    }
                    None => None,
                },
            )
        } else {
            (
                match node_ctx.left {
                    Some(k) => {
                        let (_, payload) = tree_info
                            .fetch_ctx_and_payload_at(epoch, &k)
                            .await
                            .ok_or(Error::msg(format!("Node not found for key {:?}", k)))?;
                        Some(payload.hash())
                    }
                    None => None,
                },
                Some(previous_node_hash),
            )
        };
        let node_info = NodeInfo::new(
            &node_payload.embedded_hash(),
            left_child_hash.as_ref(),
            right_child_hash.as_ref(),
            node_payload.value(),
            node_payload.min(),
            node_payload.max(),
        );
        tree_path.push((
            node_info,
            if is_left_child {
                ChildPosition::Left
            } else {
                ChildPosition::Right
            },
        ));
        siblings.push(if is_left_child {
            right_child_hash
        } else {
            left_child_hash
        });
        previous_node_hash = node_payload.hash();
        previous_node_key = parent_key;
    }

    Ok((tree_path, siblings))
}

/// Cook a query where the number of matching rows is the same as the maximum number of
/// outputs allowed
pub(crate) async fn cook_query_with_max_num_matching_rows(table: &Table) -> Result<QueryCooking> {
    let (longest_key, (min_block, max_block)) = find_longest_lived_key(table, false).await?;
    let key_value = hex::encode(longest_key.value.to_be_bytes_trimmed_vec());
    info!(
        "Longest sequence is for key {longest_key:?} -> from block {:?} to  {:?}, hex -> {}",
        min_block, max_block, key_value
    );
    // now we can fetch the key that we want
    let key_column = table.columns.secondary.name.clone();
    // Assuming this is mapping with only two columns !
    let value_column = &table.columns.rest[0].name;
    let table_name = &table.public_name;

    let added_placeholder = U256::from(42);

    let placeholders = Placeholders::from((
        vec![(PlaceholderId::Generic(1), added_placeholder)],
        U256::from(min_block),
        U256::from(max_block),
    ));

    let limit = MAX_NUM_OUTPUTS;
    let offset = 0;

    let query_str = format!(
        "SELECT {BLOCK_COLUMN_NAME}, {value_column} + $1
                FROM {table_name}
                WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER}
                AND {key_column} = '0x{key_value}'
                LIMIT {limit} OFFSET {offset};"
    );
    Ok(QueryCooking {
        min_block: min_block as BlockPrimaryIndex,
        max_block: max_block as BlockPrimaryIndex,
        query: query_str,
        placeholders,
        limit: Some(limit as u64),
        offset: Some(offset),
    })
}

pub(crate) async fn cook_query_with_matching_rows(table: &Table) -> Result<QueryCooking> {
    let (longest_key, (min_block, max_block)) = find_longest_lived_key(table, false).await?;
    let key_value = hex::encode(longest_key.value.to_be_bytes_trimmed_vec());
    info!(
        "Longest sequence is for key {longest_key:?} -> from block {:?} to  {:?}, hex -> {}",
        min_block, max_block, key_value
    );
    // now we can fetch the key that we want
    let key_column = table.columns.secondary.name.clone();
    // Assuming this is mapping with only two columns !
    let value_column = &table.columns.rest[0].name;
    let table_name = &table.public_name;

    let added_placeholder = U256::from(42);

    let placeholders = Placeholders::from((
        vec![(PlaceholderId::Generic(1), added_placeholder)],
        U256::from(min_block),
        U256::from(max_block),
    ));

    let limit = (MAX_NUM_OUTPUTS - 2).min(1);
    let offset = max_block - min_block + 1 - limit; // get the matching rows in the last blocks

    let query_str = format!(
        "SELECT {BLOCK_COLUMN_NAME}, {value_column} + $1
                FROM {table_name}
                WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER}
                AND {key_column} = '0x{key_value}'
                LIMIT {limit} OFFSET {offset};"
    );
    Ok(QueryCooking {
        min_block: min_block as BlockPrimaryIndex,
        max_block: max_block as BlockPrimaryIndex,
        query: query_str,
        placeholders,
        limit: Some(limit as u64),
        offset: Some(offset as u64),
    })
}

/// Cook a query where the offset is big enough to have no matching rows
pub(crate) async fn cook_query_too_big_offset(table: &Table) -> Result<QueryCooking> {
    let (longest_key, (min_block, max_block)) = find_longest_lived_key(table, false).await?;
    let key_value = hex::encode(longest_key.value.to_be_bytes_trimmed_vec());
    info!(
        "Longest sequence is for key {longest_key:?} -> from block {:?} to  {:?}, hex -> {}",
        min_block, max_block, key_value
    );
    // now we can fetch the key that we want
    let key_column = table.columns.secondary.name.clone();
    // Assuming this is mapping with only two columns !
    let value_column = &table.columns.rest[0].name;
    let table_name = &table.public_name;

    let added_placeholder = U256::from(42);

    let placeholders = Placeholders::from((
        vec![(PlaceholderId::Generic(1), added_placeholder)],
        U256::from(min_block),
        U256::from(max_block),
    ));

    let limit = MAX_NUM_OUTPUTS;
    let offset = 100;

    let query_str = format!(
        "SELECT {BLOCK_COLUMN_NAME}, {value_column} + $1
                FROM {table_name}
                WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER}
                AND {key_column} = '0x{key_value}'
                LIMIT {limit} OFFSET {offset};"
    );
    Ok(QueryCooking {
        min_block: min_block as BlockPrimaryIndex,
        max_block: max_block as BlockPrimaryIndex,
        query: query_str,
        placeholders,
        limit: Some(limit as u64),
        offset: Some(offset),
    })
}

pub(crate) async fn cook_query_no_matching_rows(table: &Table) -> Result<QueryCooking> {
    let initial_epoch = table.index.initial_epoch();
    let current_epoch = table.index.current_epoch();
    let min_block = initial_epoch as BlockPrimaryIndex;
    let max_block = current_epoch as BlockPrimaryIndex;

    let key_column = table.columns.secondary.name.clone();
    // Assuming this is mapping with only two columns !
    let value_column = &table.columns.rest[0].name;
    let table_name = &table.public_name;

    let key_value = U256::from(1234567890); // dummy value

    let added_placeholder = U256::from(42);

    let placeholders = Placeholders::from((
        vec![
            (PlaceholderId::Generic(1), key_value),
            (PlaceholderId::Generic(2), added_placeholder),
        ],
        U256::from(min_block),
        U256::from(max_block),
    ));

    let limit = MAX_NUM_OUTPUTS;
    let offset = 0;

    let query_str = format!(
        "SELECT {BLOCK_COLUMN_NAME}, {value_column} + $2
                FROM {table_name}
                WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER}
                AND {key_column} = $1
                LIMIT {limit} OFFSET {offset};"
    );
    Ok(QueryCooking {
        min_block: min_block as BlockPrimaryIndex,
        max_block: max_block as BlockPrimaryIndex,
        query: query_str,
        placeholders,
        limit: Some(limit as u64),
        offset: Some(offset),
    })
}

pub(crate) async fn cook_query_with_distinct(table: &Table) -> Result<QueryCooking> {
    let (longest_key, (min_block, max_block)) = find_longest_lived_key(table, false).await?;
    let key_value = hex::encode(longest_key.value.to_be_bytes_trimmed_vec());
    info!(
        "Longest sequence is for key {longest_key:?} -> from block {:?} to  {:?}, hex -> {}",
        min_block, max_block, key_value
    );
    // now we can fetch the key that we want
    let key_column = table.columns.secondary.name.clone();
    // Assuming this is mapping with only two columns !
    let value_column = &table.columns.rest[0].name;
    let table_name = &table.public_name;

    let added_placeholder = U256::from(42);

    let placeholders = Placeholders::from((
        vec![(PlaceholderId::Generic(1), added_placeholder)],
        U256::from(min_block),
        U256::from(max_block),
    ));

    let limit = MAX_NUM_OUTPUTS;
    let offset = 0;

    let query_str = format!(
        "SELECT DISTINCT {value_column} + $1
                FROM {table_name}
                WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER}
                AND {key_column} = '0x{key_value}'
                LIMIT {limit} OFFSET {offset};"
    );
    Ok(QueryCooking {
        min_block: min_block as BlockPrimaryIndex,
        max_block: max_block as BlockPrimaryIndex,
        query: query_str,
        placeholders,
        limit: Some(limit as u64),
        offset: Some(offset),
    })
}

pub(crate) async fn cook_query_with_wildcard(
    table: &Table,
    distinct: bool,
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
    let value_column = &table.columns.rest[0].name;
    let table_name = &table.public_name;

    let added_placeholder = U256::from(42);

    let placeholders = Placeholders::from((
        vec![(PlaceholderId::Generic(1), added_placeholder)],
        U256::from(min_block),
        U256::from(max_block),
    ));

    let limit = MAX_NUM_OUTPUTS;
    let offset = 0;

    let query_str = if distinct {
        format!(
            "SELECT DISTINCT *, {value_column} + $1
                    FROM {table_name}
                    WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                    AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER}
                    AND {key_column} = '0x{key_value}'
                    LIMIT {limit} OFFSET {offset};"
        )
    } else {
        format!(
            "SELECT *, {value_column} + $1
                    FROM {table_name}
                    WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                    AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER}
                    AND {key_column} = '0x{key_value}'
                    LIMIT {limit} OFFSET {offset};"
        )
    };
    Ok(QueryCooking {
        min_block: min_block as BlockPrimaryIndex,
        max_block: max_block as BlockPrimaryIndex,
        query: query_str,
        placeholders,
        limit: Some(limit as u64),
        offset: Some(offset),
    })
}

pub(crate) async fn cook_query_with_wildcard_no_distinct(table: &Table) -> Result<QueryCooking> {
    cook_query_with_wildcard(table, false).await
}

pub(crate) async fn cook_query_with_wildcard_and_distinct(table: &Table) -> Result<QueryCooking> {
    cook_query_with_wildcard(table, true).await
}
