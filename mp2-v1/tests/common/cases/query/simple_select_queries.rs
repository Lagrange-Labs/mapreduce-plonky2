use crate::common::{
    cases::{
        indexing::BLOCK_COLUMN_NAME,
        planner::{IndexInfo, QueryPlanner, RowInfo},
        query::{
            aggregated_queries::{
                check_final_outputs, find_longest_lived_key, get_node_info, prove_single_row,
            },
            GlobalCircuitInput, RevelationCircuitInput, SqlReturn, SqlType,
        },
    },
    proof_storage::{ProofKey, ProofStorage},
    table::Table,
    TableInfo,
};
use alloy::primitives::U256;
use anyhow::Result;
use itertools::Itertools;
use log::info;
use mp2_v1::{
    api::MetadataHash,
    indexing::{block::BlockPrimaryIndex, row::RowTreeKey},
    query::planner::{execute_row_query, get_path_info},
};
use parsil::{
    executor::generate_query_execution_with_keys, DEFAULT_MAX_BLOCK_PLACEHOLDER,
    DEFAULT_MIN_BLOCK_PLACEHOLDER,
};
use ryhope::{
    storage::{pgsql::ToFromBytea, RoEpochKvStorage},
    Epoch,
};
use sqlparser::ast::Query;
use tokio_postgres::Row as PgSqlRow;
use verifiable_db::{
    query::{
        computational_hash_ids::ColumnIDs,
        universal_circuit::universal_circuit_inputs::{PlaceholderId, Placeholders},
    },
    revelation::{api::MatchingRow, RowPath},
    test_utils::MAX_NUM_OUTPUTS,
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
    let res = execute_row_query(
        &planner.table.db_pool,
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
        let (row_tree_path, row_tree_siblings) =
            get_path_info(&row_tree_info.tree, &key, epoch).await?;
        let index_node_key = epoch as BlockPrimaryIndex;
        let (index_node_info, _, _) =
            get_node_info(&index_tree_info, &index_node_key, current_epoch).await;
        let (index_tree_path, index_tree_siblings) =
            get_path_info(&index_tree_info.tree, &index_node_key, current_epoch).await?;
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
    let column_ids = ColumnIDs::from(&planner.table.columns);
    let num_matching_rows = matching_rows_input.len();
    let input = RevelationCircuitInput::new_revelation_tabular(
        indexing_proof,
        matching_rows_input,
        &planner.pis.bounds,
        &planner.query.placeholders,
        &column_ids,
        &planner.pis.predication_operations,
        &planner.pis.result,
        planner.query.limit.unwrap(),
        planner.query.offset.unwrap(),
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

/// Cook a query where the number of matching rows is the same as the maximum number of
/// outputs allowed
pub(crate) async fn cook_query_with_max_num_matching_rows(
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

    let added_placeholder = U256::from(42);

    let placeholders = Placeholders::from((
        vec![(PlaceholderId::Generic(1), added_placeholder)],
        U256::from(min_block),
        U256::from(max_block),
    ));

    let limit = MAX_NUM_OUTPUTS as u32;
    let offset = 0;

    let query_str = format!(
        "SELECT {BLOCK_COLUMN_NAME}, {value_column} + $1
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
        limit: Some(limit),
        offset: Some(offset),
    })
}

pub(crate) async fn cook_query_with_matching_rows(
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

    let added_placeholder = U256::from(42);

    let placeholders = Placeholders::from((
        vec![(PlaceholderId::Generic(1), added_placeholder)],
        U256::from(min_block),
        U256::from(max_block),
    ));

    let limit: u32 = (MAX_NUM_OUTPUTS - 2).min(1).try_into().unwrap();
    let offset: u32 = (max_block - min_block + 1 - limit as usize)
        .try_into()
        .unwrap(); // get the matching rows in the last blocks

    let query_str = format!(
        "SELECT {BLOCK_COLUMN_NAME}, {value_column} + $1
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
        limit: Some(limit),
        offset: Some(offset),
    })
}

/// Cook a query where the offset is big enough to have no matching rows
pub(crate) async fn cook_query_too_big_offset(
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

    let added_placeholder = U256::from(42);

    let placeholders = Placeholders::from((
        vec![(PlaceholderId::Generic(1), added_placeholder)],
        U256::from(min_block),
        U256::from(max_block),
    ));

    let limit: u32 = MAX_NUM_OUTPUTS.try_into().unwrap();
    let offset = 100;

    let query_str = format!(
        "SELECT {BLOCK_COLUMN_NAME}, {value_column} + $1
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
        limit: Some(limit),
        offset: Some(offset),
    })
}

pub(crate) async fn cook_query_no_matching_rows(
    table: &Table,
    info: &TableInfo,
) -> Result<QueryCooking> {
    let initial_epoch = table.index.initial_epoch();
    let current_epoch = table.index.current_epoch();
    let min_block = initial_epoch as BlockPrimaryIndex;
    let max_block = current_epoch as BlockPrimaryIndex;

    let key_column = table.columns.secondary.name.clone();
    let value_column = &info.value_column;
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

    let limit: u32 = MAX_NUM_OUTPUTS.try_into().unwrap();
    let offset = 0;

    let query_str = format!(
        "SELECT {BLOCK_COLUMN_NAME}, {value_column} + $2
                FROM {table_name}
                WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER}
                AND {key_column} = $1;"
    );
    Ok(QueryCooking {
        min_block: min_block as BlockPrimaryIndex,
        max_block: max_block as BlockPrimaryIndex,
        query: query_str,
        placeholders,
        limit: Some(limit),
        offset: Some(offset),
    })
}

pub(crate) async fn cook_query_with_distinct(
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

    let added_placeholder = U256::from(42);

    let placeholders = Placeholders::from((
        vec![(PlaceholderId::Generic(1), added_placeholder)],
        U256::from(min_block),
        U256::from(max_block),
    ));

    let limit: u32 = MAX_NUM_OUTPUTS.try_into().unwrap();
    let offset = 0;

    let query_str = format!(
        "SELECT DISTINCT {value_column} + $1
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
        limit: Some(limit),
        offset: Some(offset),
    })
}

pub(crate) async fn cook_query_with_wildcard(
    table: &Table,
    distinct: bool,
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

    let added_placeholder = U256::from(42);

    let placeholders = Placeholders::from((
        vec![(PlaceholderId::Generic(1), added_placeholder)],
        U256::from(min_block),
        U256::from(max_block),
    ));

    let limit: u32 = MAX_NUM_OUTPUTS.try_into().unwrap();
    let offset = 0;

    let query_str = if distinct {
        format!(
            "SELECT DISTINCT *, {value_column} + $1
                    FROM {table_name}
                    WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                    AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER}
                    AND {key_column} = '0x{key_value}';"
        )
    } else {
        format!(
            "SELECT *, {value_column} + $1
                    FROM {table_name}
                    WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                    AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER}
                    AND {key_column} = '0x{key_value}';"
        )
    };
    Ok(QueryCooking {
        min_block: min_block as BlockPrimaryIndex,
        max_block: max_block as BlockPrimaryIndex,
        query: query_str,
        placeholders,
        limit: Some(limit),
        offset: Some(offset),
    })
}

pub(crate) async fn cook_query_with_wildcard_no_distinct(
    table: &Table,
    info: &TableInfo,
) -> Result<QueryCooking> {
    cook_query_with_wildcard(table, false, info).await
}

pub(crate) async fn cook_query_with_wildcard_and_distinct(
    table: &Table,
    info: &TableInfo,
) -> Result<QueryCooking> {
    cook_query_with_wildcard(table, true, info).await
}
