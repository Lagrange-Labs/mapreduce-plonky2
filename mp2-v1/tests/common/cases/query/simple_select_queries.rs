use alloy::primitives::U256;
use anyhow::Result;
use log::info;
use mp2_v1::{api::MetadataHash, indexing::block::BlockPrimaryIndex};
use parsil::{DEFAULT_MIN_BLOCK_PLACEHOLDER, DEFAULT_MAX_BLOCK_PLACEHOLDER};
use verifiable_db::{query::universal_circuit::universal_circuit_inputs::{PlaceholderId, Placeholders}, test_utils::MAX_NUM_OUTPUTS};

use crate::common::{cases::{query::aggregated_queries::find_longest_lived_key, indexing::BLOCK_COLUMN_NAME}, 
    table::Table, TestContext};

use super::QueryCooking;

pub(crate) async fn prove_query(
    ctx: &mut TestContext,
    table: &Table,
    query_info: QueryCooking,
    table_hash: &MetadataHash,
) -> Result<()> {
    Ok(())
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
    let max_block = min_block + 1;

    let added_placeholder = U256::from(42);

    let placeholders = Placeholders::from((
        vec![
            (PlaceholderId::Generic(1), added_placeholder),
        ],
        U256::from(min_block), 
        U256::from(max_block)
    ));

    let limit = MAX_NUM_OUTPUTS;
    let offset = 0;

    let query_str = format!(
        "SELECT {BLOCK_COLUMN_NAME}, {value_column} + S1
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