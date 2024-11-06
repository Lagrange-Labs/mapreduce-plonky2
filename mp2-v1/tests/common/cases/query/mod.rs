use aggregated_queries::{
    cook_query_between_blocks, cook_query_no_matching_entries,
    cook_query_non_matching_entries_some_blocks, cook_query_partial_block_range,
    cook_query_secondary_index_placeholder, cook_query_unique_secondary_index,
    prove_query as prove_aggregation_query,
};
use alloy::primitives::U256;
use anyhow::{Context, Result};
use itertools::Itertools;
use log::info;
use mp2_v1::{api::MetadataHash, indexing::block::BlockPrimaryIndex};
use parsil::{parse_and_validate, utils::ParsilSettingsBuilder, PlaceholderSettings};
use simple_select_queries::{
    cook_query_no_matching_rows, cook_query_too_big_offset, cook_query_with_distinct,
    cook_query_with_matching_rows, cook_query_with_max_num_matching_rows,
    cook_query_with_wildcard_and_distinct, cook_query_with_wildcard_no_distinct,
    prove_query as prove_no_aggregation_query,
};
use tokio_postgres::Row as PsqlRow;
use verifiable_db::query::{
    computational_hash_ids::Output, universal_circuit::universal_circuit_inputs::Placeholders,
};

use crate::common::{cases::planner::QueryPlanner, table::Table, TableInfo, TestContext};

use super::table_source::TableSource;

pub mod aggregated_queries;
pub mod simple_select_queries;

pub const MAX_NUM_RESULT_OPS: usize = 20;
pub const MAX_NUM_OUTPUTS: usize = 3;
pub const MAX_NUM_ITEMS_PER_OUTPUT: usize = 5;
pub const MAX_NUM_PLACEHOLDERS: usize = 10;
pub const MAX_NUM_COLUMNS: usize = 20;
pub const MAX_NUM_PREDICATE_OPS: usize = 20;
pub const ROW_TREE_MAX_DEPTH: usize = 10;
pub const INDEX_TREE_MAX_DEPTH: usize = 15;

pub type GlobalCircuitInput = verifiable_db::api::QueryCircuitInput<
    ROW_TREE_MAX_DEPTH,
    INDEX_TREE_MAX_DEPTH,
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
    ROW_TREE_MAX_DEPTH,
    INDEX_TREE_MAX_DEPTH,
    MAX_NUM_COLUMNS,
    MAX_NUM_PREDICATE_OPS,
    MAX_NUM_RESULT_OPS,
    MAX_NUM_OUTPUTS,
    MAX_NUM_ITEMS_PER_OUTPUT,
    MAX_NUM_PLACEHOLDERS,
>;

#[derive(Clone, Debug)]
pub struct QueryCooking {
    pub(crate) query: String,
    pub(crate) placeholders: Placeholders,
    pub(crate) min_block: BlockPrimaryIndex,
    pub(crate) max_block: BlockPrimaryIndex,
    pub(crate) limit: Option<u64>,
    pub(crate) offset: Option<u64>,
}

pub async fn test_query(ctx: &mut TestContext, table: Table, t: TableInfo) -> Result<()> {
    match &t.source {
        TableSource::Mapping(_) | TableSource::Merge(_) => query_mapping(ctx, &table, &t).await?,
        _ => unimplemented!("yet"),
    }
    Ok(())
}

async fn query_mapping(ctx: &mut TestContext, table: &Table, info: &TableInfo) -> Result<()> {
    let table_hash = info.metadata_hash();
    let query_info = cook_query_between_blocks(table, info).await?;
    test_query_mapping(ctx, table, query_info, &table_hash).await?;
    let query_info = cook_query_unique_secondary_index(table, info).await?;
    test_query_mapping(ctx, table, query_info, &table_hash).await?;
    //// cook query with custom placeholders
    let query_info = cook_query_secondary_index_placeholder(table, info).await?;
    test_query_mapping(ctx, table, query_info, &table_hash).await?;
    // cook query filtering over a secondary index value not valid in all the blocks
    let query_info = cook_query_non_matching_entries_some_blocks(table, info).await?;
    test_query_mapping(ctx, table, query_info, &table_hash).await?;
    // cook query with no valid blocks
    let query_info = cook_query_no_matching_entries(table, info).await?;
    test_query_mapping(ctx, table, query_info, &table_hash).await?;
    // cook query with block query range partially overlapping with blocks in the DB
    let query_info = cook_query_partial_block_range(table, info).await?;
    test_query_mapping(ctx, table, query_info, &table_hash).await?;
    // cook simple no aggregation query with matching rows
    let query_info = cook_query_with_matching_rows(table, info).await?;
    test_query_mapping(ctx, table, query_info, &table_hash).await?;
    // cook simple no aggregation query with maximum number of matching rows
    let query_info = cook_query_with_max_num_matching_rows(table, info).await?;
    test_query_mapping(ctx, table, query_info, &table_hash).await?;
    let query_info = cook_query_no_matching_rows(table, info).await?;
    test_query_mapping(ctx, table, query_info, &table_hash).await?;
    let query_info = cook_query_too_big_offset(table, info).await?;
    test_query_mapping(ctx, table, query_info, &table_hash).await?;
    let query_info = cook_query_with_distinct(table, info).await?;
    test_query_mapping(ctx, table, query_info, &table_hash).await?;
    // test queries with wilcards only if the number of columns of the table
    // doesn't make the number of items returned for each row bigger than
    // the maximum allowed value (i.e, MAX_NUM_ITEMS_PER_OUTPUT), as
    // otherwise query validation on Parsil will fail
    let num_output_items_wildcard_queries = info.columns.non_indexed_columns().len()
    + 2 // primary and secondary indexed columns
    + 1 // there is an additional item besides columns of the tables in SELECT
    ;
    if num_output_items_wildcard_queries <= MAX_NUM_ITEMS_PER_OUTPUT {
        let query_info = cook_query_with_wildcard_no_distinct(table, info).await?;
        test_query_mapping(ctx, table, query_info, &table_hash).await?;
        let query_info = cook_query_with_wildcard_and_distinct(table, info).await?;
        test_query_mapping(ctx, table, query_info, &table_hash).await?;
    }
    Ok(())
}

/// Run a test query on the mapping table such as created during the indexing phase
async fn test_query_mapping(
    ctx: &mut TestContext,
    table: &Table,
    query_info: QueryCooking,
    table_hash: &MetadataHash,
) -> Result<()> {
    let settings = {
        let mut builder = ParsilSettingsBuilder::default()
            .context(table)
            .placeholders(PlaceholderSettings::with_freestanding(
                MAX_NUM_PLACEHOLDERS - 2,
            ));
        if let Some(limit) = query_info.limit {
            builder = builder.limit(limit);
        }
        if let Some(offset) = query_info.offset {
            builder = builder.offset(offset)
        }
        builder.build().unwrap()
    };

    info!("QUERY on the testcase: {}", query_info.query);
    let mut parsed = parse_and_validate(&query_info.query, &settings)?;
    println!("QUERY table columns -> {:?}", table.columns.to_zkcolumns());
    info!(
        "BOUNDS found on query: min {}, max {} - table.genesis_block {}",
        query_info.min_block, query_info.max_block, table.genesis_block
    );

    // the query to use to actually get the outputs expected
    let mut exec_query = parsil::executor::generate_query_execution(&mut parsed, &settings)?;
    let query_params = exec_query.convert_placeholders(&query_info.placeholders);
    let res = table
        .execute_row_query(
            &exec_query
                .normalize_placeholder_names()
                .to_pgsql_string_with_placeholder(),
            &query_params,
        )
        .await?;
    let res = if is_empty_result(&res, SqlType::Numeric) {
        vec![] // empty results, but Postgres still return 1 row
    } else {
        res
    };
    info!(
        "Found {} results from query {}",
        res.len(),
        exec_query.query.to_display()
    );
    print_vec_sql_rows(&res, SqlType::Numeric);

    let pis = parsil::assembler::assemble_dynamic(&parsed, &settings, &query_info.placeholders)
        .context("while assembling PIs")?;

    let mut planner = QueryPlanner {
        query: query_info.clone(),
        pis: &pis,
        ctx,
        settings: &settings,
        table,
        columns: table.columns.clone(),
    };

    match pis.result.query_variant() {
        Output::Aggregation => {
            prove_aggregation_query(
                ctx,
                table,
                query_info,
                parsed,
                &settings,
                res,
                table_hash.clone(),
                pis,
            )
            .await
        }
        Output::NoAggregation => {
            prove_no_aggregation_query(parsed, &table_hash, &mut planner, res).await
        }
    }
}

pub enum SqlType {
    Numeric,
}

impl SqlType {
    pub fn extract(&self, row: &PsqlRow, idx: usize) -> Option<SqlReturn> {
        match self {
            SqlType::Numeric => row
                .get::<_, Option<U256>>(idx)
                .map(|num| SqlReturn::Numeric(num)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum SqlReturn {
    Numeric(U256),
}

fn is_empty_result(rows: &[PsqlRow], types: SqlType) -> bool {
    if rows.len() == 0 {
        return true;
    }
    let columns = rows.first().as_ref().unwrap().columns();
    if columns.len() == 0 {
        return true;
    }
    for row in rows {
        if types.extract(row, 0).is_none() {
            return true;
        }
    }
    false
}

fn print_vec_sql_rows(rows: &[PsqlRow], types: SqlType) {
    if rows.len() == 0 {
        println!("no rows returned");
        return;
    }
    let columns = rows.first().as_ref().unwrap().columns();
    println!(
        "{:?}",
        columns.iter().map(|c| c.name().to_string()).join(" | ")
    );
    for row in rows {
        println!(
            "{:?}",
            columns
                .iter()
                .enumerate()
                .map(|(i, _)| format!("{:?}", types.extract(row, i)))
                .join(" | ")
        );
    }
}
