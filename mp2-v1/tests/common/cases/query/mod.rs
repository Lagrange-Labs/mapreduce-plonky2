use alloy::primitives::U256;
use anyhow::{Context, Result};
use itertools::Itertools;
use log::info;
use mp2_v1::indexing::block::BlockPrimaryIndex;
use parsil::{assembler::DynamicCircuitPis, parse_and_validate, ParsilSettings};
use sqlparser::ast::Query;
use tokio_postgres::Row as PsqlRow;
use verifiable_db::query::universal_circuit::universal_circuit_inputs::Placeholders;

use crate::common::{table::Table, TestContext};

pub mod aggregated_queries;
pub mod simple_select_queries;


pub const MAX_NUM_RESULT_OPS: usize = 20;
pub const MAX_NUM_RESULTS: usize = 10;
pub const MAX_NUM_OUTPUTS: usize = 3;
pub const MAX_NUM_ITEMS_PER_OUTPUT: usize = 5;
pub const MAX_NUM_PLACEHOLDERS: usize = 10;
pub const MAX_NUM_COLUMNS: usize = 20;
pub const MAX_NUM_PREDICATE_OPS: usize = 20;
pub const ROW_TREE_MAX_DEPTH: usize = 10;
pub const INDEX_TREE_MAX_DEPTH: usize = 15;

#[derive(Clone, Debug)]
pub struct QueryCooking {
    pub(crate) query: String,
    pub(crate) placeholders: Placeholders,
    pub(crate) min_block: BlockPrimaryIndex,
    pub(crate) max_block: BlockPrimaryIndex,
}
#[derive(Debug)]
/// Data structure containing all the data about the query computed
/// during the initial processing of the query
pub struct QuerySetup {
    parsed: Query,
    res: Vec<PsqlRow>,
    pis: DynamicCircuitPis,
}

pub(crate) async fn query_setup(
    settings: &ParsilSettings<&Table>,
    ctx: &mut TestContext,
    table: &Table,
    query_info: &QueryCooking,
) -> Result<QuerySetup> {
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

    Ok(
        QuerySetup {
            parsed,
            res,
            pis,
        }
    )
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
        println!("{:?}", types.extract(row, 0));
    }
}
