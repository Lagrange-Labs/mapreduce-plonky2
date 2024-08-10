use plonky2::field::types::Field;
use std::{collections::HashMap, iter::once};

use crate::common::{
    cases::indexing::BLOCK_COLUMN_NAME, proof_storage::ProofKey, rowtree::MerkleRowTree,
};

use super::super::{context::TestContext, proof_storage::ProofStorage, table::Table};
use alloy::{primitives::U256, rpc::types::Block};
use anyhow::{Context, Result};
use futures::{stream, StreamExt};
use itertools::Itertools;
use log::{debug, info};
use mp2_common::{array::ToField, F};
use mp2_v1::{
    indexing::{
        block::BlockPrimaryIndex,
        row::{Row, RowTreeKey},
    },
    values_extraction::identifier_block_column,
};
use parsil::{resolve::CircuitPis, symbols::ContextProvider};
use ryhope::{
    storage::{pgsql::ToFromBytea, RoEpochKvStorage},
    Epoch,
};
use sqlparser::ast::Query;
use tokio_postgres::Row as PsqlRow;
use verifiable_db::query::{
    self,
    aggregation::QueryBounds,
    universal_circuit::universal_circuit_inputs::{ColumnCell, PlaceholderId},
};

pub const NUM_COLUMNS: usize = 3;
pub const MAX_NUM_COLUMNS: usize = 20;
pub const MAX_NUM_PREDICATE_OPS: usize = 20;
pub const MAX_NUM_RESULT_OPS: usize = 20;
pub const MAX_NUM_RESULTS: usize = 10;

pub type CircuitInput = query::api::CircuitInput<
    MAX_NUM_COLUMNS,
    MAX_NUM_PREDICATE_OPS,
    MAX_NUM_RESULT_OPS,
    MAX_NUM_RESULTS,
>;

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
    let query_info = cook_query(table).await?;
    info!("QUERY on the testcase: {}", query_info.query);
    let parsed = parsil::prepare(&query_info.query)?;
    println!("QUERY table columns -> {:?}", table.columns.to_zkcolumns());

    // the query to use to actually get the outputs expected
    let exec_query = parsil::executor::generate_query_execution(&parsed, table)?;
    let res = table
        .execute_row_query(
            &exec_query.to_string(),
            query_info.min_block,
            query_info.max_block,
        )
        .await?;
    info!(
        "Found {} results from query {}",
        res.len(),
        exec_query.to_string()
    );
    print_vec_sql_rows(&res, SqlType::Numeric);
    // the query to use to fetch all the rows keys involved in the result tree.
    let pis = parsil::resolve::resolve(&parsed, table)?;
    prove_query(ctx, table, query_info, parsed, pis)
        .await
        .expect("unable to run universal query proof");
    Ok(())
}

/// Execute a query to know all the touched rows, and then call the universal circuit on all rows
async fn prove_query(
    ctx: &mut TestContext,
    table: &Table,
    query: QueryCooking,
    parsed: Query,
    pis: CircuitPis,
) -> Result<()> {
    let rows_query = parsil::executor::generate_query_keys(&parsed, table)?;
    let all_touched_rows = table
        .execute_row_query(&rows_query.to_string(), query.min_block, query.max_block)
        .await?;
    info!(
        "Found {} ROW KEYS to process during proving time",
        all_touched_rows.len()
    );
    let touched_rows: HashMap<BlockPrimaryIndex, RowTreeKey> = all_touched_rows
        .into_iter()
        .map(|r| {
            let row_key = r
                .get::<_, Option<Vec<u8>>>(0)
                .map(RowTreeKey::from_bytea)
                .context("unable to parse row key tree")?;
            let block: Epoch = r.get::<_, i64>(1);
            Ok((block as BlockPrimaryIndex, row_key))
        })
        .collect::<Result<_>>()?;
    for (epoch, row_key) in &touched_rows {
        // 1. Get the all the cells including primary and secondary index
        let (row_ctx, row_payload) = table
            .row
            .fetch_with_context_at(row_key, *epoch as Epoch)
            .await;
        // API is gonna change on this but right now, we have to sort all the "rest" cells by index
        // in the tree, and put the primary one and secondary one in front
        let rest_cells = table
            .columns
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
        let primary_cell = ColumnCell::new(identifier_block_column(), U256::from(*epoch));
        let all_cells = once(primary_cell)
            .chain(once(secondary_cell))
            .chain(rest_cells)
            .collect::<Vec<_>>();
        // 2. create input
        let input = CircuitInput::new_universal_circuit(
            &all_cells,
            &pis.predication_operations,
            &pis.result,
            &query.placeholders,
            row_ctx.is_leaf(),
            &query.bounds,
        )
        .expect("unable to create universal query circuit inputs");
        // 3. run proof if not ran already
        let proof_key = ProofKey::QueryUniversal((*epoch, row_key.clone()));
        if ctx.storage.get_proof_exact(&proof_key).is_err() {
            let proof = ctx.run_query_proof(input)?;
            ctx.storage.store_proof(proof_key, proof)?;
        }
    }
    Ok(())
}

struct QueryCooking {
    query: String,
    placeholders: HashMap<PlaceholderId, U256>,
    bounds: QueryBounds,
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
    for epoch in (1..=max).rev() {
        let rows = collect_all_at(&table.row, epoch).await?;
        debug!(
            "Collecting {} rows at epoch {} (rows_keys {:?})",
            rows.len(),
            epoch,
            rows.iter().map(|r| r.k.value).collect::<Vec<_>>()
        );
        for row in rows {
            let epochs = all_table.entry(row.k.clone()).or_insert(Vec::new());
            epochs.push(epoch);
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
    info!(
        "Longest sequence is for key {longest_key:?} -> sequence of {:?} (sequence:  {:?})",
        find_longest_consecutive_sequence(epochs.clone()),
        epochs,
    );
    // now we can fetch the key that we want
    let key_value = hex::encode(longest_key.value.to_be_bytes_trimmed_vec());
    let key_column = table.columns.secondary.name.clone();
    // Assuming this is mapping with only two columns !
    let value_column = table.columns.rest[0].name.clone();
    let table_name = table.row_table_name();
    // we set the block bounds
    let (longest_sequence, starting) = find_longest_consecutive_sequence(epochs.to_vec());
    // TODO: careful about off by one error. -1 because tree epoch starts at 1
    let min_block = starting as u64 + table.genesis_block - 1;
    let max_block = min_block + longest_sequence as u64;
    // primary_min_placeholder = ".."
    // primary_max_placeholder = ".."
    // Address == $3 --> placeholders.hashmap empty, put in query bounds secondary_min = secondary_max = "$3""
    // adddress IN ($3,$4,$5) -> min "$3" max "$5", put in query bounds
    // secondary_min = $3, and secondary_max = "$5", placeholders.put(generic, "$4")
    // placeholders.generic(("generic", $3)),(generic,$4), (generic,$5))
    // WHERE price > $3 AND price < $4 <--
    let placeholders = HashMap::from([
        (F::from_canonical_usize(1), U256::from(min_block)),
        (F::from_canonical_usize(2), U256::from(max_block)),
    ]);
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
    let bounds = QueryBounds::new(
        U256::from(min_block),
        U256::from(max_block),
        Some(longest_key.value),
        Some(longest_key.value),
    );
    let query_str = format!(
        "SELECT AVG({value_column}) 
                FROM {table_name} 
                WHERE {BLOCK_COLUMN_NAME} > $1 
                AND {BLOCK_COLUMN_NAME} < $2 
                AND {key_column} = '0x{key_value}';"
    );
    Ok(QueryCooking {
        bounds,
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
