//! This module exposes some common queries, used in mandatory steps of the
//! pre-processing and query validation.

use crate::{keys_in_index_boundaries, symbols::ContextProvider, ParsilSettings};
use anyhow::*;
use ryhope::{tree::sbbst::NodeIdx, Epoch, EPOCH, KEY, VALID_FROM, VALID_UNTIL};
use verifiable_db::query::{
    universal_circuit::universal_circuit_inputs::Placeholders, utils::QueryBounds,
};

/// Return a query read to be injected in the wide lineage computation for the
/// index tree.
///
///  * execution_epoch: the epoch (block number) at which the query is executed;
///  * query_epoch_bounds: the min. and max. block numbers onto which the query
///    is executed.
pub fn core_keys_for_index_tree(
    execution_epoch: Epoch,
    query_epoch_bounds: (NodeIdx, NodeIdx),
) -> Result<String> {
    let (query_min_block, query_max_block) = query_epoch_bounds;
    ensure!(
        query_max_block as i64 <= execution_epoch,
        "query can not be executed in the past ({} < {})",
        execution_epoch,
        query_max_block
    );

    // Integer default to i32 in PgSQL, they must be cast to i64, a.k.a. BIGINT.
    Ok(format!(
        "SELECT {}::BIGINT as {EPOCH},
                generate_series(
                    GREATEST((SELECT MIN({VALID_FROM}))::BIGINT, {}::BIGINT),
                    LEAST((SELECT MAX({VALID_UNTIL}))::BIGINT, {}::BIGINT)) AS {KEY}",
        execution_epoch,
        query_min_block,
        query_max_block.min(
            execution_epoch
                .try_into()
                .with_context(|| format!("unable to convert {} to i64", execution_epoch))?
        )
    ))
}

/// Return a query read to be injected in the wide lineage computation for the
/// row tree.
///
///  * query: the zkQuery, as registered by the end user;
///  * settings: the Parsil settings used to parse & execute the query;
///  * bounds: the bounds on the prim. and sec. index for this execution of
///    the query;
///  * placeholders: the placeholders value for this execution of the query.
pub fn core_keys_for_row_tree<C: ContextProvider>(
    query: &str,
    settings: &ParsilSettings<C>,
    bounds: &QueryBounds,
    placeholders: &Placeholders,
) -> Result<String> {
    Ok(keys_in_index_boundaries(query, settings, bounds)
        .context("while computing core keys query from zkQuery")?
        .interpolate(settings, placeholders)
        .context("while injecting placeholder values in the core keys query")?
        .to_pgsql_string_no_placeholders())
}
