use anyhow::Context;
use anyhow::Result;
use sqlparser::ast::Query;
use symbols::ContextProvider;
pub use utils::parse_and_validate;
pub use utils::ParsilSettings;
pub use utils::PlaceholderSettings;
pub use utils::DEFAULT_MAX_BLOCK_PLACEHOLDER;
pub use utils::DEFAULT_MIN_BLOCK_PLACEHOLDER;
use verifiable_db::query::aggregation::QueryBounds;

pub mod assembler;
pub mod bracketer;
pub mod errors;
pub mod executor;
mod expand;
pub mod isolator;
mod parser;
mod placeholders;
pub mod symbols;
#[cfg(test)]
mod tests;
mod utils;
mod validate;
mod visitor;

/// Given an SQL query textual representation, ensure it satisfies all the
/// criterion imposed by the current proving architecture.
pub fn check<C: ContextProvider>(query: &str, settings: &ParsilSettings<C>) -> Result<()> {
    parse_and_validate(query, settings).map(|_| ())
}

/// Generate a SQL queries to fetch the keys and blocks where the conditions on
/// the primary (and potentially secondary) index is satisfied.
pub fn keys_in_index_boundaries<C: ContextProvider>(
    query: &str,
    settings: &ParsilSettings<C>,
    bounds: &QueryBounds,
) -> Result<Query> {
    let mut q = parse_and_validate(query, settings).context("while validating query")?;
    q = isolator::isolate(&q, settings, bounds).context("while isolating indices")?;
    q = executor::generate_query_keys(&mut q, settings).context("while generating query keys")?;
    Ok(q)
}
