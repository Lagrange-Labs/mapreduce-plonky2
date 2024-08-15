use anyhow::Result;
use symbols::ContextProvider;
use utils::{parse_and_validate, ParsilSettings};

mod circuit;
pub mod errors;
mod executor;
mod expand;
mod parser;
mod placeholders;
mod symbols;
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
