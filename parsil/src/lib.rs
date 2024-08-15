use anyhow::Result;
use sqlparser::ast::Query;
use utils::ParsingSettings;

pub mod errors;
pub mod executor;
mod expand;
mod parser;
pub mod resolve;
pub mod symbols;
#[cfg(test)]
mod tests;
mod utils;
mod validate;
mod visitor;

/// Given an SQL `query`:
///  - parse it;
///  - ensure that it validates Lagrange requirements;
///  - expand it into base operations processable by the proof system.
///
/// Return an error if any of these steps failed.
pub fn prepare(settings: ParsingSettings, query: &str) -> Result<Query> {
    let mut query = parser::parse(settings, query)?;
    expand::expand(&mut query);
    Ok(query)
}
