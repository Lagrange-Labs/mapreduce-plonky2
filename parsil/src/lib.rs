use anyhow::Result;
use sqlparser::ast::Query;

mod execute;
mod expand;
mod inject;
mod parser;
mod symbols;
#[cfg(test)]
mod tests;
mod validate;

/// Given an SQL `query`:
///  - parse it;
///  - ensure that it validates Lagrange requirements;
///  - expand it into base operations processable by the proof system.
///
/// Return an error if any of these steps failed.
pub fn prepare(query: &str) -> Result<Query> {
    let mut query = parser::parse(query)?;
    validate::validate(&query)?;
    expand::expand_query(&mut query);
    Ok(query)
}