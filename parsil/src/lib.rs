use anyhow::Result;
use symbols::ContextProvider;
pub use utils::parse_and_validate;
pub use utils::ParsilSettings;
pub use utils::PlaceholderSettings;
pub use utils::DEFAULT_MAX_BLOCK_PLACEHOLDER;
pub use utils::DEFAULT_MIN_BLOCK_PLACEHOLDER;

pub mod assembler;
pub mod bracketer;
pub mod errors;
pub mod executor;
mod expand;
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
