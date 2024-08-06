use anyhow::*;
use sqlparser::ast::Query;

use crate::symbols::RootContextProvider;

pub(crate) fn execute<C: RootContextProvider>(mut query: Query, ctx: C) -> Result<Query> {
    Ok(query)
}
