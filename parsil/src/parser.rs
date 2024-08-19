use anyhow::*;
use log::*;
use sqlparser::{
    ast::{Query, Statement},
    dialect::AnsiDialect,
    parser::Parser,
};

use crate::{symbols::ContextProvider, utils::ParsilSettings};

const DIALECT: AnsiDialect = AnsiDialect {};

pub fn parse<C: ContextProvider>(_settings: &ParsilSettings<C>, req: &str) -> Result<Query> {
    debug!("Parsing `{req}`");
    let mut parsed =
        Parser::parse_sql(&DIALECT, req).with_context(|| format!("trying to parse `{req}`"))?;

    ensure!(
        parsed.len() == 1,
        "expected 1 statement, found {}",
        parsed.len()
    );

    if let Statement::Query(ref mut query) = &mut parsed[0] {
        Ok(*query.clone())
    } else {
        bail!("expected query, found `{}`", parsed[0])
    }
}
