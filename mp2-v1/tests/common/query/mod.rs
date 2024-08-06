use super::{context::TestContext, proof_storage::ProofStorage, table::Table};
use anyhow::Result;

pub fn run_query<'a, 'b, P: ProofStorage>(
    ctx: ContextProvider<'a, 'b, P>,
    query: &str,
) -> Result<()> {
    let parsed = parsil::prepare(query)?;
    Ok(())
}

pub struct ContextProvider<'a, 'b, P: ProofStorage> {
    pub table: &'a Table,
    pub ctx: &'b TestContext<P>,
}

impl<'a, 'b, P: ProofStorage> ContextProvider<'a, 'b, P> {
    pub fn new(table: &'a Table, ctx: &'b TestContext<P>) -> Self {
        Self { table, ctx }
    }
}
