use super::{context::TestContext, proof_storage::ProofStorage, table::Table};
use anyhow::Result;

pub fn run_query<P: ProofStorage>(ctx: &TestContext<P>, table: &Table, query: &str) -> Result<()> {
    let parsed = parsil::prepare(query)?;
    Ok(())
}
