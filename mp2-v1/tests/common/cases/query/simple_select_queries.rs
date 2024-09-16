use anyhow::Result;
use mp2_v1::api::MetadataHash;
use parsil::{ParsilSettings, PlaceholderSettings};

use crate::common::{cases::TableSourceSlot, table::Table, TableInfo, TestContext};

use super::{query_setup, QueryCooking, MAX_NUM_PLACEHOLDERS};



pub async fn test_query(ctx: &mut TestContext, table: Table, t: TableInfo) -> Result<()> {
    match &t.source {
        TableSourceSlot::Mapping(_) => query_mapping(ctx, &table, t.metadata_hash()).await?,
        _ => unimplemented!("yet"),
    }
    Ok(())
}

async fn query_mapping(
    ctx: &mut TestContext,
    table: &Table,
    table_hash: MetadataHash,
) -> Result<()> {
    todo!()
}

/// Run a test query on the mapping table such as created during the indexing phase
async fn test_query_mapping(
    ctx: &mut TestContext,
    table: &Table,
    query_info: QueryCooking,
    table_hash: &MetadataHash,
) -> Result<()> {
    let settings = ParsilSettings {
        context: table,
        placeholders: PlaceholderSettings::with_freestanding(MAX_NUM_PLACEHOLDERS - 2),
    };

    let setup_info = query_setup(&settings, ctx, table, &query_info).await?;

    Ok(())
}