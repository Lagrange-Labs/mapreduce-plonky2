use crate::common::{cases::indexing::BLOCK_COLUMN_NAME, rowtree::MerkleRowTree};

use super::{
    super::{context::TestContext, proof_storage::ProofStorage, table::Table},
    MappingValuesExtractionArgs, TableSourceSlot, TestCase,
};
use anyhow::Result;
use futures::{stream, StreamExt};
use hashbrown::HashMap;
use log::{debug, info};
use mp2_v1::indexing::{block::BlockPrimaryIndex, row::Row};
use parsil::symbols::ContextProvider;
use ryhope::{storage::RoEpochKvStorage, Epoch};

impl TestCase {
    pub async fn test_query<P: ProofStorage>(&self, ctx: &TestContext<P>) -> Result<()> {
        match self.source {
            TableSourceSlot::Mapping((ref map, _)) => query_mapping(&ctx, map, &self.table).await?,
            _ => unimplemented!("yet"),
        }
        Ok(())
    }
}
async fn query_mapping<P: ProofStorage>(
    ctx: &TestContext<P>,
    map: &MappingValuesExtractionArgs,
    table: &Table,
) -> Result<()> {
    let query = cook_query(ctx, map, table).await?;
    info!("QUERY on the testcase: {query}");
    let parsed = parsil::prepare(&query)?;
    let zktable = table.fetch_table(&table.name);
    info!(
        "table name {:?} => columns name {:?}",
        table.name,
        zktable.iter().map(|c| c.name.clone()).collect::<Vec<_>>()
    );
    let pis = parsil::resolve::resolve(&parsed, table)?;
    Ok(())
}

// cook up a SQL query on the secondary index. For that we just iterate on mapping keys and
// take the one that exist for most blocks
async fn cook_query<P: ProofStorage>(
    ctx: &TestContext<P>,
    map: &MappingValuesExtractionArgs,
    table: &Table,
) -> Result<String> {
    let mut all_table = HashMap::new();
    let max = table.row.current_epoch();
    for epoch in (1..=max).rev() {
        let rows = collect_all_at(&table.row, epoch).await?;
        info!(
            "Collecting {} rows at epoch {} (rows_keys {:?})",
            rows.len(),
            epoch,
            rows.iter().map(|r| r.k.value).collect::<Vec<_>>()
        );
        for row in rows {
            let epochs = all_table.entry(row.k.clone()).or_insert(Vec::new());
            epochs.push(epoch);
        }
    }
    // sort the epochs
    let all_table: HashMap<_, _> = all_table
        .into_iter()
        .map(|(k, mut epochs)| {
            epochs.sort_unstable();
            (k, epochs)
        })
        .collect();
    // find the longest running row
    let (longest_key, epochs) = all_table
        .iter()
        .max_by_key(|(k, epochs)| {
            // simplification here to start at first epoch where this row was. Otherwise need to do
            // longest consecutive sequence etc...
            let (l, start) = find_longest_consecutive_sequence(epochs.to_vec());
            info!("finding sequence of {l} blocks for key {k:?} (epochs {epochs:?}");
            l
        })
        .unwrap_or_else(|| {
            panic!(
                "unable to find longest row? -> length all _table {}, max {}",
                all_table.len(),
                max
            )
        });
    info!(
        "Longest sequence is for key {longest_key:?} -> sequence of {:?} (sequence:  {:?})",
        find_longest_consecutive_sequence(epochs.clone()),
        epochs,
    );
    // now we can fetch the key that we want
    let key_value = hex::encode(longest_key.value.to_be_bytes_vec());
    let key_column = table.columns.secondary.name.clone();
    // Assuming this is mapping with only two columns !
    let value_column = table.columns.rest[0].name.clone();
    let table_name = table.name.clone();
    // we set the block bounds
    let (longest_sequence, starting) = find_longest_consecutive_sequence(epochs.to_vec());
    // TODO: careful about off by one error. -1 because tree epoch starts at 1
    let min_block = starting as u64 + table.genesis_block - 1;
    let max_block = min_block + longest_sequence as u64;
    Ok(format!(
        "SELECT AVG({value_column}) 
                FROM {table_name} 
                WHERE {BLOCK_COLUMN_NAME} > {min_block} 
                AND {BLOCK_COLUMN_NAME} < {max_block} 
                AND {key_column} = '0x{key_value}';"
    ))
}

async fn collect_all_at(tree: &MerkleRowTree, at: Epoch) -> Result<Vec<Row<BlockPrimaryIndex>>> {
    let root_key = tree.root_at(at).await.unwrap();
    let (ctx, payload) = tree.try_fetch_with_context_at(&root_key, at).await.unwrap();
    let root_row = Row {
        k: root_key,
        payload,
    };
    let mut all_rows = vec![root_row];
    let mut to_inspect = vec![ctx];
    while !to_inspect.is_empty() {
        let local = to_inspect.clone();
        let (local_rows, local_ctx): (Vec<_>, Vec<_>) = stream::iter(local.iter())
            .then(|ctx| async {
                let lctx = ctx.clone();
                let mut local_rows = Vec::new();
                let mut local_ctx = Vec::new();
                for child_k in lctx.iter_children().flatten() {
                    let (child_ctx, child_payload) =
                        tree.try_fetch_with_context_at(child_k, at).await.unwrap();
                    local_rows.push(Row {
                        k: child_k.clone(),
                        payload: child_payload,
                    });
                    local_ctx.push(child_ctx.clone())
                }
                (local_rows, local_ctx)
            })
            .unzip()
            .await;
        all_rows.extend(local_rows.into_iter().flatten().collect::<Vec<_>>());
        to_inspect = local_ctx.into_iter().flatten().collect::<Vec<_>>();
    }
    Ok(all_rows)
}

fn find_longest_consecutive_sequence(v: Vec<i64>) -> (usize, i64) {
    let mut longest = 0;
    let mut starting_idx = 0;
    for i in 0..v.len() - 1 {
        if v[i] + 1 == v[i + 1] {
            longest += 1;
        } else {
            longest = 0;
            starting_idx = i + 1;
        }
    }
    (longest, v[starting_idx])
}
