use std::{collections::BTreeSet, fmt::Debug};
use anyhow::Result;

use alloy::primitives::U256;
use futures::{stream, StreamExt};
use hashbrown::HashMap;
use itertools::Itertools;
use parsil::symbols::ContextProvider;
use ryhope::{storage::WideLineage, Epoch};
use verifiable_db::query::{batching::{RowPath, RowWithPath, TreePathInputs}, computational_hash_ids::ColumnIDs, universal_circuit::universal_circuit_inputs::{ColumnCell, RowCells}};

use crate::{indexing::{block::{BlockPrimaryIndex, BlockTreeKey}, index::IndexNode, row::{RowPayload, RowTreeKey}, LagrangeNode}, query::planner::TreeFetcher};

use super::planner::NonExistenceInput;

async fn compute_input_for_row<
    T: TreeFetcher<RowTreeKey, RowPayload<BlockPrimaryIndex>>
>(
    tree: &T,
    row_key: &RowTreeKey,
    index_value: BlockPrimaryIndex,
    index_path: &TreePathInputs,
    column_ids: &ColumnIDs,
) -> RowWithPath {
    let row_path = tree.compute_path(row_key, index_value as Epoch)
    .await
    .expect(format!("node with key {:?} not found in cache", row_key).as_str());
    let path = RowPath::new_from_paths(
        row_path, 
        index_path.clone()
    );
    let (_, row_payload) = tree.fetch_ctx_and_payload_at(row_key, index_value as Epoch)
        .await
        .expect(format!("node with key {:?} not found in cache", row_key).as_str());
    // build row cells
    let primary_index_cell = ColumnCell::new(
        column_ids.primary_column(),
        U256::from(index_value),
    );
    let secondary_index_cell = ColumnCell::new(
        column_ids.secondary_column(), 
        row_payload.secondary_index_value()
    );
    let non_indexed_cells = column_ids.non_indexed_columns().into_iter().filter_map(|id| {
        row_payload
            .cells
            .find_by_column(id)
            .map(|info| ColumnCell::new(id, info.value))
    })
    .collect::<Vec<_>>();
    let row_cells = RowCells::new(
        primary_index_cell,
        secondary_index_cell,
        non_indexed_cells,
    );
    RowWithPath::new(&row_cells, &path)
}

pub async fn generate_chunks<'a, const CHUNK_SIZE: usize, C: ContextProvider>(
    row_cache: WideLineage<RowTreeKey, RowPayload<BlockPrimaryIndex>>,
    index_cache: WideLineage<BlockTreeKey, IndexNode<BlockPrimaryIndex>>,
    column_ids: &ColumnIDs,
    non_existence_inputs: NonExistenceInput<'a, C>,
) -> Result<Vec<Vec<RowWithPath>>> 
{
    let index_keys_by_epochs = index_cache.keys_by_epochs();
    assert_eq!(index_keys_by_epochs.len(), 1);
    let row_keys_by_epochs = row_cache.keys_by_epochs();
    let current_epoch = *index_keys_by_epochs.keys().next().unwrap() as Epoch;
    let sorted_index_values = index_keys_by_epochs[&current_epoch].iter().cloned().collect::<BTreeSet<_>>();

    Ok(
        stream::iter(sorted_index_values.into_iter()).then(async |index_value| {
        let index_path = index_cache.compute_path(&index_value, current_epoch)
            .await
            .expect(format!("node with key {index_value} not found in index tree cache").as_str());
        let proven_rows = if let Some(matching_rows) = row_keys_by_epochs.get(&(index_value as Epoch)) {
            let sorted_rows = matching_rows.into_iter().collect::<BTreeSet<_>>();
            stream::iter(sorted_rows.iter()).then(async |&row_key| {
                compute_input_for_row(
                    &row_cache, 
                    row_key, 
                    index_value, 
                    &index_path, 
                    column_ids
                ).await
            }).collect::<Vec<RowWithPath>>().await
        } else {
            //ToDO: find non-existence rows
            let proven_node = non_existence_inputs.find_row_node_for_non_existence(index_value)
                .await
                .expect(format!("node for non-existence not found for index value {index_value}").as_str());
            let row_input = compute_input_for_row(
                non_existence_inputs.row_tree, 
                &proven_node, 
                index_value, 
                &index_path, 
                column_ids
            ).await;
            vec![row_input] 
        };
        proven_rows
    }).concat().await.chunks(CHUNK_SIZE).map(|chunk|
        chunk.to_vec()
    ).collect_vec()
    )
}