use alloy::primitives::Address;
use anyhow::Result;
use futures::{
    stream::{self, StreamExt},
    FutureExt,
};
use log::debug;
use mp2_v1::indexing::{
    block::BlockPrimaryIndex,
    cell::{self, Cell, CellTreeKey, MerkleCellTree},
    index::IndexNode,
    row::{CellCollection, Row, RowTreeKey},
    ColumnID,
};
use ryhope::{
    storage::{updatetree::UpdateTree, EpochKvStorage, RoEpochKvStorage, TreeTransactionalStorage},
    tree::{
        sbbst,
        scapegoat::{self, Alpha},
    },
    InitSettings,
};
use serde::{Deserialize, Serialize};
use std::hash::Hash;

use super::{index_tree::MerkleIndexTree, rowtree::MerkleRowTree, ColumnIdentifier};

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TableID(String);

impl TableID {
    /// TODO: should contain more info probablyalike which index are selected
    pub fn new(init_block: u64, contract: &Address, slots: &[u8]) -> Self {
        TableID(format!(
            "{}-{}-{}",
            init_block,
            contract,
            slots
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join("+"),
        ))
    }
}

#[derive(Clone, Debug)]
pub enum IndexType {
    Primary,
    Secondary,
    None,
}

#[derive(Clone, Debug)]
pub struct TableColumn {
    pub identifier: ColumnID,
    pub _index: IndexType,
}

#[derive(Clone, Debug)]
pub struct TableColumns {
    pub primary: TableColumn,
    pub secondary: TableColumn,
    pub rest: Vec<TableColumn>,
}
impl TableColumns {
    pub fn primary_column(&self) -> TableColumn {
        self.primary.clone()
    }
    pub fn secondary_column(&self) -> TableColumn {
        self.secondary.clone()
    }
    pub fn non_indexed_columns(&self) -> Vec<TableColumn> {
        self.rest.clone()
    }
    pub fn column_id_of_cells_index(&self, key: CellTreeKey) -> Option<ColumnID> {
        self.rest.get(key - 1).map(|tc| tc.identifier)
    }
    // Returns the index of the column identifier in the index tree, ie. the order of columns  in
    // the cells tree
    // NOTE this assumes we keep all the values in the Row JSON payload which makes more sense
    pub fn cells_tree_index_of(&self, identifier: ColumnIdentifier) -> usize {
        match identifier {
            // TODO this will be problematic in the CSV case
            _ if identifier == self.primary.identifier => panic!(
                "should not call the position on primary index since should not be included in cells tree"
            ),
            _ if identifier == self.secondary.identifier => panic!(
                "should not call the position on secondary index since should not be included in cells tree"
            ),
            _ => self
                .rest
                .iter()
                .enumerate()
                .find(|(_, c)| c.identifier == identifier)
                // + 1 because sbbst starts at 1 not zero
                .map(|(i, _)| i+1)
                .expect("can't find index of identfier"),
        }
    }
    pub fn self_assert(&self) {
        for column in self.non_indexed_columns() {
            let idx = self.cells_tree_index_of(column.identifier);
            let id = self.column_id_of_cells_index(idx).unwrap();
            assert!(column.identifier == id);
        }
    }
}

pub struct Table {
    pub(crate) id: TableID,
    pub(crate) columns: TableColumns,
    // NOTE: there is no cell tree because it's small and can be reconstructed
    // on the fly very quickly. Otherwise, we would need to store one cell tree per row
    // and that means one sql table per row which would be untenable.
    // Instead, we construct the tree from the mapping identifier -> tree key from
    // the columns information
    pub(crate) row: MerkleRowTree,
    pub(crate) index: MerkleIndexTree,
}

impl Table {
    pub async fn new(genesis_block: u64, table_id: TableID, columns: TableColumns) -> Self {
        let row_tree = MerkleRowTree::new(
            InitSettings::Reset(scapegoat::Tree::empty(Alpha::new(0.8))),
            (),
        )
        .await
        .unwrap();
        let index_tree = MerkleIndexTree::new(
            //InitSettings::Reset(sbbst::Tree::empty()),
            InitSettings::Reset(sbbst::Tree::with_shift((genesis_block - 1) as usize)),
            (),
        )
        .await
        .unwrap();
        columns.self_assert();
        Self {
            columns,
            id: table_id,
            row: row_tree,
            index: index_tree,
        }
    }

    // Function to call each time we need to build the index tree, i.e. for each row and
    // at each update for each row. Reason is we don't store it in memory since it's
    // very fast to recompute.
    pub async fn construct_cell_tree(
        &self,
        cells: &CellCollection<BlockPrimaryIndex>,
    ) -> MerkleCellTree<BlockPrimaryIndex> {
        let mut cell_tree = cell::new_tree().await;
        // we fetch the info from the column ids, and construct the cells of the tree
        let rest_cells = self
            .columns
            .non_indexed_columns()
            .iter()
            .map(|tc| tc.identifier)
            .filter_map(|id| cells.find_by_column(id).map(|info| (id, info)))
            .map(|(id, info)| cell::MerkleCell::new(id, info.value, info.primary))
            .collect::<Vec<_>>();
        // because of lifetime issues in async
        let columns = self.columns.clone();
        // the first time we actually create the cells tree, there is nothing
        if !rest_cells.is_empty() {
            let _ = cell_tree
                .in_transaction(|t| {
                    async move {
                        // if there is no cell, this loop wont run
                        for cell in rest_cells {
                            // here we don't put i+2 (primary + secondary) since only those values are in the cells tree
                            // but we put + 1 because sbbst starts at +1
                            let idx = columns.cells_tree_index_of(cell.id);
                            t.store(idx, cell).await?;
                        }
                        Ok(())
                    }
                    .boxed()
                })
                .await
                .expect("can't update cell tree");
        }
        cell_tree
    }

    // Call this function first on all the cells tree that change from one update to another
    // Then prove the updates. Once done, you can call `apply_row_update` to update the row trees
    // and then once done you can call `apply_index_update`
    pub async fn apply_cells_update(
        &mut self,
        update: CellsUpdate<BlockPrimaryIndex>,
        update_type: TreeUpdateType,
    ) -> Result<CellsUpdateResult<BlockPrimaryIndex>> {
        // fetch previous row or return 0 cells in case of init
        let previous_cells = self
            .row
            .try_fetch(&update.previous_row_key)
            .await
            .map(|row_node| row_node.cells)
            // if it happens, it must be because of init time
            .or_else(|| Some(CellCollection::default()))
            .unwrap();
        // reconstruct the _current_ cell tree before update
        // note we ignore the update plan here since we assume it already has been proven
        // or is empty
        println!(
            "BEFORE construct cell tree - previous_cells {:?}",
            previous_cells
        );
        let mut cell_tree = self.construct_cell_tree(&previous_cells).await;
        println!(
            "BEFORE update cell tree -> going over {} new updated cells",
            update.updated_cells.len()
        );
        // apply updates and save the update plan for the new values
        // clone for lifetime issues with async
        let columns = self.columns.clone();
        let cell_update = cell_tree
            .in_transaction(|t| {
                async move {
                    for new_cell in update.updated_cells.iter() {
                        let merkle_cell =
                            cell::MerkleCell::new(new_cell.id, new_cell.value, update.primary);
                        println!(
                            " --- TREE: inserting rest-cell: (index {}) : {:?}",
                            columns.cells_tree_index_of(new_cell.id),
                            merkle_cell
                        );
                        let cell_key = columns.cells_tree_index_of(new_cell.id);
                        match update_type {
                            TreeUpdateType::Update => t.update(cell_key, merkle_cell).await?,
                            // This should only happen at init time or at creation of a new row
                            TreeUpdateType::Insertion => t.store(cell_key, merkle_cell).await?,
                        }
                    }
                    Ok(())
                }
                .boxed()
            })
            .await
            .expect("can't apply cells update");
        println!(
            "Cell trees root hash after updates (impacted key {:?}): {:?}",
            cell_update.impacted_keys(),
            hex::encode(&cell_tree.root_data().await.unwrap().hash[..])
        );
        Ok(CellsUpdateResult {
            previous_row_key: update.previous_row_key,
            new_row_key: update.new_row_key,
            to_update: cell_update,
            latest: cell_tree,
        })
    }

    // apply the transformation directly to the row tree to get the update plan and the new
    pub async fn apply_row_update(
        &mut self,
        new_primary: BlockPrimaryIndex,
        updates: Vec<TreeRowUpdate>,
    ) -> Result<RowUpdateResult> {
        let out = self
            .row
            .in_transaction(|t| {
                async move {
                    // apply all the updates and then look at the touched ones to update to the new
                    // primary
                    for update in updates {
                        debug!("Apply update to row tree: {:?}", update);
                        match update {
                            TreeRowUpdate::Update(row) => {
                                t.update(row.k.clone(), row.payload.clone()).await?;
                            }
                            TreeRowUpdate::Deletion(row_key) => match t.try_fetch(&row_key).await {
                                // sanity check
                                Some(_) => {
                                    t.remove(row_key.clone()).await?;
                                }
                                None => panic!("can't delete a row key that does not exist"),
                            },
                            TreeRowUpdate::Insertion(row) => {
                                t.store(row.k.clone(), row.payload.clone()).await?;
                            }
                        }
                    }
                    let dirties = t.touched().await;
                    // we now update the primary value of all nodes affected by the update.
                    // Because nodes are proven from bottom up, all the parents of leaves will already
                    // be able to fetch the latest children proof at the latest primary thanks to this
                    // update.
                    let filtered_rows = stream::iter(dirties.into_iter())
                        .then(|row_key| async {
                            let mut row_payload = t.fetch(&row_key).await;
                            let mut cell_info = row_payload
                                .cells
                                .find_by_column(row_payload.secondary_index_column)
                                .unwrap()
                                .clone();
                            cell_info.primary = new_primary;
                            row_payload.cells.update_column(
                                row_payload.secondary_index_column,
                                cell_info.clone(),
                            );
                            Row {
                                k: row_key,
                                payload: row_payload,
                            }
                        })
                        .collect::<Vec<_>>()
                        .await;
                    for row in filtered_rows {
                        t.update(row.k, row.payload).await?;
                    }
                    Ok(())
                }
                .boxed()
            })
            .await
            .map(|plan| RowUpdateResult { updates: plan });
        {
            // debugging
            println!("\n+++++++++++++++++++++++++++++++++\n");
            self.row.print_tree().await;
            println!("\n+++++++++++++++++++++++++++++++++\n");
        }
        out
    }

    // apply the transformation on the index tree and returns the new nodes to prove
    // NOTE: hardcode for block since only block can use sbbst
    pub async fn apply_index_update(
        &mut self,
        updates: IndexUpdate<BlockPrimaryIndex>,
    ) -> Result<IndexUpdateResult<BlockPrimaryIndex>> {
        let plan = self
            .index
            .in_transaction(|t| {
                async move {
                    t.store(updates.added_index.0, updates.added_index.1)
                        .await?;
                    Ok(())
                }
                .boxed()
            })
            .await?;
        Ok(IndexUpdateResult { plan })
    }
}

#[derive(Debug, Clone)]
pub struct IndexUpdate<PrimaryIndex> {
    // TODO: at the moment we only append one by one the block.
    // Depending on how we do things for CSV, this might be a vector
    pub added_index: (PrimaryIndex, IndexNode<PrimaryIndex>),
    // TODO for CSV modification and deletion ?
}

#[derive(Clone)]
pub struct IndexUpdateResult<PrimaryIndex: Clone + PartialEq + Eq + Hash> {
    pub plan: UpdateTree<PrimaryIndex>,
}

/// NOTE this hardcoding is ok for now but will have to change once we move to CSV types of data.
#[derive(Debug, Clone)]
pub enum TreeRowUpdate {
    Insertion(Row<BlockPrimaryIndex>),
    Update(Row<BlockPrimaryIndex>),
    Deletion(RowTreeKey),
}

#[derive(Clone)]
pub struct RowUpdateResult {
    // There is only a single row key for a table that we update continuously
    // so no need to track all the rows that have been updated in the result
    // The tree already have this information by now.
    pub updates: UpdateTree<RowTreeKey>,
}

#[derive(Debug, Clone)]
pub struct CellsUpdate<PrimaryIndex> {
    /// Row key where to fetch the previous cells existing. In case  of  
    /// a secondary index value changing, that means a deletion + insertion.
    /// So tree logic should fetch the cells from the to-be-deleted row first
    ///     * In case there is no update of secondary index value, this value is
    /// just equal to the row key under which the cells must be updated
    ///     * In case there is no previous row key, which happens at initialization time
    /// then it can be the `RowTreeKey::default()` one.
    pub previous_row_key: RowTreeKey,
    /// the key under which the new cells are going to be stored. Can be
    /// the same as previous_row_key if the secondary index value did
    /// not change
    pub new_row_key: RowTreeKey,
    // this must NOT contain the secondary index cell. Otherwise, in case the secondary index cell values
    // did not change, we would not be able to separate the rest from the secondary index cell.
    // NOTE: In the case of initialization time, this contains the initial cells of the row
    pub updated_cells: Vec<Cell>,
    /// Primary index associated with the proving of these cells. This is necessary to associate
    /// the actual _proofs_ of each cell to an unique storage location. This primary is stored
    /// within each cell of the cells tree, allowing for cells to evolve independently.
    pub primary: PrimaryIndex,
}

// Contains the data necessary to start proving the update of the cells tree
// and including the new information in the respective rows.
// For example one needs to setup the location of the proof, the root hash of the new cells tree.
// Once that is done, one can call `apply_row_update`
pub struct CellsUpdateResult<
    PrimaryIndex: std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Clone
        + Sized
        + Sync
        + Send
        + Serialize
        + for<'a> Deserialize<'a>,
> {
    pub previous_row_key: RowTreeKey,
    pub new_row_key: RowTreeKey,
    // give the tree here since we don't really store it so it's easier down the line to pass it
    // around
    pub latest: MerkleCellTree<PrimaryIndex>,
    pub to_update: UpdateTree<CellTreeKey>,
}

impl<PrimaryIndex> CellsUpdateResult<PrimaryIndex>
where
    PrimaryIndex: std::fmt::Debug
        + PartialEq
        + Eq
        + Default
        + Clone
        + Sized
        + Sync
        + Send
        + Serialize
        + for<'a> Deserialize<'a>,
{
    pub fn is_new_row(&self) -> bool {
        self.previous_row_key == Default::default()
    }
    pub fn is_same_row(&self) -> bool {
        self.previous_row_key == self.new_row_key
    }
    pub fn is_moving_row(&self) -> bool {
        !(self.is_new_row() || self.is_same_row())
    }
}

pub enum TreeUpdateType {
    Insertion,
    Update,
}
