use alloy::primitives::Address;
use anyhow::Result;
use ryhope::{
    storage::{updatetree::UpdateTree, EpochKvStorage, RoEpochKvStorage, TreeTransactionalStorage},
    tree::{
        sbbst,
        scapegoat::{self, Alpha},
    },
    InitSettings,
};
use serde::{Deserialize, Serialize};

use super::{
    celltree::{Cell, CellTreeKey, MerkleCellTree, TreeCell},
    index_tree::{IndexNode, IndexTreeKey, MerkleIndexTree},
    rowtree::{CellCollection, MerkleRowTree, Row, RowPayload, RowTreeKey},
    ColumnIdentifier,
};

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
    pub identifier: ColumnIdentifier,
    pub index: IndexType,
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
                // here we don't put i+2 (primary + secondary) since only those values are in the cells tree
                // but we put + 1 because sbbst starts at +1
                .map(|(i, _)| i+1)
                .expect("can't find index of identfier"),
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
    pub fn new(genesis_block: u64, table_id: TableID, columns: TableColumns) -> Self {
        let row_tree = MerkleRowTree::new(
            InitSettings::Reset(scapegoat::Tree::empty(Alpha::new(0.8))),
            (),
        )
        .unwrap();
        println!("genesis_block = {genesis_block}");
        let index_tree = MerkleIndexTree::new(
            //InitSettings::Reset(sbbst::Tree::empty()),
            InitSettings::Reset(sbbst::Tree::with_shift((genesis_block - 1) as usize)),
            (),
        )
        .unwrap();
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
    fn construct_cell_tree(&mut self, cells: &CellCollection) -> MerkleCellTree {
        let mut cell_tree =
            MerkleCellTree::new(InitSettings::Reset(sbbst::Tree::empty()), ()).unwrap();
        // the first time we actually create the cells tree, there is nothing
        if !cells.non_indexed_cells().unwrap_or_default().is_empty() {
            let _ = cell_tree
                .in_transaction(|t| {
                    // if there is no cell, this loop wont run
                    for cell in cells.non_indexed_cells().unwrap_or_default() {
                        let idx = self.columns.cells_tree_index_of(cell.id);
                        t.store(idx, cell.into())?;
                    }
                    Ok(())
                })
                .expect("can't update cell tree");
        }
        cell_tree
    }

    // Call this function first on all the cells tree that change from one update to another
    // Then prove the updates. Once done, you can call `apply_row_update` to update the row trees
    // and then once done you can call `apply_index_update`
    // TODO: handle the case where the row secondary index changes, as this requires a deletion
    // then fresh insertion
    pub fn apply_cells_update(&mut self, update: CellsUpdate) -> Result<CellsUpdateResult> {
        // fetch previous row or return 0 cells in case of init
        let previous_cells = self
            .row
            .try_fetch(&update.row_key)
            .map(|row_node| row_node.cells)
            .or_else(|| {
                if update.init {
                    Some(CellCollection::default())
                } else {
                    log::error!(
                        "either row is full or we are initializing - this is something else"
                    );
                    None
                }
            })
            .unwrap();
        // reconstruct the _current_ cell tree before update
        // note we ignore the update plan here since we assume it already has been proven
        // or is empty
        println!("BEFORE construct cell tree");
        let mut cell_tree = self.construct_cell_tree(&previous_cells);
        println!("BEFORE update cell tree");
        // apply updates and save the update plan for the new values
        let cell_update = cell_tree
            .in_transaction(|t| {
                for new_cell in update.updated_cells.iter() {
                    let cell_key = self.columns.cells_tree_index_of(new_cell.id);
                    if update.init {
                        t.store(cell_key, new_cell.into())?;
                    } else {
                        t.update(cell_key, new_cell.into())?;
                    }
                }
                Ok(())
            })
            .expect("can't apply cells update");
        Ok(CellsUpdateResult {
            key: update.row_key.clone(),
            to_update: cell_update,
            latest: cell_tree,
        })
    }

    // apply the transformation directly to the row tree to get the update plan and the new
    pub fn apply_row_update(&mut self, updates: RowUpdate) -> Result<RowUpdateResult> {
        let plan = self.row.in_transaction(move |t| {
            for update in updates.modified_rows.into_iter() {
                if updates.init {
                    t.store(update.k.clone(), update.payload)?;
                } else {
                    t.update(update.k.clone(), update.payload)?;
                }
            }
            Ok(())
        })?;
        Ok(RowUpdateResult { updates: plan })
    }

    // apply the transformation on the index tree and returns the new nodes to prove
    pub fn apply_index_update(&mut self, updates: IndexUpdate) -> Result<IndexUpdateResult> {
        let plan = self.index.in_transaction(move |t| {
            if updates.init {
                t.store(updates.added_index.0, updates.added_index.1)?;
            } else {
                t.update(updates.added_index.0, updates.added_index.1)?;
            }
            Ok(())
        })?;
        Ok(IndexUpdateResult { plan })
    }
}

#[derive(Debug, Clone)]
pub struct IndexUpdate {
    // TODO: at the moment we only append one by one the block.
    // Depending on how we do things for CSV, this might be a vector
    pub added_index: (IndexTreeKey, IndexNode),
    pub init: bool,
    // TODO for CSV modification and deletion ?
}

#[derive(Clone)]
pub struct IndexUpdateResult {
    pub plan: UpdateTree<IndexTreeKey>,
}

#[derive(Debug, Clone)]
pub struct RowUpdate {
    // TODO:
    // * added rows
    // * deleted rows
    pub modified_rows: Vec<Row>,
    pub init: bool,
}

#[derive(Clone)]
pub struct RowUpdateResult {
    pub updates: UpdateTree<RowTreeKey>,
}

#[derive(Debug, Clone)]
pub struct CellsUpdate {
    pub row_key: RowTreeKey,
    // this must NOT contain the secondary index cell. Otherwise, in case the secondary index cell values
    // did not change, we would not be able to separate the rest from the secondary index cell.
    pub updated_cells: Vec<Cell>,
    // set this to true to notify to consumers this is the first insert in the cell tree
    // Useful to know whether this update contains all the cells or the rest of the cells
    // must be fetching somewhere else.
    pub init: bool,
    // TODO:
    // * add modified secondary index
    // * add deleted cells
    // no need for added cells since we don't add columns on a table
}

// Contains the data necessary to start proving the update of the cells tree
// and including the new information in the respective rows.
// For example one needs to setup the location of the proof, the root hash of the new cells tree.
// Once that is done, one can call `apply_row_update`
pub struct CellsUpdateResult {
    pub key: RowTreeKey,
    // give the tree here since we don't really store it so it's easier down the line to pass it
    // around
    pub latest: MerkleCellTree,
    pub to_update: UpdateTree<CellTreeKey>,
}
