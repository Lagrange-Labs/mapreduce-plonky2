use anyhow::{ensure, Context, Result};
use bb8::Pool;
use bb8_postgres::{tokio_postgres::NoTls, PostgresConnectionManager};
use futures::{
    stream::{self, StreamExt},
    FutureExt,
};
use itertools::Itertools;
use log::debug;
use mp2_v1::{
    indexing::{
        block::{BlockPrimaryIndex, BlockTreeKey},
        cell::{self, Cell, CellTreeKey, MerkleCell, MerkleCellTree},
        index::IndexNode,
        row::{CellCollection, Row, RowTreeKey},
        ColumnID,
    },
    values_extraction::gadgets::column_info::ColumnInfo,
};
use parsil::symbols::{ColumnKind, ContextProvider, ZkColumn, ZkTable};
use plonky2::field::types::PrimeField64;
use ryhope::{
    storage::{
        pgsql::{SqlServerConnection, SqlStorageSettings},
        updatetree::UpdateTree,
        EpochKvStorage, RoEpochKvStorage, TreeTransactionalStorage,
    },
    tree::scapegoat::Alpha,
    Epoch, InitSettings,
};
use serde::{Deserialize, Serialize};
use std::{hash::Hash, iter::once};
use verifiable_db::query::computational_hash_ids::ColumnIDs;

use super::{
    cases::query::{
        MAX_NUM_COLUMNS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_OUTPUTS, MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
    },
    index_tree::MerkleIndexTree,
    rowtree::MerkleRowTree,
    ColumnIdentifier,
};

pub type TableID = String;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum IndexType {
    Primary,
    Secondary,
    None,
}

impl IndexType {
    pub fn is_primary(&self) -> bool {
        matches!(self, IndexType::Primary)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TableColumn {
    pub name: String,
    pub info: ColumnInfo,
    pub index: IndexType,
    /// multiplier means if this columns come from a "merged" table, then it either come from a
    /// table a or table b. One of these table is the "multiplier" table, the other is not.
    pub multiplier: bool,
}

impl TableColumn {
    pub fn identifier(&self) -> ColumnID {
        self.info.identifier().to_canonical_u64()
    }
}

/// Table Row unique ID is used to compute the unique data of a row when proving for the cells.
/// It corresponds to the different types of storage slot as:
/// Single slot - row_unique_data_for_single_leaf()
/// Mapping slot - row_unique_data_for_mapping_leaf(mapping_key)
/// Mapping of mappings slot - row_unique_data_for_mapping_of_mappings_leaf(outer_mapping_key, inner_mapping_key)
/// We save the column IDs for fetching the cell value to compute this row unique data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TableRowUniqueID {
    Single,
    Mapping(ColumnID),
    MappingOfMappings(ColumnID, ColumnID),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
        self.rest.get(key - 1).map(|tc| tc.identifier())
    }
    pub fn column_info(&self, identifier: ColumnIdentifier) -> TableColumn {
        self.rest
            .iter()
            .chain(once(&self.secondary))
            .find(|c| c.identifier() == identifier)
            .unwrap_or_else(|| panic!("can't find cell from identifier {}", identifier))
            .clone()
    }
    pub fn ordered_cells(
        &self,
        mut rest_cells: Vec<MerkleCell<BlockPrimaryIndex>>,
    ) -> Vec<MerkleCell<BlockPrimaryIndex>> {
        rest_cells.sort_by_key(|c| self.cells_tree_index_of(c.identifier()));
        rest_cells
    }
    // Returns the index of the column identifier in the index tree, ie. the order of columns  in
    // the cells tree
    // NOTE this assumes we keep all the values in the Row JSON payload which makes more sense
    pub fn cells_tree_index_of(&self, identifier: ColumnIdentifier) -> usize {
        match identifier {
            // TODO this will be problematic in the CSV case
            _ if identifier == self.primary.identifier() => panic!(
                "should not call the position on primary index since should not be included in cells tree: {} == {}",
                identifier,
                self.primary.identifier(),
            ),
            _ if identifier == self.secondary.identifier() => panic!(
                "should not call the position on secondary index since should not be included in cells tree: {} == {}",
                identifier,
                self.secondary.identifier(),
            ),
            _ => self
                .rest
                .iter()
                .enumerate()
                .find(|(_, c)| c.identifier() == identifier)
                // + 1 because sbbst starts at 1 not zero
                .map(|(i, _)| i+1)
                .expect("can't find index of identfier"),
        }
    }
    pub fn self_assert(&self) {
        for column in self.non_indexed_columns() {
            let idx = self.cells_tree_index_of(column.identifier());
            let id = self.column_id_of_cells_index(idx).unwrap();
            assert!(column.identifier() == id);
        }
    }
}

impl From<&TableColumns> for ColumnIDs {
    fn from(columns: &TableColumns) -> Self {
        ColumnIDs::new(
            columns.primary.identifier(),
            columns.secondary.identifier(),
            columns
                .non_indexed_columns()
                .into_iter()
                .map(|column| column.identifier())
                .collect_vec(),
        )
    }
}

pub type DBPool = Pool<PostgresConnectionManager<NoTls>>;
async fn new_db_pool(db_url: &str) -> anyhow::Result<DBPool> {
    let db_manager = PostgresConnectionManager::new_from_stringlike(db_url, NoTls)
        .with_context(|| format!("while connecting to postgreSQL with `{}`", db_url))?;

    let db_pool = DBPool::builder()
        .build(db_manager)
        .await
        .context("while creating the db_pool")?;
    Ok(db_pool)
}

pub struct Table {
    pub(crate) genesis_block: BlockPrimaryIndex,
    pub(crate) public_name: TableID,
    pub(crate) columns: TableColumns,
    pub(crate) row_unique_id: TableRowUniqueID,
    // NOTE: there is no cell tree because it's small and can be reconstructed
    // on the fly very quickly. Otherwise, we would need to store one cell tree per row
    // and that means one sql table per row which would be untenable.
    // Instead, we construct the tree from the mapping identifier -> tree key from
    // the columns information
    pub(crate) row: MerkleRowTree,
    pub(crate) index: MerkleIndexTree,
    pub(crate) db_pool: DBPool,
}

fn row_table_name(name: &str) -> String {
    format!("row_{}", name)
}
fn index_table_name(name: &str) -> String {
    format!("index_{}", name)
}

impl Table {
    pub async fn load(
        public_name: String,
        columns: TableColumns,
        row_unique_id: TableRowUniqueID,
    ) -> Result<Self> {
        let db_url = std::env::var("DB_URL").unwrap_or("host=localhost dbname=storage".to_string());
        let row_tree = MerkleRowTree::new(
            InitSettings::MustExist,
            SqlStorageSettings {
                table: row_table_name(&public_name),
                source: SqlServerConnection::NewConnection(db_url.clone()),
            },
        )
        .await
        .unwrap();
        let index_tree = MerkleIndexTree::new(
            InitSettings::MustExist,
            SqlStorageSettings {
                source: SqlServerConnection::NewConnection(db_url.clone()),
                table: index_table_name(&public_name),
            },
        )
        .await
        .unwrap();
        let genesis = index_tree.storage_state().await?.shift;
        columns.self_assert();

        Ok(Self {
            db_pool: new_db_pool(&db_url).await?,
            columns,
            row_unique_id,
            genesis_block: genesis as BlockPrimaryIndex,
            public_name,
            row: row_tree,
            index: index_tree,
        })
    }

    pub fn row_table_name(&self) -> String {
        row_table_name(&self.public_name)
    }

    pub async fn new(
        genesis_block: u64,
        root_table_name: String,
        columns: TableColumns,
        row_unique_id: TableRowUniqueID,
    ) -> Self {
        let db_url = std::env::var("DB_URL").unwrap_or("host=localhost dbname=storage".to_string());
        let db_settings_index = SqlStorageSettings {
            source: SqlServerConnection::NewConnection(db_url.clone()),
            table: index_table_name(&root_table_name),
        };
        let db_settings_row = SqlStorageSettings {
            source: SqlServerConnection::NewConnection(db_url.clone()),
            table: row_table_name(&root_table_name),
        };

        let row_tree = ryhope::new_row_tree(
            genesis_block as Epoch,
            Alpha::new(0.8),
            db_settings_row,
            true,
        )
        .await
        .unwrap();
        let index_tree = ryhope::new_index_tree(genesis_block as Epoch, db_settings_index, true)
            .await
            .unwrap();

        columns.self_assert();
        Self {
            db_pool: new_db_pool(&db_url)
                .await
                .expect("unable to create db pool"),
            columns,
            row_unique_id,
            genesis_block: genesis_block as BlockPrimaryIndex,
            public_name: root_table_name,
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
            .map(|tc| tc.identifier())
            .filter_map(|id| cells.find_by_column(id).map(|info| (id, info)))
            .map(|(id, info)| cell::MerkleCell::new(id, info.value, info.primary))
            .collect::<Vec<_>>();
        // because of lifetime issues in async
        let columns = self.columns.clone();
        let rest_cells = columns.ordered_cells(rest_cells);
        // the first time we actually create the cells tree, there is nothing
        if !rest_cells.is_empty() {
            let _ = cell_tree
                .in_transaction(|t| {
                    async move {
                        // if there is no cell, this loop wont run
                        for cell in rest_cells {
                            // here we don't put i+2 (primary + secondary) since only those values are in the cells tree
                            // but we put + 1 because sbbst starts at +1
                            let idx = columns.cells_tree_index_of(cell.identifier());
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
    ) -> anyhow::Result<CellsUpdateResult<BlockPrimaryIndex>> {
        // fetch previous row or return 0 cells in case of init
        let previous_cells = self
            .row
            .try_fetch(&update.previous_row_key)
            .await?
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
        let merkle_cells = update
            .updated_cells
            .iter()
            .map(|c| cell::MerkleCell::new(c.identifier(), c.value(), update.primary))
            .collect_vec();
        let merkle_cells = self.columns.ordered_cells(merkle_cells);
        let cell_update = cell_tree
            .in_transaction(|t| {
                async move {
                    for merkle_cell in merkle_cells {
                        println!(
                            " --- TREE: inserting rest-cell: (index {}) : {:?}",
                            columns.cells_tree_index_of(merkle_cell.identifier()),
                            merkle_cell
                        );
                        let cell_key = columns.cells_tree_index_of(merkle_cell.identifier());
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
            "Cell trees root hash after updates (impacted keys {:?}): {:?}",
            cell_update.nodes().collect_vec(),
            hex::encode(&cell_tree.root_data().await?.unwrap().hash[..])
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
    ) -> anyhow::Result<RowUpdateResult> {
        let current_epoch = self.row.current_epoch();
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
                            TreeRowUpdate::Deletion(row_key) => {
                                match t.try_fetch(&row_key).await? {
                                    // sanity check
                                    Some(_) => {
                                        t.remove(row_key.clone()).await?;
                                    }
                                    None => panic!("can't delete a row key that does not exist"),
                                }
                            }
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
                            let mut row_payload = t.try_fetch(&row_key).await.unwrap().unwrap();
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
            let root = self.row.root_data().await?.unwrap();
            let new_epoch = self.row.current_epoch();
            assert!(
                current_epoch != new_epoch,
                "new epoch {} vs previous epoch {}",
                new_epoch,
                current_epoch
            );
            println!(
                " ++ After row update, row cell tree root tree proof hash = {:?}",
                hex::encode(root.cell_root_hash.unwrap().0)
            );
            self.row.print_tree().await;
            println!("\n+++++++++++++++++++++++++++++++++\n");
        }
        Ok(out?)
    }

    // apply the transformation on the index tree and returns the new nodes to prove
    // NOTE: hardcode for block since only block can use sbbst
    pub async fn apply_index_update(
        &mut self,
        updates: IndexUpdate<BlockPrimaryIndex>,
    ) -> anyhow::Result<IndexUpdateResult<BlockTreeKey>> {
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

impl Table {
    fn to_zktable(&self) -> anyhow::Result<ZkTable> {
        let zk_columns = self.columns.to_zkcolumns();
        Ok(ZkTable {
            // NOTE : we always look data in the row table
            zktable_name: self.row_table_name(),
            user_facing_name: self.public_name.clone(),
            columns: zk_columns,
        })
    }
}

impl TableColumns {
    pub fn to_zkcolumns(&self) -> Vec<ZkColumn> {
        once(&self.primary_column())
            .chain(once(&self.secondary_column()))
            .chain(self.rest.iter())
            .map(|c| c.to_zkcolumn())
            .collect()
    }
}

impl TableColumn {
    pub fn to_zkcolumn(&self) -> ZkColumn {
        ZkColumn {
            id: self.identifier(),
            kind: match self.index {
                IndexType::Primary => ColumnKind::PrimaryIndex,
                IndexType::Secondary => ColumnKind::SecondaryIndex,
                IndexType::None => ColumnKind::Standard,
            },
            name: self.name.clone(),
        }
    }
}

impl ContextProvider for Table {
    fn fetch_table(&self, table_name: &str) -> anyhow::Result<ZkTable> {
        <&Self as ContextProvider>::fetch_table(&self, table_name)
    }

    const MAX_NUM_COLUMNS: usize = <&Self as ContextProvider>::MAX_NUM_COLUMNS;

    const MAX_NUM_PREDICATE_OPS: usize = <&Self as ContextProvider>::MAX_NUM_PREDICATE_OPS;

    const MAX_NUM_RESULT_OPS: usize = <&Self as ContextProvider>::MAX_NUM_RESULT_OPS;

    const MAX_NUM_ITEMS_PER_OUTPUT: usize = <&Self as ContextProvider>::MAX_NUM_ITEMS_PER_OUTPUT;

    const MAX_NUM_OUTPUTS: usize = <&Self as ContextProvider>::MAX_NUM_OUTPUTS;
}

impl ContextProvider for &Table {
    fn fetch_table(&self, table_name: &str) -> anyhow::Result<ZkTable> {
        ensure!(
            self.public_name == table_name,
            "names differ table {} vs requested {}",
            self.row_table_name(),
            table_name
        );
        self.to_zktable()
    }

    const MAX_NUM_COLUMNS: usize = MAX_NUM_COLUMNS;

    const MAX_NUM_PREDICATE_OPS: usize = MAX_NUM_PREDICATE_OPS;

    const MAX_NUM_RESULT_OPS: usize = MAX_NUM_RESULT_OPS;

    const MAX_NUM_ITEMS_PER_OUTPUT: usize = MAX_NUM_ITEMS_PER_OUTPUT;

    const MAX_NUM_OUTPUTS: usize = MAX_NUM_OUTPUTS;
}
