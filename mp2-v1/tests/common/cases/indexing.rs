//! Test case for local Simple contract
//! Reference `test-contracts/src/Simple.sol` for the details of Simple contract.

use anyhow::Result;
use itertools::Itertools;
use log::{debug, info};
use mp2_v1::{
    api::{compute_table_info, SlotInput},
    contract_extraction,
    indexing::{
        block::BlockPrimaryIndex,
        cell::Cell,
        row::{CellCollection, CellInfo, Row, RowTreeKey},
        ColumnID,
    },
    values_extraction::{
        gadgets::column_info::ColumnInfo, identifier_block_column, identifier_for_value_column,
    },
};
use ryhope::storage::RoEpochKvStorage;

use crate::common::{
    bindings::simple::Simple::{
        self, simpleStructReturn, structMappingReturn, MappingChange, MappingOperation,
        MappingStructChange, SimpleInstance,
    },
    cases::{
        contract::Contract,
        identifier_for_mapping_key_column,
        table_source::{
            LengthExtractionArgs, MappingIndex, MappingStructExtractionArgs,
            MappingValuesExtractionArgs, MergeSource, SingleStructExtractionArgs,
            SingleValuesExtractionArgs, DEFAULT_ADDRESS,
        },
    },
    proof_storage::{ProofKey, ProofStorage},
    rowtree::SecondaryIndexCell,
    table::{
        CellsUpdate, IndexType, IndexUpdate, Table, TableColumn, TableColumns, TableRowUniqueID,
        TreeRowUpdate, TreeUpdateType,
    },
    MetadataGadget, TableInfo, TestContext,
};

use super::{ContractExtractionArgs, TableIndexing, TableSource};
use alloy::{
    contract::private::{Network, Provider, Transport},
    primitives::{Address, U256},
    providers::ProviderBuilder,
};
use mp2_common::{
    eth::StorageSlot,
    proof::ProofWithVK,
    types::{HashOutput, MAPPING_LEAF_VALUE_LEN},
    F,
};
use plonky2::field::types::PrimeField64;

/// Test slots for single values extraction
pub(crate) const SINGLE_SLOTS: [u8; 4] = [0, 1, 2, 3];

/// Define which slots is the secondary index. In this case, it's the U256
const INDEX_SLOT: u8 = 1;

/// Test slot for mapping values extraction
pub(crate) const MAPPING_SLOT: u8 = 4;

/// Test slot for length extraction
const LENGTH_SLOT: u8 = 1;

/// Test length value for length extraction
const LENGTH_VALUE: u8 = 2;

/// Test slot for contract extraction
const CONTRACT_SLOT: usize = 1;

/// Test slot for single Struct extraction
pub(crate) const SINGLE_STRUCT_SLOT: usize = 6;

/// Test slot for mapping Struct extraction
pub(crate) const MAPPING_STRUCT_SLOT: usize = 8;

/// Test slot for mapping of mappings extraction
pub(crate) const MAPPING_OF_MAPPINGS_SLOT: usize = 9;

/// human friendly name about the column containing the block number
pub(crate) const BLOCK_COLUMN_NAME: &str = "block_number";
pub(crate) const MAPPING_VALUE_COLUMN: &str = "map_value";
pub(crate) const MAPPING_KEY_COLUMN: &str = "map_key";

impl TableIndexing {
    pub fn table(&self) -> &Table {
        &self.table
    }
    pub(crate) async fn merge_table_test_case(
        ctx: &mut TestContext,
    ) -> Result<(Self, Vec<TableRowUpdate<BlockPrimaryIndex>>)> {
        // Create a provider with the wallet for contract deployment and interaction.
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());

        let contract = Simple::deploy(&provider).await.unwrap();
        info!(
            "Deployed Simple contract at address: {}",
            contract.address()
        );
        let contract_address = contract.address();
        let chain_id = ctx.rpc.get_chain_id().await.unwrap();
        let contract = Contract {
            address: *contract_address,
            chain_id,
        };
        // this test puts the mapping value as secondary index so there is no index for the
        // single variable slots.
        let single_source = SingleValuesExtractionArgs::new(None);
        let mapping_key_id =
            identifier_for_mapping_key_column(MAPPING_SLOT, contract_address, chain_id, vec![]);
        let mapping_value_id = identifier_for_value_column(
            &MappingValuesExtractionArgs::slot_input(),
            contract_address,
            chain_id,
            vec![],
        );
        // to toggle off and on
        let value_as_index = false;
        let (mapping_index_id, mapping_index, mapping_cell_id) = match value_as_index {
            true => (
                mapping_value_id,
                MappingIndex::Value(mapping_value_id),
                mapping_key_id,
            ),
            false => (
                mapping_key_id,
                MappingIndex::Key(mapping_key_id),
                mapping_value_id,
            ),
        };
        let mapping_source = MappingValuesExtractionArgs::new(mapping_index);
        let mut source = TableSource::Merge(MergeSource::new(single_source, mapping_source));
        let genesis_change = source.init_contract_data(ctx, &contract).await;
        let single_columns = SingleValuesExtractionArgs::slot_inputs()
            .iter()
            .enumerate()
            .map(|(i, slot_input)| {
                let identifier =
                    identifier_for_value_column(slot_input, contract_address, chain_id, vec![]);
                let info = ColumnInfo::new_from_slot_input(identifier, slot_input);
                TableColumn {
                    name: format!("column_{}", i),
                    index: IndexType::None,
                    // ALL single columns are "multiplier" since we do tableA * D(tableB), i.e. all
                    // entries of table A are repeated for each entry of table B.
                    multiplier: true,
                    info,
                }
            })
            .collect_vec();
        let mapping_slot_input = MappingValuesExtractionArgs::slot_input();
        let mapping_column = {
            let info = ColumnInfo::new_from_slot_input(mapping_cell_id, &mapping_slot_input);
            vec![TableColumn {
                name: if value_as_index {
                    MAPPING_KEY_COLUMN
                } else {
                    MAPPING_VALUE_COLUMN
                }
                .to_string(),
                index: IndexType::None,
                // here is it important to specify false to mean that the entries of table B are
                // not repeated.
                multiplier: false,
                info,
            }]
        };
        let value_column = mapping_column[0].name.clone();
        let all_columns = [single_columns.as_slice(), mapping_column.as_slice()].concat();
        let columns = TableColumns {
            primary: TableColumn {
                name: BLOCK_COLUMN_NAME.to_string(),
                index: IndexType::Primary,
                // it doesn't matter for this one since block is "outside" of the table definition
                // really, it is a special column we add
                multiplier: true,
                // Only valid for the identifier of block column, others are dummy.
                info: ColumnInfo::new(0, identifier_block_column(), 0, 0, 0, 0),
            },
            secondary: TableColumn {
                name: if value_as_index {
                    MAPPING_VALUE_COLUMN
                } else {
                    MAPPING_KEY_COLUMN
                }
                .to_string(),
                index: IndexType::Secondary,
                // here is it important to specify false to mean that the entries of table B are
                // not repeated.
                multiplier: false,
                info: ColumnInfo::new_from_slot_input(mapping_index_id, &mapping_slot_input),
            },
            rest: all_columns,
        };
        println!(
            "Table information:\n{}\n",
            serde_json::to_string_pretty(&columns)?
        );
        let row_unique_id = TableRowUniqueID::Mapping(mapping_index_id);

        let indexing_genesis_block = ctx.block_number().await;
        let table = Table::new(
            indexing_genesis_block,
            "merged_table".to_string(),
            columns,
            row_unique_id,
        )
        .await;
        Ok((
            Self {
                value_column,
                source: source.clone(),
                table,
                contract,
                contract_extraction: ContractExtractionArgs {
                    slot: StorageSlot::Simple(CONTRACT_SLOT),
                },
            },
            genesis_change,
        ))
    }

    pub(crate) async fn single_value_test_case(
        ctx: &mut TestContext,
    ) -> Result<(Self, Vec<TableRowUpdate<BlockPrimaryIndex>>)> {
        // Create a provider with the wallet for contract deployment and interaction.
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());

        let contract = Simple::deploy(&provider).await.unwrap();
        info!(
            "Deployed Simple contract at address: {}",
            contract.address()
        );
        let contract_address = contract.address();
        let chain_id = ctx.rpc.get_chain_id().await.unwrap();
        let contract = Contract {
            address: *contract_address,
            chain_id,
        };

        let mut source =
            TableSource::SingleValues(SingleValuesExtractionArgs::new(Some(INDEX_SLOT)));
        let genesis_updates = source.init_contract_data(ctx, &contract).await;
        let indexing_genesis_block = ctx.block_number().await;
        let mut slot_inputs = SingleValuesExtractionArgs::slot_inputs();
        let pos = slot_inputs
            .iter()
            .position(|slot_input| slot_input.slot() == INDEX_SLOT)
            .unwrap();
        let secondary_index_slot_input = slot_inputs.remove(pos);

        // Defining the columns structure of the table from the source slots
        // This is depending on what is our data source, mappings and CSV both have their o
        // own way of defining their table.
        let columns = TableColumns {
            primary: TableColumn {
                name: BLOCK_COLUMN_NAME.to_string(),
                index: IndexType::Primary,
                multiplier: false,
                // Only valid for the identifier of block column, others are dummy.
                info: ColumnInfo::new(0, identifier_block_column(), 0, 0, 0, 0),
            },
            secondary: TableColumn {
                name: "column_value".to_string(),
                index: IndexType::Secondary,
                // here we put false always since these are not coming from a "merged" table
                multiplier: false,
                info: ColumnInfo::new_from_slot_input(
                    identifier_for_value_column(
                        &secondary_index_slot_input,
                        contract_address,
                        chain_id,
                        vec![],
                    ),
                    &secondary_index_slot_input,
                ),
            },
            rest: slot_inputs
                .iter()
                .enumerate()
                .map(|(i, slot_input)| {
                    let identifier =
                        identifier_for_value_column(slot_input, contract_address, chain_id, vec![]);
                    let info = ColumnInfo::new_from_slot_input(identifier, slot_input);
                    TableColumn {
                        name: format!("column_{}", i),
                        index: IndexType::None,
                        multiplier: false,
                        info,
                    }
                })
                .collect_vec(),
        };
        let row_unique_id = TableRowUniqueID::Single;
        let table = Table::new(
            indexing_genesis_block,
            "single_table".to_string(),
            columns,
            row_unique_id,
        )
        .await;
        Ok((
            Self {
                value_column: "".to_string(),
                source: source.clone(),
                table,
                contract,
                contract_extraction: ContractExtractionArgs {
                    slot: StorageSlot::Simple(CONTRACT_SLOT),
                },
            },
            genesis_updates,
        ))
    }

    pub(crate) async fn single_struct_test_case(
        ctx: &mut TestContext,
    ) -> Result<(Self, Vec<TableRowUpdate<BlockPrimaryIndex>>)> {
        // Create a provider with the wallet for contract deployment and interaction.
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());

        let contract = Simple::deploy(&provider).await.unwrap();
        info!(
            "Deployed Simple contract at address: {}",
            contract.address()
        );
        let contract_address = contract.address();
        let chain_id = ctx.rpc.get_chain_id().await.unwrap();
        let contract = Contract {
            address: *contract_address,
            chain_id,
        };

        let mut source = TableSource::SingleStruct(SingleStructExtractionArgs::new(&contract));
        let genesis_updates = source.init_contract_data(ctx, &contract).await;
        let indexing_genesis_block = ctx.block_number().await;
        let secondary_index_slot_input = SingleStructExtractionArgs::secondary_index_slot_input();
        let rest_slot_inputs = SingleStructExtractionArgs::rest_slot_inputs();

        // Defining the columns structure of the table from the source slots
        // This is depending on what is our data source, mappings and CSV both have their o
        // own way of defining their table.
        let columns = TableColumns {
            primary: TableColumn {
                name: BLOCK_COLUMN_NAME.to_string(),
                index: IndexType::Primary,
                multiplier: false,
                // Only valid for the identifier of block column, others are dummy.
                info: ColumnInfo::new(0, identifier_block_column(), 0, 0, 0, 0),
            },
            secondary: TableColumn {
                name: "column_value".to_string(),
                index: IndexType::Secondary,
                // here we put false always since these are not coming from a "merged" table
                multiplier: false,
                info: {
                    let id = identifier_for_value_column(
                        &secondary_index_slot_input,
                        contract_address,
                        chain_id,
                        vec![],
                    );
                    debug!("Single struct SECONDARY identifier: {id}");
                    ColumnInfo::new_from_slot_input(id, &secondary_index_slot_input)
                },
            },
            rest: rest_slot_inputs
                .iter()
                .enumerate()
                .map(|(i, slot_input)| {
                    let id =
                        identifier_for_value_column(slot_input, contract_address, chain_id, vec![]);
                    debug!("Single struct REST identifier-{i}: {id}");
                    let info = ColumnInfo::new_from_slot_input(id, slot_input);
                    TableColumn {
                        name: format!("column_{}", i),
                        index: IndexType::None,
                        multiplier: false,
                        info,
                    }
                })
                .collect_vec(),
        };
        let row_unique_id = TableRowUniqueID::Single;
        let table = Table::new(
            indexing_genesis_block,
            "single_struct_table".to_string(),
            columns,
            row_unique_id,
        )
        .await;
        Ok((
            Self {
                value_column: "".to_string(),
                source: source.clone(),
                table,
                contract,
                contract_extraction: ContractExtractionArgs {
                    slot: StorageSlot::Simple(CONTRACT_SLOT),
                },
            },
            genesis_updates,
        ))
    }

    pub(crate) async fn mapping_test_case(
        ctx: &mut TestContext,
    ) -> Result<(Self, Vec<TableRowUpdate<BlockPrimaryIndex>>)> {
        // Create a provider with the wallet for contract deployment and interaction.
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());

        let contract = Simple::deploy(&provider).await.unwrap();
        info!(
            "Deployed MAPPING Simple contract at address: {}",
            contract.address()
        );
        let contract_address = contract.address();
        let chain_id = ctx.rpc.get_chain_id().await.unwrap();
        let slot_input = MappingValuesExtractionArgs::slot_input();
        let key_id =
            identifier_for_mapping_key_column(MAPPING_SLOT, contract_address, chain_id, vec![]);
        let value_id = identifier_for_value_column(&slot_input, contract_address, chain_id, vec![]);
        // to toggle off and on
        let value_as_index = false;
        let (index_identifier, mapping_index, cell_identifier) = match value_as_index {
            true => (value_id, MappingIndex::Value(value_id), key_id),
            false => (key_id, MappingIndex::Key(key_id), value_id),
        };
        // mapping(uint256 => address) public m1
        let mapping_args = MappingValuesExtractionArgs::new(mapping_index);
        let mut source = TableSource::MappingValues((
            mapping_args,
            Some(LengthExtractionArgs {
                slot: LENGTH_SLOT,
                value: LENGTH_VALUE,
            }),
        ));
        let contract = Contract {
            address: *contract_address,
            chain_id,
        };

        let table_row_updates = source.init_contract_data(ctx, &contract).await;
        // Defining the columns structure of the table from the source slots
        // This is depending on what is our data source, mappings and CSV both have their o
        // own way of defining their table.
        let columns = TableColumns {
            primary: TableColumn {
                name: BLOCK_COLUMN_NAME.to_string(),
                index: IndexType::Primary,
                multiplier: false,
                // Only valid for the identifier of block column, others are dummy.
                info: ColumnInfo::new(0, identifier_block_column(), 0, 0, 0, 0),
            },
            secondary: TableColumn {
                name: if value_as_index {
                    MAPPING_VALUE_COLUMN
                } else {
                    MAPPING_KEY_COLUMN
                }
                .to_string(),
                index: IndexType::Secondary,
                // here important to put false since these are not coming from any "merged" table
                multiplier: false,
                info: ColumnInfo::new_from_slot_input(index_identifier, &slot_input),
            },
            rest: vec![TableColumn {
                name: if value_as_index {
                    MAPPING_KEY_COLUMN
                } else {
                    MAPPING_VALUE_COLUMN
                }
                .to_string(),
                index: IndexType::None,
                // here important to put false since these are not coming from any "merged" table
                multiplier: false,
                info: ColumnInfo::new_from_slot_input(cell_identifier, &slot_input),
            }],
        };
        let value_column = columns.rest[0].name.clone();
        debug!("MAPPING ZK COLUMNS -> {:?}", columns);
        let index_genesis_block = ctx.block_number().await;
        let row_unique_id = TableRowUniqueID::Mapping(key_id);
        let table = Table::new(
            index_genesis_block,
            "mapping_table".to_string(),
            columns,
            row_unique_id,
        )
        .await;

        Ok((
            Self {
                value_column,
                contract_extraction: ContractExtractionArgs {
                    slot: StorageSlot::Simple(CONTRACT_SLOT),
                },
                contract,
                source,
                table,
            },
            table_row_updates,
        ))
    }

    pub(crate) async fn mapping_struct_test_case(
        ctx: &mut TestContext,
    ) -> Result<(Self, Vec<TableRowUpdate<BlockPrimaryIndex>>)> {
        // Create a provider with the wallet for contract deployment and interaction.
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());

        let contract = Simple::deploy(&provider).await.unwrap();
        info!(
            "Deployed MAPPING Simple contract at address: {}",
            contract.address()
        );
        let contract_address = contract.address();
        let chain_id = ctx.rpc.get_chain_id().await.unwrap();
        let contract = Contract {
            address: *contract_address,
            chain_id,
        };
        let key_id = identifier_for_mapping_key_column(
            MAPPING_STRUCT_SLOT as u8,
            contract_address,
            chain_id,
            vec![],
        );
        let mut slot_inputs = LargeStruct::slot_inputs(MAPPING_STRUCT_SLOT as u8);
        let mut value_ids = slot_inputs
            .iter()
            .map(|slot_input| {
                identifier_for_value_column(slot_input, contract_address, chain_id, vec![])
            })
            .collect_vec();
        // to toggle off and on
        let value_as_index = false;
        let (mapping_index, secondary_column, rest_columns) = match value_as_index {
            true => {
                const TEST_VALUE_INDEX: usize = 1;
                let secondary_id = value_ids.remove(TEST_VALUE_INDEX);
                let secondary_slot_input = slot_inputs.remove(TEST_VALUE_INDEX);
                let secondary_column = TableColumn {
                    name: MAPPING_VALUE_COLUMN.to_string(),
                    index: IndexType::Secondary,
                    multiplier: false,
                    info: ColumnInfo::new_from_slot_input(secondary_id, &secondary_slot_input),
                };
                let mut rest_columns = value_ids
                    .into_iter()
                    .zip(slot_inputs.iter())
                    .enumerate()
                    .map(|(i, (id, slot_input))| TableColumn {
                        name: format!("mapping_value_column_{}", i),
                        index: IndexType::None,
                        multiplier: false,
                        info: ColumnInfo::new_from_slot_input(id, slot_input),
                    })
                    .collect_vec();
                rest_columns.push(TableColumn {
                    name: "mapping_key_column".to_string(),
                    index: IndexType::None,
                    multiplier: false,
                    // The slot input is useless for the key column.
                    info: ColumnInfo::new_from_slot_input(key_id, &slot_inputs[0]),
                });

                (
                    MappingIndex::Value(secondary_id),
                    secondary_column,
                    rest_columns,
                )
            }
            false => {
                let secondary_column = TableColumn {
                    name: MAPPING_KEY_COLUMN.to_string(),
                    index: IndexType::Secondary,
                    multiplier: false,
                    info: ColumnInfo::new_from_slot_input(
                        key_id,
                        // The slot input is useless for the key column.
                        &slot_inputs[0],
                    ),
                };
                let rest_columns = value_ids
                    .into_iter()
                    .zip(slot_inputs.iter())
                    .enumerate()
                    .map(|(i, (id, slot_input))| TableColumn {
                        name: format!("mapping_value_column_{}", i),
                        index: IndexType::None,
                        multiplier: false,
                        info: ColumnInfo::new_from_slot_input(id, slot_input),
                    })
                    .collect_vec();

                (MappingIndex::Key(key_id), secondary_column, rest_columns)
            }
        };
        let mapping_args = MappingStructExtractionArgs::new(mapping_index, &contract);
        let mut source = TableSource::MappingStruct((mapping_args, None));
        let table_row_updates = source.init_contract_data(ctx, &contract).await;
        // Defining the columns structure of the table from the source slots
        // This is depending on what is our data source, mappings and CSV both have their o
        // own way of defining their table.
        let columns = TableColumns {
            primary: TableColumn {
                name: BLOCK_COLUMN_NAME.to_string(),
                index: IndexType::Primary,
                multiplier: false,
                // Only valid for the identifier of block column, others are dummy.
                info: ColumnInfo::new(0, identifier_block_column(), 0, 0, 0, 0),
            },
            secondary: secondary_column,
            rest: rest_columns,
        };
        let value_column = columns.rest[0].name.clone();
        debug!("MAPPING STRUCT ZK COLUMNS -> {:?}", columns);
        let index_genesis_block = ctx.block_number().await;
        let row_unique_id = TableRowUniqueID::Mapping(key_id);
        let table = Table::new(
            index_genesis_block,
            "mapping_struct_table".to_string(),
            columns,
            row_unique_id,
        )
        .await;

        Ok((
            Self {
                value_column,
                contract_extraction: ContractExtractionArgs {
                    slot: StorageSlot::Simple(CONTRACT_SLOT),
                },
                contract,
                source,
                table,
            },
            table_row_updates,
        ))
    }

    pub async fn run(
        &mut self,
        ctx: &mut TestContext,
        genesis_change: Vec<TableRowUpdate<BlockPrimaryIndex>>,
        changes: Vec<ChangeType>,
    ) -> Result<()> {
        // Call the contract function to set the test data.
        log::info!("Applying initial updates to contract done");
        let bn = ctx.block_number().await as BlockPrimaryIndex;

        // we first run the initial preprocessing and db creation.
        let metadata_hash = self.run_mpt_preprocessing(ctx, bn).await?;
        // then we run the creation of our tree
        self.run_lagrange_preprocessing(ctx, bn, genesis_change, &metadata_hash)
            .await?;

        log::info!("FIRST block {bn} finished proving. Moving on to update",);

        for ut in changes {
            let table_row_updates = self
                .source
                .random_contract_update(ctx, &self.contract, ut)
                .await;
            let bn = ctx.block_number().await as BlockPrimaryIndex;
            log::info!("Applying follow up updates to contract done - now at block {bn}",);
            // we first run the initial preprocessing and db creation.
            // NOTE: we don't show copy on write here - the fact of only reproving what has been
            // updated, as this is not new from v0.
            // TODO: implement copy on write mechanism for MPT
            let metadata_hash = self.run_mpt_preprocessing(ctx, bn).await?;
            self.run_lagrange_preprocessing(ctx, bn, table_row_updates, &metadata_hash)
                .await?;
        }
        Ok(())
    }

    // separate function only dealing with preprocesisng MPT proofs
    // This function is "generic" as it can table a table description
    async fn run_lagrange_preprocessing(
        &mut self,
        ctx: &mut TestContext,
        bn: BlockPrimaryIndex,
        // Note there is only one entry for a single variable update, but multiple for mappings for
        // example
        updates: Vec<TableRowUpdate<BlockPrimaryIndex>>,
        expected_metadata_hash: &HashOutput,
    ) -> Result<()> {
        let current_block = ctx.block_number().await;
        // apply the new cells to the trees
        // NOTE ONLY the rest of the cells, not including the secondary one !
        let mut rows_update = Vec::new();
        for row_update in updates {
            let tree_update = match row_update {
                TableRowUpdate::Insertion(ref new_cells, _) => {
                    let tree_update = self
                        .table
                        .apply_cells_update(new_cells.clone(), TreeUpdateType::Insertion)
                        .await
                        .expect("can't insert in cells tree");
                    // it may be an insertion where the cells already existed before ("delete  +
                    // insertio" = update on secondary index value) so we first fetch the previous
                    // cells collection and merge with the new one. THis allows us to not having
                    // the reprove the cells tree from scratch in that case !
                    // NOTE: this assume we go over the current row tree
                    let previous_row = match new_cells.previous_row_key != Default::default() {
                        true => Row {
                            k: new_cells.previous_row_key.clone(),
                            payload: self.table.row.fetch(&new_cells.previous_row_key).await,
                        },
                        false => Row::default(),
                    };
                    let new_cell_collection = row_update.updated_cells_collection(
                        self.table.columns.secondary_column().identifier(),
                        bn,
                        &previous_row.payload.cells,
                    );
                    let new_row_key = tree_update.new_row_key.clone();
                    let row_payload = ctx
                        .prove_cells_tree(
                            &self.table,
                            current_block as usize,
                            previous_row,
                            new_cell_collection,
                            tree_update,
                        )
                        .await;
                    TreeRowUpdate::Insertion(Row {
                        k: new_row_key,
                        payload: row_payload,
                    })
                }
                TableRowUpdate::Update(ref new_cells) => {
                    let tree_update = self
                        .table
                        .apply_cells_update(new_cells.clone(), TreeUpdateType::Update)
                        .await
                        .expect("can't insert in cells tree");
                    // fetch all the current cells, merge with the new modified ones
                    let old_row = self
                        .table
                        .row
                        .try_fetch(&new_cells.previous_row_key)
                        .await
                        .expect("unable to find previous row");
                    let new_cell_collection = row_update.updated_cells_collection(
                        self.table.columns.secondary_column().identifier(),
                        bn,
                        &old_row.cells,
                    );
                    let new_row_key = tree_update.new_row_key.clone();
                    let row_payload = ctx
                        .prove_cells_tree(
                            &self.table,
                            current_block as usize,
                            Row {
                                k: new_cells.previous_row_key.clone(),
                                payload: old_row,
                            },
                            new_cell_collection,
                            tree_update,
                        )
                        .await;
                    TreeRowUpdate::Update(Row {
                        k: new_row_key,
                        payload: row_payload,
                    })
                }
                // in this case, the translation is stupid but TreeRowUpdate contains different
                // values than TableRowUpdate. The latter is only related to tree information,
                // containing output of previous steps, the former is only created from the updates
                // of a table, this is the source.
                TableRowUpdate::Deletion(k) => TreeRowUpdate::Deletion(k.clone()),
            };
            rows_update.push(tree_update);
        }
        info!("Generated final CELLs tree proofs for block {current_block}");
        let updates = self.table.apply_row_update(bn, rows_update).await?;
        info!("Applied updates to row tree");
        let index_node = ctx
            .prove_update_row_tree(bn, &self.table, updates)
            .await
            .expect("unable to prove row tree");
        info!("Generated final ROWs tree proofs for block {current_block}");

        // NOTE the reason we separate and use block number as IndexTreeKey is because this index
        // could be different if we were using NOT block number. It should be the index of the
        // enumeration, something that may arise during the query when building a result tree.
        // NOTE2: There is no "init" field here since we _always_ insert in the index tree by
        // definition. This is a core assumption we currently have and that will not change in the
        // short term.
        let index_update = IndexUpdate {
            added_index: (bn, index_node),
        };
        let updates = self
            .table
            .apply_index_update(index_update)
            .await
            .expect("can't update index tree");
        info!("Applied updates to index tree for block {current_block}");
        let _root_proof_key = ctx
            .prove_update_index_tree(bn, &self.table, updates.plan)
            .await;
        info!("Generated final BLOCK tree proofs for block {current_block}");
        let _ = ctx
            .prove_ivc(
                &self.table.public_name,
                bn,
                &self.table.index,
                expected_metadata_hash,
            )
            .await;
        info!("Generated final IVC proof for block {}", current_block,);

        Ok(())
    }

    // separate function only dealing with preprocessing MPT proofs
    async fn run_mpt_preprocessing(
        &self,
        ctx: &mut TestContext,
        bn: BlockPrimaryIndex,
    ) -> Result<HashOutput> {
        let contract_proof_key = ProofKey::ContractExtraction((self.contract.address, bn));
        let contract_proof = match ctx.storage.get_proof_exact(&contract_proof_key) {
            Ok(proof) => {
                info!(
                    "Loaded Contract Extraction (C.3) proof for block number {}",
                    bn
                );
                proof
            }
            Err(_) => {
                let contract_proof = ctx
                    .prove_contract_extraction(
                        &self.contract.address,
                        self.contract_extraction.slot.clone(),
                        bn,
                    )
                    .await;
                ctx.storage
                    .store_proof(contract_proof_key, contract_proof.clone())?;
                info!(
                    "Generated Contract Extraction (C.3) proof for block number {}",
                    bn
                );
                {
                    let pvk = ProofWithVK::deserialize(&contract_proof)?;
                    let pis =
                        contract_extraction::PublicInputs::from_slice(&pvk.proof().public_inputs);
                    debug!(
                        " CONTRACT storage root pis.storage_root() {:?}",
                        hex::encode(
                            pis.root_hash_field()
                                .into_iter()
                                .flat_map(|u| u.to_be_bytes())
                                .collect::<Vec<_>>()
                        )
                    );
                }
                contract_proof
            }
        };

        // We look if block proof has already been generated for this block
        // since it is the same between proofs
        let block_proof_key = ProofKey::BlockExtraction(bn as BlockPrimaryIndex);
        let block_proof = match ctx.storage.get_proof_exact(&block_proof_key) {
            Ok(proof) => {
                info!(
                    "Loaded Block Extraction (C.4) proof for block number {}",
                    bn
                );
                proof
            }
            Err(_) => {
                let proof = ctx
                    .prove_block_extraction(bn as BlockPrimaryIndex)
                    .await
                    .unwrap();
                ctx.storage.store_proof(block_proof_key, proof.clone())?;
                info!(
                    "Generated Block Extraction (C.4) proof for block number {}",
                    bn
                );
                proof
            }
        };

        let table_id = &self.table.public_name.clone();
        // we construct the proof key for both mappings and single variable in the same way since
        // it is derived from the table id which should be different for any tables we create.
        let value_key = ProofKey::ValueExtraction((table_id.clone(), bn as BlockPrimaryIndex));
        // final extraction for single variables combining the different proofs generated before
        let final_key = ProofKey::FinalExtraction((table_id.clone(), bn as BlockPrimaryIndex));
        let (extraction, metadata_hash) = self
            .source
            .generate_extraction_proof_inputs(ctx, &self.contract, value_key)
            .await?;

        // no need to generate it if it's already present
        if ctx.storage.get_proof_exact(&final_key).is_err() {
            let proof = ctx
                .prove_final_extraction(contract_proof, block_proof, extraction)
                .await
                .unwrap();
            ctx.storage
                .store_proof(final_key, proof.clone())
                .expect("unable to save in storage?");
            info!("Generated Final Extraction (C.5.1) proof for block {bn}");
        }
        info!("Generated ALL MPT preprocessing proofs for block {bn}");
        Ok(metadata_hash)
    }
}

#[derive(Clone, Debug)]
pub enum UpdateSimpleStorage {
    SingleValues(SimpleSingleValue),
    MappingValues(Vec<MappingValuesUpdate>),
    SingleStruct(LargeStruct),
    MappingStruct(Vec<MappingStructUpdate>),
}

/// Represents the update that can come from the chain
#[derive(Clone, Debug)]
pub enum MappingValuesUpdate {
    // key, value
    Deletion(U256, U256),
    // key, previous_value, new_value
    Update(U256, U256, U256),
    // key, value
    Insertion(U256, U256),
}

/// passing form the rust type to the solidity type
impl From<&MappingValuesUpdate> for MappingOperation {
    fn from(value: &MappingValuesUpdate) -> Self {
        Self::from(match value {
            MappingValuesUpdate::Deletion(_, _) => 0,
            MappingValuesUpdate::Update(_, _, _) => 1,
            MappingValuesUpdate::Insertion(_, _) => 2,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SimpleSingleValue {
    pub(crate) s1: bool,
    pub(crate) s2: U256,
    pub(crate) s3: String,
    pub(crate) s4: Address,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct LargeStruct {
    pub(crate) field1: U256,
    pub(crate) field2: u128,
    pub(crate) field3: u128,
}

impl LargeStruct {
    pub const FIELD_NUM: usize = 3;

    pub fn new(field1: U256, field2: u128, field3: u128) -> Self {
        Self {
            field1,
            field2,
            field3,
        }
    }

    pub fn slot_inputs(slot: u8) -> Vec<SlotInput> {
        vec![
            SlotInput::new(slot, 0, 256, 0),
            // Big-endian layout
            SlotInput::new(slot, 16, 128, 1),
            SlotInput::new(slot, 0, 128, 1),
        ]
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.field1
            .to_be_bytes::<{ U256::BYTES }>()
            .into_iter()
            .chain(self.field2.to_be_bytes())
            .chain(self.field3.to_be_bytes())
            .collect()
    }

    // The LargeStruct has 3 fields, the first one is an EVM word (an Uint256),
    // and the last two are located in one EVM word (each is an Uint128).
    pub fn metadata(slot: u8, chain_id: u64, contract_address: &Address) -> Vec<MetadataGadget> {
        let table_info =
            compute_table_info(Self::slot_inputs(slot), contract_address, chain_id, vec![]);
        let ids1 = table_info[..1]
            .iter()
            .map(|c| c.identifier().to_canonical_u64())
            .collect_vec();
        let ids2 = table_info[1..]
            .iter()
            .map(|c| c.identifier().to_canonical_u64())
            .collect_vec();
        vec![
            MetadataGadget::new(table_info.clone(), &ids1, 0),
            MetadataGadget::new(table_info, &ids2, 1),
        ]
    }
}

impl From<simpleStructReturn> for LargeStruct {
    fn from(res: simpleStructReturn) -> Self {
        Self {
            field1: res.field1,
            field2: res.field2,
            field3: res.field3,
        }
    }
}

impl From<structMappingReturn> for LargeStruct {
    fn from(res: structMappingReturn) -> Self {
        Self {
            field1: res.field1,
            field2: res.field2,
            field3: res.field3,
        }
    }
}

impl From<&[[u8; MAPPING_LEAF_VALUE_LEN]]> for LargeStruct {
    fn from(fields: &[[u8; MAPPING_LEAF_VALUE_LEN]]) -> Self {
        assert_eq!(fields.len(), Self::FIELD_NUM);

        let fields = fields
            .iter()
            .cloned()
            .map(U256::from_be_bytes)
            .collect_vec();

        let field1 = fields[0];
        let field2 = fields[1].to();
        let field3 = fields[2].to();
        Self {
            field1,
            field2,
            field3,
        }
    }
}
#[derive(Clone, Debug)]
pub enum MappingStructUpdate {
    // key, struct value
    Deletion(U256, LargeStruct),
    // key, previous struct value, new struct value
    Update(U256, LargeStruct, LargeStruct),
    // key, struct value
    Insertion(U256, LargeStruct),
}

impl From<&MappingStructUpdate> for MappingOperation {
    fn from(mapping: &MappingStructUpdate) -> Self {
        Self::from(match mapping {
            MappingStructUpdate::Deletion(_, _) => 0,
            MappingStructUpdate::Update(_, _, _) => 1,
            MappingStructUpdate::Insertion(_, _) => 2,
        })
    }
}

impl UpdateSimpleStorage {
    // This function applies the update in _one_ transaction so that Anvil only moves by one block
    // so we can test the "subsequent block"
    pub async fn apply_to<T: Transport + Clone, P: Provider<T, N>, N: Network>(
        &self,
        contract: &SimpleInstance<T, P, N>,
    ) {
        match self {
            UpdateSimpleStorage::SingleValues(ref single) => {
                Self::update_single_values(contract, single).await
            }
            UpdateSimpleStorage::MappingValues(ref updates) => {
                Self::update_mapping_values(contract, updates).await
            }
            UpdateSimpleStorage::SingleStruct(ref single) => {
                Self::update_single_struct(contract, single).await
            }
            UpdateSimpleStorage::MappingStruct(ref updates) => {
                Self::update_mapping_struct(contract, updates).await
            }
        }
    }

    async fn update_single_values<T: Transport + Clone, P: Provider<T, N>, N: Network>(
        contract: &SimpleInstance<T, P, N>,
        values: &SimpleSingleValue,
    ) {
        let b = contract.setSimples(values.s1, values.s2, values.s3.clone(), values.s4);
        b.send().await.unwrap().watch().await.unwrap();
        log::info!("Updated simple contract single values");
    }

    async fn update_mapping_values<T: Transport + Clone, P: Provider<T, N>, N: Network>(
        contract: &SimpleInstance<T, P, N>,
        values: &[MappingValuesUpdate],
    ) {
        let contract_changes = values
            .iter()
            .map(|tuple| {
                let op: MappingOperation = tuple.into();
                let (k, v) = match tuple {
                    MappingValuesUpdate::Deletion(k, _) => (*k, *DEFAULT_ADDRESS),
                    MappingValuesUpdate::Update(k, _, v) | MappingValuesUpdate::Insertion(k, v) => {
                        (*k, Address::from_slice(&v.to_be_bytes_trimmed_vec()))
                    }
                };
                MappingChange {
                    key: k,
                    value: v,
                    operation: op.into(),
                }
            })
            .collect::<Vec<_>>();

        let b = contract.changeMapping(contract_changes);
        b.send().await.unwrap().watch().await.unwrap();
        {
            // sanity check
            for op in values {
                match op {
                    MappingValuesUpdate::Deletion(k, _) => {
                        let res = contract.m1(*k).call().await.unwrap();
                        let vu: U256 = res._0.into_word().into();
                        let is_correct = vu == U256::from(0);
                        assert!(is_correct, "key deletion not correct on contract");
                    }
                    MappingValuesUpdate::Insertion(k, v) => {
                        let res = contract.m1(*k).call().await.unwrap();
                        let newv: U256 = res._0.into_word().into();
                        let is_correct = newv == *v;
                        assert!(is_correct, "key insertion not correct on contract");
                    }
                    MappingValuesUpdate::Update(k, _, v) => {
                        let res = contract.m1(*k).call().await.unwrap();
                        let newv: U256 = res._0.into_word().into();
                        let is_correct = newv == *v;
                        assert!(is_correct, "KEY Updated, new value valid ? {is_correct}");
                    }
                }
            }
        }
        log::info!("Updated simple contract single values");
    }

    async fn update_single_struct<T: Transport + Clone, P: Provider<T, N>, N: Network>(
        contract: &SimpleInstance<T, P, N>,
        single: &LargeStruct,
    ) {
        let b = contract.setSimpleStruct(single.field1, single.field2, single.field3);
        b.send().await.unwrap().watch().await.unwrap();
        log::info!("Updated simple contract for single struct");
    }

    async fn update_mapping_struct<T: Transport + Clone, P: Provider<T, N>, N: Network>(
        contract: &SimpleInstance<T, P, N>,
        values: &[MappingStructUpdate],
    ) {
        let contract_changes = values
            .iter()
            .map(|tuple| {
                let op: MappingOperation = tuple.into();
                let (key, field1, field2, field3) = match tuple {
                    MappingStructUpdate::Deletion(k, v) => (*k, v.field1, v.field2, v.field3),
                    MappingStructUpdate::Update(k, _, v) | MappingStructUpdate::Insertion(k, v) => {
                        (*k, v.field1, v.field2, v.field3)
                    }
                };
                MappingStructChange {
                    key,
                    field1,
                    field2,
                    field3,
                    operation: op.into(),
                }
            })
            .collect_vec();

        let b = contract.changeMappingStruct(contract_changes);
        b.send().await.unwrap().watch().await.unwrap();
        {
            // sanity check
            for op in values {
                match op {
                    MappingStructUpdate::Deletion(k, _) => {
                        let res = contract.structMapping(*k).call().await.unwrap();
                        assert_eq!(
                            LargeStruct::from(res),
                            LargeStruct::new(U256::from(0), 0, 0)
                        );
                    }
                    MappingStructUpdate::Insertion(k, v) | MappingStructUpdate::Update(k, _, v) => {
                        let res = contract.structMapping(*k).call().await.unwrap();
                        debug!("Set mapping struct: key = {k}, value = {v:?}");
                        assert_eq!(&LargeStruct::from(res), v);
                    }
                }
            }
        }
        log::info!("Updated simple contract for single struct");
    }
}

#[derive(Clone, Debug)]
pub enum ChangeType {
    Deletion,
    Insertion,
    Update(UpdateType),
    Silent,
}

#[derive(Clone, Debug)]
pub enum UpdateType {
    SecondaryIndex,
    Rest,
}

/// Represents in a generic way the value present in a row from a table
/// TODO: add the first index in generic way as well for CSV
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct TableRowValues<PrimaryIndex> {
    // cells without the secondary index
    pub current_cells: Vec<Cell>,
    pub current_secondary: Option<SecondaryIndexCell>,
    pub primary: PrimaryIndex,
}

impl<PrimaryIndex: Clone + Default + PartialEq + Eq> TableRowValues<PrimaryIndex> {
    // Compute the update from the current values and the new values
    // NOTE: if the table doesn't have a secondary index, the table row update will have all row
    // keys set to default. This must later be fixed before "sending" this to the update table
    // logic. This only happens for merge table. After this call, the secondary index is then
    // fixed.
    pub fn compute_update(&self, new: &Self) -> Vec<TableRowUpdate<PrimaryIndex>> {
        // this is initialization
        if self == &Self::default() {
            let cells_update = CellsUpdate {
                previous_row_key: RowTreeKey::default(),
                new_row_key: (new.current_secondary.clone().unwrap_or_default()).into(),
                updated_cells: new.current_cells.clone(),
                primary: new.primary.clone(),
            };
            return vec![TableRowUpdate::Insertion(
                cells_update,
                new.current_secondary.clone().unwrap_or_default(),
            )];
        }
        let new_secondary = new.current_secondary.clone().unwrap_or_default();
        let previous_secondary = self.current_secondary.clone().unwrap_or_default();

        // the cells columns are fixed so we can compare
        assert!(self.current_cells.len() == new.current_cells.len());
        let updated_cells = self
            .current_cells
            .iter()
            .filter_map(|current| {
                let new = new
                    .current_cells
                    .iter()
                    .find(|new| current.identifier() == new.identifier())
                    .expect("missing cell");
                if new.value() != current.value() {
                    // there is an update!
                    Some(new.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let cells_update = CellsUpdate {
            // Both keys may be the same if the secondary index value
            // did not change
            new_row_key: (&new_secondary).into(),
            previous_row_key: (&previous_secondary).into(),
            updated_cells,
            primary: new.primary.clone(),
        };

        assert!(
            previous_secondary.cell().identifier() == new_secondary.cell().identifier(),
            "ids are different between updates?"
        );
        assert!(
            previous_secondary.rest() == new_secondary.rest(),
            "computing update from different row"
        );
        match previous_secondary.cell() != new_secondary.cell() {
            true => vec![
                // We first delete then insert a new row in the case of a secondary index value
                // change
                TableRowUpdate::Deletion(previous_secondary.into()),
                TableRowUpdate::Insertion(cells_update, new_secondary.clone()),
            ],
            // no update on the secondary index value
            false if !cells_update.updated_cells.is_empty() => {
                vec![TableRowUpdate::Update(cells_update)]
            }
            false => {
                vec![]
            }
        }
    }
}

/// The structure representing the updates that have happened on a table
/// This is computed from the update of a contract in the case of the current test, but
/// should be given directly in case of CSV file.
#[derive(Clone, Debug)]
pub enum TableRowUpdate<PrimaryIndex> {
    /// A row to be deleted
    Deletion(RowTreeKey),
    /// NOTE : this only includes changes on the regular non indexed cells.
    /// This must NOT include an update on the secondary index value
    /// A new secondary index value is translated to a deletion and then a new insert
    /// since that is what must happen at the tree level where we delete the node corresponding to
    /// the previous secondary index value.
    Update(CellsUpdate<PrimaryIndex>),
    /// Used to insert a new row from scratch
    Insertion(CellsUpdate<PrimaryIndex>, SecondaryIndexCell),
}

impl<PrimaryIndex> TableRowUpdate<PrimaryIndex>
where
    PrimaryIndex: PartialEq + Eq + Default + Clone + Default,
{
    // Returns the full cell collection to put inside the JSON row payload
    fn updated_cells_collection(
        &self,
        secondary_column: ColumnID,
        new_primary: PrimaryIndex,
        previous: &CellCollection<PrimaryIndex>,
    ) -> CellCollection<PrimaryIndex> {
        let new_cells = CellCollection(
            match self {
                TableRowUpdate::Deletion(_) => vec![],
                TableRowUpdate::Insertion(cells, index) => {
                    let rest = cells.updated_cells.clone();
                    // we want the new secondary index value to put inside the CellCollection of the JSON
                    // at the first position
                    let mut full = vec![index.cell()];
                    full.extend(rest);
                    full
                }
                TableRowUpdate::Update(cells) => cells.updated_cells.clone(),
            }
            .into_iter()
            .map(|c| {
                (
                    c.identifier(),
                    CellInfo {
                        primary: new_primary.clone(),
                        value: c.value(),
                    },
                )
            })
            .collect(),
        );

        let mut new_collection = previous.merge_with_update(&new_cells);
        let mut secondary_cell = new_collection
            .find_by_column(secondary_column)
            .expect("new collection should have secondary index")
            .clone();
        // NOTE: ! we _always_ update the new primary of a row that is being updated, since we are
        // always reproving it !
        secondary_cell.primary = new_primary;
        new_collection.update_column(secondary_column, secondary_cell);
        new_collection
    }
}

impl TableIndexing {
    pub fn table_info(&self) -> TableInfo {
        TableInfo {
            public_name: self.table.public_name.clone(),
            value_column: self.value_column.clone(),
            chain_id: self.contract.chain_id,
            columns: self.table.columns.clone(),
            contract_address: self.contract.address,
            source: self.source.clone(),
            row_unique_id: self.table.row_unique_id.clone(),
        }
    }
}
