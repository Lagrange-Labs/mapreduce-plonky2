//! Test case for local Simple contract
//! Reference `test-contracts/src/Simple.sol` for the details of Simple contract.

use anyhow::Result;
use itertools::Itertools;
use log::{debug, info};
use mp2_v1::{
    api::SlotInput,
    contract_extraction,
    indexing::{
        block::BlockPrimaryIndex,
        cell::Cell,
        row::{CellCollection, CellInfo, Row, RowTreeKey},
        ColumnID,
    },
    values_extraction::{
        identifier_block_column, identifier_for_data_column, identifier_for_gas_used_column,
        identifier_for_inner_mapping_key_column, identifier_for_outer_mapping_key_column,
        identifier_for_topic_column, identifier_for_value_column, DATA_NAME, GAS_USED_NAME,
        TOPIC_NAME,
    },
};

use rand::{thread_rng, Rng};
use ryhope::storage::RoEpochKvStorage;

use crate::common::{
    bindings::eventemitter::EventEmitter::{self, EventEmitterInstance},
    cases::{
        contract::Contract,
        identifier_for_mapping_key_column,
        slot_info::{
            LargeStruct, SimpleMapping, SimpleNestedMapping, StructMapping, StructNestedMapping,
        },
        table_source::{
            ContractExtractionArgs, MappingExtractionArgs, MappingIndex, MergeSource,
            ReceiptExtractionArgs, SingleExtractionArgs, TableSource,
        },
        TableIndexing,
    },
    proof_storage::{ProofKey, ProofStorage},
    rowtree::SecondaryIndexCell,
    table::{
        CellsUpdate, IndexType, IndexUpdate, Table, TableColumn, TableColumns, TableRowUniqueID,
        TreeRowUpdate, TreeUpdateType,
    },
    TableInfo, TestContext,
};

use alloy::{
    contract::private::{Network, Provider, Transport},
    network::{Ethereum, TransactionBuilder},
    primitives::U256,
    providers::{ext::AnvilApi, ProviderBuilder},
    sol_types::SolEvent,
};
use mp2_common::{
    eth::{EventLogInfo, StorageSlot},
    proof::ProofWithVK,
    types::HashOutput,
};

/// Test slots for single values extraction
pub(crate) const SINGLE_SLOTS: [u8; 4] = [0, 1, 2, 3];

/// Test slot for mapping values extraction
const MAPPING_SLOT: u8 = 4;

/// Test slot for length extraction
#[allow(dead_code)]
const LENGTH_SLOT: u8 = 1;

/// Test length value for length extraction
#[allow(dead_code)]
const LENGTH_VALUE: u8 = 2;

/// Test slot for contract extraction
const CONTRACT_SLOT: usize = 1;

/// Test slot for single Struct extraction
pub(crate) const SINGLE_STRUCT_SLOT: usize = 6;

/// Test slot for mapping Struct extraction
const MAPPING_STRUCT_SLOT: usize = 8;

/// Test slot for mapping of single value mappings extraction
pub(crate) const MAPPING_OF_SINGLE_VALUE_MAPPINGS_SLOT: u8 = 9;

/// Test slot for mapping of struct mappings extraction
pub(crate) const MAPPING_OF_STRUCT_MAPPINGS_SLOT: u8 = 10;

/// human friendly name about the column containing the block number
pub(crate) const BLOCK_COLUMN_NAME: &str = "block_number";
pub(crate) const SINGLE_SECONDARY_COLUMN: &str = "single_secondary_column";
pub(crate) const MAPPING_KEY_COLUMN: &str = "mapping_key_column";
pub(crate) const MAPPING_VALUE_COLUMN: &str = "mapping_value_column";
pub(crate) const MAPPING_OF_MAPPINGS_OUTER_KEY_COLUMN: &str =
    "mapping_of_mappings_outer_key_column";
pub(crate) const MAPPING_OF_MAPPINGS_INNER_KEY_COLUMN: &str =
    "mapping_of_mappings_inner_key_column";
pub(crate) const MAPPING_OF_MAPPINGS_VALUE_COLUMN: &str = "mapping_of_mappings_value_column";

/// Construct the all slot inputs for single value testing.
fn single_value_slot_inputs() -> Vec<SlotInput> {
    let mut slot_inputs = SINGLE_SLOTS
        .map(|slot| SlotInput::new(slot, 0, 32, 0))
        .to_vec();

    // Add the Struct single slots.
    let struct_slots = LargeStruct::slot_inputs(SINGLE_STRUCT_SLOT as u8);
    slot_inputs.extend(struct_slots);

    slot_inputs
}

pub(crate) const TX_INDEX_COLUMN: &str = "tx_index";

impl<T: TableSource> TableIndexing<T> {
    pub(crate) async fn merge_table_test_case(
        ctx: &mut TestContext,
    ) -> Result<(
        TableIndexing<MergeSource>,
        Vec<TableRowUpdate<BlockPrimaryIndex>>,
    )> {
        // Deploy the simple contract.
        let contract = Contract::deploy_simple_contract(ctx).await;
        let contract_address = contract.address;
        let chain_id = contract.chain_id;

        // This test puts the mapping value as secondary index so there is no index for the
        // single variable slots.
        let single_source = {
            let slot_inputs = single_value_slot_inputs();
            SingleExtractionArgs::new(None, slot_inputs)
        };
        let single_columns = single_source
            .slot_inputs
            .iter()
            .enumerate()
            .map(|(i, slot_input)| {
                let identifier =
                    identifier_for_value_column(slot_input, &contract_address, chain_id, vec![]);

                TableColumn {
                    name: format!("single_column_{i}"),
                    index: IndexType::None,
                    // ALL single columns are "multiplier" since we do tableA * D(tableB), i.e. all
                    // entries of table A are repeated for each entry of table B.
                    multiplier: true,
                    identifier,
                }
            })
            .collect_vec();
        let (mapping_secondary_column, mapping_rest_columns, row_unique_id, mapping_source) = {
            let slot_inputs = LargeStruct::slot_inputs(MAPPING_STRUCT_SLOT as u8);
            let key_id = identifier_for_mapping_key_column(
                MAPPING_STRUCT_SLOT as u8,
                &contract_address,
                chain_id,
                vec![],
            );
            let mut value_ids = slot_inputs
                .iter()
                .map(|slot_input| {
                    identifier_for_value_column(slot_input, &contract_address, chain_id, vec![])
                })
                .collect_vec();
            // Switch the test index.
            // let mapping_index = MappingIndex::Value(value_ids(1));
            let mapping_index = MappingIndex::OuterKey(key_id);
            let source = MappingExtractionArgs::new(
                MAPPING_STRUCT_SLOT as u8,
                mapping_index,
                slot_inputs.clone(),
                None,
            );
            // Construct the table columns.
            let (secondary_column, rest_columns) = match mapping_index {
                MappingIndex::OuterKey(_) => {
                    let secondary_column = TableColumn {
                        name: MAPPING_KEY_COLUMN.to_string(),
                        index: IndexType::Secondary,
                        multiplier: false,
                        identifier: key_id,
                    };
                    let rest_columns = value_ids
                        .into_iter()
                        .enumerate()
                        .map(|(i, id)| TableColumn {
                            name: format!("{MAPPING_VALUE_COLUMN}_{i}"),
                            index: IndexType::None,
                            multiplier: false,
                            identifier: id,
                        })
                        .collect_vec();

                    (secondary_column, rest_columns)
                }
                MappingIndex::Value(secondary_value_id) => {
                    let pos = value_ids
                        .iter()
                        .position(|id| id == &secondary_value_id)
                        .unwrap();
                    let secondary_id = value_ids.remove(pos);

                    let secondary_column = TableColumn {
                        name: MAPPING_VALUE_COLUMN.to_string(),
                        index: IndexType::Secondary,
                        multiplier: false,
                        identifier: secondary_id,
                    };
                    let mut rest_columns = value_ids
                        .into_iter()
                        .enumerate()
                        .map(|(i, id)| TableColumn {
                            name: format!("{MAPPING_VALUE_COLUMN}_{i}"),
                            index: IndexType::None,
                            multiplier: false,
                            identifier: id,
                        })
                        .collect_vec();
                    rest_columns.push(TableColumn {
                        name: MAPPING_KEY_COLUMN.to_string(),
                        index: IndexType::None,
                        multiplier: false,
                        // The slot input is useless for the key column.
                        identifier: key_id,
                    });

                    (secondary_column, rest_columns)
                }
                _ => unreachable!(),
            };
            let row_unique_id = TableRowUniqueID::Mapping(key_id);

            (secondary_column, rest_columns, row_unique_id, source)
        };
        let mut source = MergeSource::new(single_source, mapping_source);
        let genesis_change = source.init_contract_data(ctx, &contract).await;
        let value_column = mapping_rest_columns[0].name.clone();
        let all_columns = [single_columns.as_slice(), &mapping_rest_columns].concat();
        let columns = TableColumns {
            primary: TableColumn {
                name: BLOCK_COLUMN_NAME.to_string(),
                index: IndexType::Primary,
                // it doesn't matter for this one since block is "outside" of the table definition
                // really, it is a special column we add
                multiplier: true,
                // Only valid for the identifier of block column, others are dummy.
                identifier: identifier_block_column(),
            },
            secondary: mapping_secondary_column,
            rest: all_columns,
        };
        info!(
            "Table information:\n{}\n",
            serde_json::to_string_pretty(&columns)?
        );

        let indexing_genesis_block = ctx.block_number().await;
        let table = Table::new(
            indexing_genesis_block,
            "merged_table".to_string(),
            columns,
            row_unique_id,
        )
        .await?;
        Ok((
            TableIndexing::<MergeSource> {
                value_column,
                source: source.clone(),
                table,
                contract,
                contract_extraction: Some(ContractExtractionArgs {
                    slot: StorageSlot::Simple(CONTRACT_SLOT),
                }),
            },
            genesis_change,
        ))
    }

    /// The single value test case includes the all single value slots and one single Struct slot.
    pub(crate) async fn single_value_test_case(
        ctx: &mut TestContext,
    ) -> Result<(
        TableIndexing<SingleExtractionArgs>,
        Vec<TableRowUpdate<BlockPrimaryIndex>>,
    )> {
        let rng = &mut thread_rng();

        // Deploy the simple contract.
        let contract = Contract::deploy_simple_contract(ctx).await;
        let contract_address = contract.address;
        let chain_id = contract.chain_id;

        let mut source = {
            let slot_inputs = single_value_slot_inputs();
            let secondary_index = rng.gen_range(0..slot_inputs.len());
            SingleExtractionArgs::new(Some(secondary_index), slot_inputs)
        };
        let genesis_updates = source.init_contract_data(ctx, &contract).await;
        let indexing_genesis_block = ctx.block_number().await;
        let secondary_index_slot_input = source.secondary_index_slot_input().unwrap();
        let rest_column_slot_inputs = source.rest_column_slot_inputs();

        // Defining the columns structure of the table from the source slots
        // This is depending on what is our data source, mappings and CSV both have their
        // own way of defining their table.
        let columns = TableColumns {
            primary: TableColumn {
                name: BLOCK_COLUMN_NAME.to_string(),
                index: IndexType::Primary,
                multiplier: false,
                // Only valid for the identifier of block column, others are dummy.
                identifier: identifier_block_column(),
            },
            secondary: TableColumn {
                name: SINGLE_SECONDARY_COLUMN.to_string(),
                index: IndexType::Secondary,
                // here we put false always since these are not coming from a "merged" table
                multiplier: false,
                identifier: identifier_for_value_column(
                    &secondary_index_slot_input,
                    &contract_address,
                    chain_id,
                    vec![],
                ),
            },
            rest: rest_column_slot_inputs
                .iter()
                .enumerate()
                .map(|(i, slot_input)| {
                    let identifier = identifier_for_value_column(
                        slot_input,
                        &contract_address,
                        chain_id,
                        vec![],
                    );

                    TableColumn {
                        name: format!("rest_column_{i}"),
                        index: IndexType::None,
                        multiplier: false,
                        identifier,
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
        .await?;
        Ok((
            TableIndexing::<SingleExtractionArgs> {
                value_column: "".to_string(),
                source,
                table,
                contract,
                contract_extraction: Some(ContractExtractionArgs {
                    slot: StorageSlot::Simple(CONTRACT_SLOT),
                }),
            },
            genesis_updates,
        ))
    }

    /// The test case for mapping of single values
    pub(crate) async fn mapping_value_test_case(
        ctx: &mut TestContext,
    ) -> Result<(
        TableIndexing<MappingExtractionArgs<SimpleMapping>>,
        Vec<TableRowUpdate<BlockPrimaryIndex>>,
    )> {
        // Deploy the simple contract.
        let contract = Contract::deploy_simple_contract(ctx).await;
        let contract_address = contract.address;
        let chain_id = contract.chain_id;

        let slot_input = SlotInput::new(MAPPING_SLOT, 12, 20, 0);
        let key_id =
            identifier_for_mapping_key_column(MAPPING_SLOT, &contract_address, chain_id, vec![]);
        let value_id =
            identifier_for_value_column(&slot_input, &contract_address, chain_id, vec![]);
        // Switch the test index.
        // let mapping_index = MappingIndex::Value(value_id);
        let mapping_index = MappingIndex::OuterKey(key_id);
        let mut source = MappingExtractionArgs::<SimpleMapping>::new(
            MAPPING_SLOT,
            mapping_index,
            vec![slot_input],
            None,
        );

        let contract = Contract {
            address: contract_address,
            chain_id,
        };

        let table_row_updates = source.init_contract_data(ctx, &contract).await;

        let table = build_mapping_table(ctx, &mapping_index, key_id, vec![value_id]).await;
        let value_column = table.columns.rest[0].name.clone();

        Ok((
            TableIndexing::<MappingExtractionArgs<SimpleMapping>> {
                value_column,
                contract_extraction: Some(ContractExtractionArgs {
                    slot: StorageSlot::Simple(CONTRACT_SLOT),
                }),
                contract,
                source,
                table,
            },
            table_row_updates,
        ))
    }

    /// The test case for mapping of Struct values
    pub(crate) async fn mapping_struct_test_case(
        ctx: &mut TestContext,
    ) -> Result<(
        TableIndexing<MappingExtractionArgs<StructMapping>>,
        Vec<TableRowUpdate<BlockPrimaryIndex>>,
    )> {
        // Deploy the simple contract.
        let contract = Contract::deploy_simple_contract(ctx).await;
        let contract_address = contract.address;
        let chain_id = contract.chain_id;

        let slot_inputs = LargeStruct::slot_inputs(MAPPING_STRUCT_SLOT as u8);
        let key_id = identifier_for_mapping_key_column(
            MAPPING_STRUCT_SLOT as u8,
            &contract_address,
            chain_id,
            vec![],
        );
        let value_ids = slot_inputs
            .iter()
            .map(|slot_input| {
                identifier_for_value_column(slot_input, &contract_address, chain_id, vec![])
            })
            .collect_vec();
        // Switch the test index.
        // let mapping_index = MappingIndex::OuterKey(key_id);
        let mapping_index = MappingIndex::Value(value_ids[1]);
        let mut source = MappingExtractionArgs::<StructMapping>::new(
            MAPPING_STRUCT_SLOT as u8,
            mapping_index,
            slot_inputs.clone(),
            None,
        );

        let table_row_updates = source.init_contract_data(ctx, &contract).await;

        let table = build_mapping_table(ctx, &mapping_index, key_id, value_ids).await;
        let value_column = table.columns.rest[0].name.clone();

        Ok((
            TableIndexing::<MappingExtractionArgs<StructMapping>> {
                value_column,
                contract_extraction: Some(ContractExtractionArgs {
                    slot: StorageSlot::Simple(CONTRACT_SLOT),
                }),
                contract,
                source,
                table,
            },
            table_row_updates,
        ))
    }

    pub(crate) async fn mapping_of_single_value_mappings_test_case(
        ctx: &mut TestContext,
    ) -> Result<(
        TableIndexing<MappingExtractionArgs<SimpleNestedMapping>>,
        Vec<TableRowUpdate<BlockPrimaryIndex>>,
    )> {
        // Deploy the simple contract.
        let contract = Contract::deploy_simple_contract(ctx).await;
        let contract_address = contract.address;
        let chain_id = contract.chain_id;

        let slot_input = SlotInput::new(MAPPING_OF_SINGLE_VALUE_MAPPINGS_SLOT, 0, 32, 0);
        let outer_key_id = identifier_for_outer_mapping_key_column(
            MAPPING_OF_SINGLE_VALUE_MAPPINGS_SLOT,
            &contract_address,
            chain_id,
            vec![],
        );
        let inner_key_id = identifier_for_inner_mapping_key_column(
            MAPPING_OF_SINGLE_VALUE_MAPPINGS_SLOT,
            &contract_address,
            chain_id,
            vec![],
        );
        let value_id =
            identifier_for_value_column(&slot_input, &contract_address, chain_id, vec![]);
        // Enable to test different indexes.
        // let index = MappingIndex::Value(value_id);
        // let index = MappingIndex::OuterKey(outer_key_id);
        let index = MappingIndex::InnerKey(inner_key_id);
        let mut source = MappingExtractionArgs::<SimpleNestedMapping>::new(
            MAPPING_OF_SINGLE_VALUE_MAPPINGS_SLOT,
            index,
            vec![slot_input],
            None,
        );

        let table_row_updates = source.init_contract_data(ctx, &contract).await;

        let table = build_mapping_of_mappings_table(
            ctx,
            &index,
            outer_key_id,
            inner_key_id,
            vec![value_id],
        )
        .await;
        let value_column = table.columns.rest[0].name.clone();

        Ok((
            TableIndexing::<MappingExtractionArgs<SimpleNestedMapping>> {
                value_column,
                contract_extraction: Some(ContractExtractionArgs {
                    slot: StorageSlot::Simple(CONTRACT_SLOT),
                }),
                contract,
                source,
                table,
            },
            table_row_updates,
        ))
    }

    pub(crate) async fn mapping_of_struct_mappings_test_case(
        ctx: &mut TestContext,
    ) -> Result<(
        TableIndexing<MappingExtractionArgs<StructNestedMapping>>,
        Vec<TableRowUpdate<BlockPrimaryIndex>>,
    )> {
        // Deploy the simple contract.
        let contract = Contract::deploy_simple_contract(ctx).await;
        let contract_address = contract.address;
        let chain_id = contract.chain_id;

        let slot_inputs = LargeStruct::slot_inputs(MAPPING_OF_STRUCT_MAPPINGS_SLOT);
        let outer_key_id = identifier_for_outer_mapping_key_column(
            MAPPING_OF_STRUCT_MAPPINGS_SLOT,
            &contract_address,
            chain_id,
            vec![],
        );
        let inner_key_id = identifier_for_inner_mapping_key_column(
            MAPPING_OF_STRUCT_MAPPINGS_SLOT,
            &contract_address,
            chain_id,
            vec![],
        );
        let value_ids = slot_inputs
            .iter()
            .map(|slot_input| {
                identifier_for_value_column(slot_input, &contract_address, chain_id, vec![])
            })
            .collect_vec();
        // Enable to test different indexes.
        // let index = MappingIndex::OuterKey(outer_key_id);
        // let index = MappingIndex::InnerKey(inner_key_id);
        let index = MappingIndex::Value(value_ids[1]);
        let mut source = MappingExtractionArgs::<StructNestedMapping>::new(
            MAPPING_OF_STRUCT_MAPPINGS_SLOT,
            index,
            slot_inputs.clone(),
            None,
        );

        let table_row_updates = source.init_contract_data(ctx, &contract).await;

        let table =
            build_mapping_of_mappings_table(ctx, &index, outer_key_id, inner_key_id, value_ids)
                .await;
        let value_column = table.columns.rest[0].name.clone();

        Ok((
            TableIndexing::<MappingExtractionArgs<StructNestedMapping>> {
                value_column,
                contract_extraction: Some(ContractExtractionArgs {
                    slot: StorageSlot::Simple(CONTRACT_SLOT),
                }),
                contract,
                source,
                table,
            },
            table_row_updates,
        ))
    }

    pub(crate) async fn receipt_test_case(
        no_topics: usize,
        no_data: usize,
        ctx: &mut TestContext,
    ) -> Result<(TableIndexing<T>, Vec<TableRowUpdate<BlockPrimaryIndex>>)>
    where
        T: ReceiptExtractionArgs,
        [(); <T as ReceiptExtractionArgs>::NO_TOPICS]:,
        [(); <T as ReceiptExtractionArgs>::MAX_DATA_WORDS]:,
    {
        // Create a provider with the wallet for contract deployment and interaction.
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());

        let contract = EventEmitter::deploy(&provider).await.unwrap();
        info!(
            "Deployed EventEmitter contract at address: {}",
            contract.address()
        );
        let contract_address = contract.address();
        let chain_id = ctx.rpc.get_chain_id().await.unwrap();
        let contract = Contract {
            address: *contract_address,
            chain_id,
        };

        // Retrieve the event signature `str` based on `no_topics` and `no_data`
        let event_signature = match (no_topics, no_data) {
            (0, 0) => EventEmitter::noIndexed::SIGNATURE,
            (0, 1) => EventEmitter::noIOneD::SIGNATURE,
            (0, 2) => EventEmitter::noITwoD::SIGNATURE,
            (1, 0) => EventEmitter::oneIndexed::SIGNATURE,
            (1, 1) => EventEmitter::oneIOneD::SIGNATURE,
            (1, 2) => EventEmitter::oneITwoD::SIGNATURE,
            (2, 0) => EventEmitter::twoIndexed::SIGNATURE,
            (2, 1) => EventEmitter::twoIOneD::SIGNATURE,
            (2, 2) => EventEmitter::twoITwoD::SIGNATURE,
            (3, 0) => EventEmitter::threeIndexed::SIGNATURE,
            (3, 1) => EventEmitter::oneData::SIGNATURE,
            (3, 2) => EventEmitter::twoData::SIGNATURE,
            _ => panic!(
                "Events with {} topics and {} additional pieces of data not supported",
                no_topics, no_data
            ),
        };
        let chain_id = provider.get_chain_id().await?;
        let mut source = T::new(contract.address(), chain_id, event_signature);
        let genesis_updates = source.init_contract_data(ctx, &contract).await;

        let indexing_genesis_block = ctx.block_number().await;
        // Defining the columns structure of the table from the source event
        // This is depending on what is our data source, mappings and CSV both have their o
        // own way of defining their table.
        let columns = TableColumns {
            primary: TableColumn {
                name: BLOCK_COLUMN_NAME.to_string(),
                identifier: identifier_block_column(),
                index: IndexType::Primary,
                multiplier: false,
            },
            secondary: TableColumn {
                name: TX_INDEX_COLUMN.to_string(),
                identifier: <T as ReceiptExtractionArgs>::get_index(&source),

                index: IndexType::Secondary,
                // here we put false always since these are not coming from a "merged" table
                multiplier: false,
            },
            rest: compute_non_indexed_receipt_column_ids(&source.get_event())
                .into_iter()
                .map(|(name, identifier)| TableColumn {
                    name,
                    identifier,
                    index: IndexType::None,
                    multiplier: false,
                })
                .collect::<Vec<TableColumn>>(),
        };

        let tx_index_id = columns.secondary_column().identifier();
        let gas_used_id = columns.rest[0].identifier();
        let row_unique_id = TableRowUniqueID::Receipt(tx_index_id, gas_used_id);
        let table = Table::new(
            indexing_genesis_block,
            "receipt_table".to_string(),
            columns,
            row_unique_id,
        )
        .await?;
        Ok((
            TableIndexing::<T> {
                value_column: table.columns.rest[0].name.clone(),
                source,
                table,
                contract,
                contract_extraction: None,
            },
            genesis_updates,
        ))
    }

    pub async fn run(
        &mut self,
        ctx: &mut TestContext,
        genesis_change: Vec<TableRowUpdate<BlockPrimaryIndex>>,
        changes: Vec<ChangeType>,
    ) -> anyhow::Result<()> {
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

            if table_row_updates.is_empty() {
                continue;
            }

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
    ) -> anyhow::Result<()> {
        let current_block = ctx.block_number().await as BlockPrimaryIndex;
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
                            payload: self
                                .table
                                .row
                                .try_fetch(&new_cells.previous_row_key)
                                .await?
                                .unwrap(),
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
                            current_block,
                            previous_row,
                            new_cell_collection,
                            tree_update,
                        )
                        .await?;
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
                        .await?
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
                            current_block,
                            Row {
                                k: new_cells.previous_row_key.clone(),
                                payload: old_row,
                            },
                            new_cell_collection,
                            tree_update,
                        )
                        .await?;
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
                TableRowUpdate::DeleteAll => TreeRowUpdate::Wipe,
            };
            rows_update.push(tree_update);
        }
        info!("Generated final CELLs tree proofs for block {current_block}");
        let updates = self.table.apply_row_update(bn, rows_update).await?;
        info!("Applied updates to row tree");
        let index_node = if let Some(updates) = updates {
            Some(
                ctx.prove_update_row_tree(bn, &self.table, updates)
                    .await
                    .expect("unable to prove row tree"),
            )
        } else {
            None
        };

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
        let root_proof_key = ctx
            .prove_update_index_tree(bn, &self.table, updates)
            .await?;
        info!("Generated final BLOCK tree proofs for block {current_block}");
        ctx.prove_ivc(
            bn,
            root_proof_key,
            &self.table.index,
            expected_metadata_hash,
        )
        .await?;
        info!("Generated final IVC proof for block {}", current_block);

        Ok(())
    }

    // separate function only dealing with preprocessing MPT proofs
    async fn run_mpt_preprocessing(
        &self,
        ctx: &mut TestContext,
        bn: BlockPrimaryIndex,
    ) -> anyhow::Result<HashOutput> {
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
                if let Some(contract_extraction) = &self.contract_extraction {
                    let contract_proof = ctx
                        .prove_contract_extraction(
                            &self.contract.address,
                            contract_extraction.slot.clone(),
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
                        let pis = contract_extraction::PublicInputs::from_slice(
                            &pvk.proof().public_inputs,
                        );
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
                } else {
                    vec![]
                }
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

        let table_id = &self.table.public_name;
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

/// Function that computes the column identifiers for the non-indexed columns together with their names as [`String`]s.
pub fn compute_non_indexed_receipt_column_ids<
    const NO_TOPICS: usize,
    const MAX_DATA_WORDS: usize,
>(
    event: &EventLogInfo<NO_TOPICS, MAX_DATA_WORDS>,
) -> Vec<(String, ColumnID)> {
    let gas_used_column_id =
        identifier_for_gas_used_column(&event.event_signature, &event.address, event.chain_id, &[]);

    let topic_ids = event
        .topics
        .iter()
        .enumerate()
        .map(|(j, _)| {
            (
                format!("{}_{}", TOPIC_NAME, j + 1),
                identifier_for_topic_column(
                    &event.event_signature,
                    &event.address,
                    event.chain_id,
                    j as u8 + 1,
                    &[],
                ),
            )
        })
        .collect::<Vec<(String, ColumnID)>>();

    let data_ids = event
        .data
        .iter()
        .enumerate()
        .map(|(j, _)| {
            (
                format!("{}_{}", DATA_NAME, j + 1),
                identifier_for_data_column(
                    &event.event_signature,
                    &event.address,
                    event.chain_id,
                    j as u8 + 1,
                    &[],
                ),
            )
        })
        .collect::<Vec<(String, ColumnID)>>();

    [
        vec![(GAS_USED_NAME.to_string(), gas_used_column_id)],
        topic_ids,
        data_ids,
    ]
    .concat()
}

/// Build the mapping table.
async fn build_mapping_table(
    ctx: &TestContext,
    mapping_index: &MappingIndex,
    key_id: u64,
    mut value_ids: Vec<u64>,
) -> Table {
    // Construct the table columns.
    let (secondary_column, rest_columns) = match mapping_index {
        MappingIndex::OuterKey(_) => {
            let secondary_column = TableColumn {
                name: MAPPING_KEY_COLUMN.to_string(),
                index: IndexType::Secondary,
                multiplier: false,
                identifier: key_id,
            };
            let rest_columns = value_ids
                .into_iter()
                .enumerate()
                .map(|(i, id)| TableColumn {
                    name: format!("{MAPPING_VALUE_COLUMN}_{i}"),
                    index: IndexType::None,
                    multiplier: false,
                    identifier: id,
                })
                .collect_vec();

            (secondary_column, rest_columns)
        }
        MappingIndex::Value(secondary_value_id) => {
            let pos = value_ids
                .iter()
                .position(|id| id == secondary_value_id)
                .unwrap();
            let secondary_id = value_ids.remove(pos);

            let secondary_column = TableColumn {
                name: MAPPING_VALUE_COLUMN.to_string(),
                index: IndexType::Secondary,
                multiplier: false,
                identifier: secondary_id,
            };
            let mut rest_columns = value_ids
                .into_iter()
                .enumerate()
                .map(|(i, id)| TableColumn {
                    name: format!("{MAPPING_VALUE_COLUMN}_{i}"),
                    index: IndexType::None,
                    multiplier: false,
                    identifier: id,
                })
                .collect_vec();
            rest_columns.push(TableColumn {
                name: MAPPING_KEY_COLUMN.to_string(),
                index: IndexType::None,
                multiplier: false,
                // The slot input is useless for the key column.
                identifier: key_id,
            });

            (secondary_column, rest_columns)
        }
        _ => unreachable!(),
    };
    // Defining the columns structure of the table from the source slots
    // This is depending on what is our data source, mappings and CSV both have their o
    // own way of defining their table.
    let columns = TableColumns {
        primary: TableColumn {
            name: BLOCK_COLUMN_NAME.to_string(),
            index: IndexType::Primary,
            multiplier: false,
            // Only valid for the identifier of block column, others are dummy.
            identifier: identifier_block_column(),
        },
        secondary: secondary_column,
        rest: rest_columns,
    };
    debug!("MAPPING ZK COLUMNS -> {:?}", columns);
    let index_genesis_block = ctx.block_number().await;
    let row_unique_id = TableRowUniqueID::Mapping(key_id);
    Table::new(
        index_genesis_block,
        "mapping_table".to_string(),
        columns,
        row_unique_id,
    )
    .await
    .unwrap()
}

/// Build the mapping of mappings table.
async fn build_mapping_of_mappings_table(
    ctx: &TestContext,
    index: &MappingIndex,
    outer_key_id: u64,
    inner_key_id: u64,
    value_ids: Vec<u64>,
) -> Table {
    let mut rest_columns = value_ids
        .into_iter()
        .enumerate()
        .map(|(i, id)| TableColumn {
            name: format!("{MAPPING_OF_MAPPINGS_VALUE_COLUMN}_{i}"),
            index: IndexType::None,
            multiplier: false,
            identifier: id,
        })
        .collect_vec();

    let secondary_column = match index {
        MappingIndex::OuterKey(_) => {
            rest_columns.push(TableColumn {
                name: MAPPING_OF_MAPPINGS_INNER_KEY_COLUMN.to_string(),
                index: IndexType::None,
                multiplier: false,
                identifier: inner_key_id,
            });

            TableColumn {
                name: MAPPING_OF_MAPPINGS_OUTER_KEY_COLUMN.to_string(),
                index: IndexType::Secondary,
                multiplier: false,
                identifier: outer_key_id,
            }
        }
        MappingIndex::InnerKey(_) => {
            rest_columns.push(TableColumn {
                name: MAPPING_OF_MAPPINGS_OUTER_KEY_COLUMN.to_string(),
                index: IndexType::None,
                multiplier: false,
                identifier: outer_key_id,
            });

            TableColumn {
                name: MAPPING_OF_MAPPINGS_INNER_KEY_COLUMN.to_string(),
                index: IndexType::Secondary,
                multiplier: false,
                identifier: inner_key_id,
            }
        }
        MappingIndex::Value(secondary_value_id) => {
            let pos = rest_columns
                .iter()
                .position(|col| &col.identifier() == secondary_value_id)
                .unwrap();
            let mut secondary_column = rest_columns.remove(pos);
            secondary_column.index = IndexType::Secondary;
            let key_columns = [
                (outer_key_id, MAPPING_OF_MAPPINGS_OUTER_KEY_COLUMN),
                (inner_key_id, MAPPING_OF_MAPPINGS_INNER_KEY_COLUMN),
            ]
            .map(|(id, name)| TableColumn {
                name: name.to_string(),
                index: IndexType::None,
                multiplier: false,
                identifier: id,
            });
            rest_columns.extend(key_columns);

            secondary_column
        }
        _ => unreachable!(),
    };

    let columns = TableColumns {
        primary: TableColumn {
            name: BLOCK_COLUMN_NAME.to_string(),
            index: IndexType::Primary,
            multiplier: false,
            identifier: identifier_block_column(),
        },
        secondary: secondary_column,
        rest: rest_columns,
    };
    debug!("MAPPING OF MAPPINGS ZK COLUMNS -> {:?}", columns);
    let index_genesis_block = ctx.block_number().await;
    let row_unique_id = TableRowUniqueID::MappingOfMappings(outer_key_id, inner_key_id);
    Table::new(
        index_genesis_block,
        "mapping_of_mappings_table".to_string(),
        columns,
        row_unique_id,
    )
    .await
    .unwrap()
}

#[derive(Debug, Clone, Copy)]
pub struct ReceiptUpdate {
    pub event_type: (u8, u8),
    /// The number of events to emit related to the event defined by `event_type`
    pub no_relevant: usize,
    /// The number of other random events to emit.
    pub no_others: usize,
}

impl ReceiptUpdate {
    /// Create a new [`ReceiptUpdate`]
    pub fn new(event_type: (u8, u8), no_relevant: usize, no_others: usize) -> ReceiptUpdate {
        ReceiptUpdate {
            event_type,
            no_relevant,
            no_others,
        }
    }

    /// Apply an update to an [`EventEmitterInstance`].
    pub async fn apply_update<T: Transport + Clone, P: Provider<T, Ethereum>>(
        &self,
        ctx: &TestContext,
        contract: &EventEmitterInstance<T, P, Ethereum>,
    ) {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());

        let addresses = ctx.local_node.as_ref().unwrap().addresses();

        provider.anvil_set_auto_mine(false).await.unwrap();

        provider.anvil_auto_impersonate_account(true).await.unwrap();
        // Send a bunch of transactions, some of which are related to the event we are testing for.
        let mut pending_tx_builders = vec![];

        for j in 0..(self.no_relevant + self.no_others) {
            let (tx_req, address_index) = {
                let tx_req = if j < self.no_relevant {
                    self.select_event(contract)
                } else {
                    self.select_non_indexed_event(contract)
                };
                let address_index = rand::random::<usize>() % addresses.len();
                (tx_req, address_index)
            };
            let sender_address = addresses[address_index];

            let funding = U256::from(1e18 as u64);

            provider
                .anvil_set_balance(sender_address, funding)
                .await
                .unwrap();

            let new_req = tx_req.with_from(sender_address);
            let tx_req_final = provider
                .fill(new_req)
                .await
                .unwrap()
                .as_envelope()
                .cloned()
                .unwrap();
            pending_tx_builders.push(provider.send_tx_envelope(tx_req_final).await.unwrap());
        }

        provider
            .anvil_auto_impersonate_account(false)
            .await
            .unwrap();
        provider.anvil_set_auto_mine(true).await.unwrap();

        for pending_tx in pending_tx_builders {
            pending_tx.watch().await.unwrap();
        }
    }

    fn select_event<T: Transport + Clone, P: Provider<T, N>, N: Network>(
        &self,
        contract: &EventEmitterInstance<T, P, N>,
    ) -> N::TransactionRequest {
        match self.event_type {
            (0, 0) => contract.testNoIndexed().into_transaction_request(),
            (1, 0) => contract.testOneIndexed().into_transaction_request(),
            (2, 0) => contract.testTwoIndexed().into_transaction_request(),
            (3, 0) => contract.testThreeIndexed().into_transaction_request(),
            (0, 1) => contract.testNoIOneD().into_transaction_request(),
            (0, 2) => contract.testNoITwoD().into_transaction_request(),
            (1, 1) => contract.testOneIOneD().into_transaction_request(),
            (1, 2) => contract.testOneITwoD().into_transaction_request(),
            (2, 1) => contract.testTwoIOneD().into_transaction_request(),
            (2, 2) => contract.testTwoITwoD().into_transaction_request(),
            (3, 1) => contract.testOneData().into_transaction_request(),
            (3, 2) => contract.testTwoData().into_transaction_request(),
            _ => contract.testNoIndexed().into_transaction_request(),
        }
    }

    fn select_non_indexed_event<T: Transport + Clone, P: Provider<T, N>, N: Network>(
        &self,
        contract: &EventEmitterInstance<T, P, N>,
    ) -> N::TransactionRequest {
        // Randomly pick a pair that is not equal to `self.event_type`
        let mut first_random = rand::random::<u8>() % 4;
        let mut second_random = rand::random::<u8>() % 3;
        while (first_random, second_random) == self.event_type {
            first_random = rand::random::<u8>() % 4;
            second_random = rand::random::<u8>() % 3;
        }
        match (first_random, second_random) {
            (0, 0) => contract.testNoIndexed().into_transaction_request(),
            (1, 0) => contract.testOneIndexed().into_transaction_request(),
            (2, 0) => contract.testTwoIndexed().into_transaction_request(),
            (3, 0) => contract.testThreeIndexed().into_transaction_request(),
            (0, 1) => contract.testNoIOneD().into_transaction_request(),
            (0, 2) => contract.testNoITwoD().into_transaction_request(),
            (1, 1) => contract.testOneIOneD().into_transaction_request(),
            (1, 2) => contract.testOneITwoD().into_transaction_request(),
            (2, 1) => contract.testTwoIOneD().into_transaction_request(),
            (2, 2) => contract.testTwoITwoD().into_transaction_request(),
            (3, 1) => contract.testOneData().into_transaction_request(),
            (3, 2) => contract.testTwoData().into_transaction_request(),
            _ => contract.testNoIndexed().into_transaction_request(),
        }
    }
}

#[derive(Clone, Debug, Copy)]
pub enum ChangeType {
    Deletion,
    Insertion,
    Update(UpdateType),
    Silent,
    Receipt(usize, usize),
}

#[derive(Clone, Debug, Copy)]
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
                    Some(*new)
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
    /// Used to wipe the current row tree before any other operation occurs,
    /// useful with Receipts
    DeleteAll,
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
                TableRowUpdate::Deletion(_) | TableRowUpdate::DeleteAll => vec![],
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

impl<T: TableSource + Clone> TableIndexing<T> {
    pub fn table_info(&self) -> TableInfo<T> {
        TableInfo {
            public_name: self.table.public_name.clone(),
            value_column: self.value_column.clone(),
            chain_id: self.contract.chain_id(),
            columns: self.table.columns.clone(),
            contract_address: self.contract.address,
            source: self.source.clone(),
            row_unique_id: self.table.row_unique_id.clone(),
        }
    }
}
