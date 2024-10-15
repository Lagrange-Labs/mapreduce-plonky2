//! Test case for local Simple contract
//! Reference `test-contracts/src/Simple.sol` for the details of Simple contract.

use anyhow::Result;
use futures::SinkExt;
use itertools::Itertools;
use log::{debug, info};
use mp2_v1::{
    api::{metadata_hash, SlotInputs},
    indexing::{
        block::BlockPrimaryIndex,
        cell::Cell,
        row::{CellCollection, CellInfo, Row, RowTreeKey},
        ColumnID,
    },
    values_extraction::{gadgets::column_info::ColumnInfo, identifier_block_column},
};
use rand::{Rng, SeedableRng};
use ryhope::storage::RoEpochKvStorage;
use std::slice;

use crate::common::{
    bindings::simple::Simple::{self, MappingChange, MappingOperation},
    cases::{
        identifier_for_mapping_key_column, identifier_for_mapping_value_column,
        identifier_single_var_column, MappingIndex,
    },
    proof_storage::{ProofKey, ProofStorage},
    rowtree::SecondaryIndexCell,
    table::{
        CellsUpdate, IndexType, IndexUpdate, Table, TableColumn, TableColumns, TreeRowUpdate,
        TreeUpdateType,
    },
    MetadataGadget, StorageSlotInfo, TestContext,
};

use super::{
    super::bindings::simple::Simple::SimpleInstance, ContractExtractionArgs, LengthExtractionArgs,
    MappingValuesExtractionArgs, SingleValuesExtractionArgs, TableSourceSlot, TestCase,
    UniqueMappingEntry,
};
use alloy::{
    contract::private::{Network, Provider, Transport},
    eips::BlockNumberOrTag,
    primitives::{Address, U256},
    providers::ProviderBuilder,
};
use mp2_common::{
    eth::{ProofQuery, StorageSlot},
    proof::ProofWithVK,
    types::{HashOutput, ADDRESS_LEN},
    F,
};
use plonky2::field::types::Field;
use std::{assert_matches::assert_matches, str::FromStr, sync::atomic::AtomicU64};

/// Test slots for single values extraction
const SINGLE_SLOTS: [u8; 4] = [0, 1, 2, 3];
/// Define which slots is the secondary index. In this case, it's the U256
const INDEX_SLOT: u8 = 1;

/// Test slot for mapping values extraction
const MAPPING_SLOT: u8 = 4;

/// Test slot for length extraction
const LENGTH_SLOT: u8 = 1;

/// Test length value for length extraction
const LENGTH_VALUE: u8 = 2;

/// Test slot for contract extraction
const CONTRACT_SLOT: usize = 1;

/// Test slot for single Struct extractin
const SINGLE_STRUCT_SLOT: usize = 6;

/// Test slot for mapping Struct extraction
const MAPPING_STRUCT_SLOT: usize = 7;

/// Test slot for mapping of mappings extraction
const MAPPING_OF_MAPPINGS_SLOT: usize = 8;

/// human friendly name about the column containing the block number
pub(crate) const BLOCK_COLUMN_NAME: &str = "block_number";
pub(crate) const MAPPING_VALUE_COLUMN: &str = "map_value";
pub(crate) const MAPPING_KEY_COLUMN: &str = "map_key";

pub enum TreeFactory {
    New,
    Load,
}

impl TestCase {
    pub fn table(&self) -> &Table {
        &self.table
    }
    pub(crate) async fn single_value_test_case(
        ctx: &TestContext,
        factory: TreeFactory,
    ) -> Result<Self> {
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
        let source = TableSourceSlot::SingleValues(SingleValuesExtractionArgs {
            slots: single_var_slot_info(contract_address, chain_id),
        });

        // + 1 because we are going to deploy some update to contract in a transaction, which for
        // Anvil means it's a new block
        let indexing_genesis_block = ctx.block_number().await + 1;
        // Defining the columns structure of the table from the source slots
        // This is depending on what is our data source, mappings and CSV both have their o
        // own way of defining their table.
        let columns = TableColumns {
            primary: TableColumn {
                name: BLOCK_COLUMN_NAME.to_string(),
                identifier: identifier_block_column(),
                index: IndexType::Primary,
            },
            secondary: TableColumn {
                name: "column_value".to_string(),
                identifier: identifier_single_var_column(
                    INDEX_SLOT,
                    0,
                    contract_address,
                    chain_id,
                    vec![],
                ),
                index: IndexType::Secondary,
            },
            rest: SINGLE_SLOTS
                .iter()
                .enumerate()
                .filter_map(|(i, slot)| match i {
                    _ if *slot == INDEX_SLOT => None,
                    _ => {
                        let identifier = identifier_single_var_column(
                            *slot,
                            0,
                            contract_address,
                            chain_id,
                            vec![],
                        );

                        Some(TableColumn {
                            name: format!("column_{}", i),
                            identifier,
                            index: IndexType::None,
                        })
                    }
                })
                .collect::<Vec<_>>(),
        };
        let table = match factory {
            TreeFactory::New => {
                Table::new(indexing_genesis_block, "single_table".to_string(), columns).await
            }
            TreeFactory::Load => Table::load("single_table".to_string(), columns).await?,
        };
        Ok(Self {
            source,
            table,
            contract_address: *contract_address,
            contract_extraction: ContractExtractionArgs {
                slot: StorageSlot::Simple(CONTRACT_SLOT),
            },
            chain_id: ctx.rpc.get_chain_id().await.unwrap(),
        })
    }

    pub(crate) async fn mapping_test_case(ctx: &TestContext, factory: TreeFactory) -> Result<Self> {
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
        // index genesis block is the first block where I start processing the data. it is one
        // block more than the deploy block
        // + 1 because we are going to deploy some update to contract in a transaction, which for
        // Anvil means it's a new block
        let index_genesis_block = ctx.block_number().await + 1;
        // to toggle off and on
        let value_as_index = true;
        let value_id = identifier_for_mapping_value_column(
            MAPPING_SLOT,
            0,
            contract_address,
            chain_id,
            vec![],
        );
        let key_id =
            identifier_for_mapping_key_column(MAPPING_SLOT, 0, contract_address, chain_id, vec![]);
        let (index_identifier, mapping_index, cell_identifier) = match value_as_index {
            true => (value_id, MappingIndex::Value(value_id), key_id),
            false => (key_id, MappingIndex::Key(key_id), value_id),
        };

        // mapping(uint256 => address) public m1
        let mapping_args = MappingValuesExtractionArgs {
            slot: MAPPING_SLOT,
            evm_word: 0,
            length: ADDRESS_LEN,
            index: mapping_index,
            // at the beginning there is no mapping key inserted
            // NOTE: This array is a convenience to handle smart contract updates
            // manually, but does not need to be stored explicitely by dist system.
            mapping_keys: vec![],
        };

        let source = TableSourceSlot::Mapping((
            mapping_args,
            Some(LengthExtractionArgs {
                slot: LENGTH_SLOT,
                value: LENGTH_VALUE,
            }),
        ));

        // Defining the columns structure of the table from the source slots
        // This is depending on what is our data source, mappings and CSV both have their o
        // own way of defining their table.
        let columns = TableColumns {
            primary: TableColumn {
                name: BLOCK_COLUMN_NAME.to_string(),
                identifier: identifier_block_column(),
                index: IndexType::Primary,
            },
            secondary: TableColumn {
                name: if value_as_index {
                    MAPPING_VALUE_COLUMN
                } else {
                    MAPPING_KEY_COLUMN
                }
                .to_string(),
                identifier: index_identifier,
                index: IndexType::Secondary,
            },
            rest: vec![TableColumn {
                name: if value_as_index {
                    MAPPING_KEY_COLUMN
                } else {
                    MAPPING_VALUE_COLUMN
                }
                .to_string(),
                identifier: cell_identifier,
                index: IndexType::None,
            }],
        };
        debug!("MAPPING ZK COLUMNS -> {:?}", columns);
        let table = match factory {
            TreeFactory::New => {
                Table::new(index_genesis_block, "mapping_table".to_string(), columns).await
            }
            TreeFactory::Load => Table::load("mapping_table".to_string(), columns).await?,
        };

        Ok(Self {
            contract_extraction: ContractExtractionArgs {
                slot: StorageSlot::Simple(CONTRACT_SLOT),
            },
            contract_address: *contract_address,
            source,
            table,
            chain_id: ctx.rpc.get_chain_id().await.unwrap(),
        })
    }

    pub async fn run(&mut self, ctx: &mut TestContext, changes: Vec<ChangeType>) -> Result<()> {
        // Call the contract function to set the test data.
        // TODO: make it return an update for a full table, right now it's only for one row.
        // to make when we deal with mappings
        let table_row_updates = self.init_contract_data(ctx).await;
        log::info!("Applying initial updates to contract done");
        let bn = ctx.block_number().await as BlockPrimaryIndex;

        // we first run the initial preprocessing and db creation.
        let metadata_hash = self.run_mpt_preprocessing(ctx, bn).await?;
        // then we run the creation of our tree
        self.run_lagrange_preprocessing(ctx, bn, table_row_updates, &metadata_hash)
            .await?;

        log::info!("FIRST block {bn} finished proving. Moving on to update",);

        for ut in changes {
            let table_row_updates = self.random_contract_update(ctx, ut).await;
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
                        self.table.columns.secondary_column().identifier,
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
                        self.table.columns.secondary_column().identifier,
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
        let contract_proof_key = ProofKey::ContractExtraction((self.contract_address, bn));
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
                        &self.contract_address,
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
                let proof = ctx.prove_block_extraction().await.unwrap();
                ctx.storage.store_proof(block_proof_key, proof.clone())?;
                info!(
                    "Generated Block Extraction (C.4) proof for block number {}",
                    bn
                );
                proof
            }
        };

        let table_id = &self.table.public_name.clone();
        let chain_id = ctx.rpc.get_chain_id().await?;
        // we construct the proof key for both mappings and single variable in the same way since
        // it is derived from the table id which should be different for any tables we create.
        let proof_key = ProofKey::ValueExtraction((table_id.clone(), bn as BlockPrimaryIndex));
        let (value_proof, compound, length, metadata_hash) = match self.source {
            // first lets do without length
            TableSourceSlot::Mapping((ref mapping, _)) => {
                let mapping_root_proof = match ctx.storage.get_proof_exact(&proof_key) {
                    Ok(p) => p,
                    Err(_) => {
                        let mapping_values_proof = ctx
                            .prove_mapping_values_extraction(
                                &self.contract_address,
                                chain_id,
                                mapping.slot,
                                mapping.evm_word,
                                mapping.length,
                                mapping.mapping_keys.clone(),
                            )
                            .await;

                        ctx.storage
                            .store_proof(proof_key, mapping_values_proof.clone())?;
                        info!("Generated Values Extraction (C.1) proof for mapping slots");
                        {
                            let pproof = ProofWithVK::deserialize(&mapping_values_proof).unwrap();
                            let pi = mp2_v1::values_extraction::PublicInputs::new(
                                &pproof.proof().public_inputs,
                            );
                            debug!("[--] FINAL MPT DIGEST VALUE --> {:?} ", pi.values_digest());
                        }
                        mapping_values_proof
                    }
                };
                let slot_input = SlotInputs::Mapping(mapping.slot);
                let metadata_hash =
                    metadata_hash(slot_input, &self.contract_address, chain_id, vec![]);
                // it's a compoound value type of proof since we're not using the length
                (mapping_root_proof, true, None, metadata_hash)
            }
            TableSourceSlot::SingleValues(ref args) => {
                let single_value_proof = match ctx.storage.get_proof_exact(&proof_key) {
                    Ok(p) => p,
                    Err(_) => {
                        let single_values_proof = ctx
                            .prove_single_values_extraction(&self.contract_address, &args.slots)
                            .await;
                        ctx.storage
                            .store_proof(proof_key, single_values_proof.clone())?;
                        info!("Generated Values Extraction (C.1) proof for single variables");
                        {
                            let pproof = ProofWithVK::deserialize(&single_values_proof).unwrap();
                            let pi = mp2_v1::values_extraction::PublicInputs::new(
                                &pproof.proof().public_inputs,
                            );
                            debug!("[--] FINAL MPT DIGEST VALUE --> {:?} ", pi.values_digest());
                        }
                        single_values_proof
                    }
                };
                let slots = args
                    .slots
                    .iter()
                    .map(|slot_info| slot_info.slot().slot())
                    .collect();
                let slot_input = SlotInputs::Simple(slots);
                let metadata_hash =
                    metadata_hash(slot_input, &self.contract_address, chain_id, vec![]);
                // we're just proving a single set of a value
                (single_value_proof, false, None, metadata_hash)
            }
        };
        // final extraction for single variables combining the different proofs generated before
        let final_key = ProofKey::FinalExtraction((table_id.clone(), bn as BlockPrimaryIndex));
        // no need to generate it if it's already present
        if ctx.storage.get_proof_exact(&final_key).is_err() {
            let proof = ctx
                .prove_final_extraction(contract_proof, value_proof, block_proof, compound, length)
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

    // Returns the table updated
    async fn apply_update_to_contract(
        &self,
        ctx: &TestContext,
        update: &UpdateSimpleStorage,
    ) -> Result<()> {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());

        let contract = Simple::new(self.contract_address, &provider);
        update.apply_to(&contract).await;
        info!("Updated contract with new values {:?}", update);
        Ok(())
    }

    async fn current_single_values(&self, ctx: &TestContext) -> Result<SimpleSingleValue> {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());

        let contract = Simple::new(self.contract_address, &provider);

        Ok(SimpleSingleValue {
            s1: contract.s1().call().await.unwrap()._0,
            s2: contract.s2().call().await.unwrap()._0,
            s3: contract.s3().call().await.unwrap()._0,
            s4: contract.s4().call().await.unwrap()._0,
        })
    }

    async fn random_contract_update(
        &mut self,
        ctx: &mut TestContext,
        c: ChangeType,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        match self.source {
            // NOTE 1: The first part is just trying to construct the right input to simulate any
            // changes on a mapping. This is mostly irrelevant for dist system but needs to
            // manually construct our test cases here. The second part is more interesting as it looks at "what to do
            // when receiving an update from scrapper". The core of the function is in
            // `from_mapping_to_table_update`
            //
            // NOTE 2: Thhis implementation tries to emulate as much as possible what happens in dist
            // system. TO compute the set of updates, it first simulate an update on the contract
            // and creates the signal "MappingUpdate" corresponding to the update. From that point
            // onwards, the table row updates are manually created.
            // Note this can actually lead to more work than necessary in some cases.
            // Take an example where the mapping is storing (10->A), (11->A), and where the
            // secondary index value is the value, i.e. A.
            // Our table initially looks like `A | 10`, `A | 11`.
            // Imagine an update where we want to change the first row to `A | 12`. In the "table"
            // world, this is only a simple update of a simple cell, no index even involved. But
            // from the perspective of mapping, the "scrapper" can only tells us :
            // * Key 10 has been deleted
            // * Key 12 has been added with value A
            // In the backend, we translate that in the "table world" to a deletion and an insertion.
            // Having such optimization could be done later on, need to properly evaluate the cost
            // of it.
            TableSourceSlot::Mapping((ref mut mapping, _)) => {
                //let idx = thread_rng().gen_range(0..mapping.mapping_keys.len());
                //let idx = mapping.mapping_keys.len() - 1;
                // easier to debug
                let idx = 0;
                let mkey = &mapping.mapping_keys[idx].clone();
                let slot = mapping.slot as usize;
                let index_type = mapping.index.clone();
                let address = &self.contract_address.clone();
                let query = ProofQuery::new_mapping_slot(*address, slot, mkey.to_owned());
                let response = ctx
                    .query_mpt_proof(&query, BlockNumberOrTag::Number(ctx.block_number().await))
                    .await;
                let current_value = response.storage_proof[0].value;
                let current_key = U256::from_be_slice(mkey);
                let new_key = next_mapping_key();
                let new_value: U256 = next_address().into_word().into();
                let mapping_updates = match c {
                    ChangeType::Silent => vec![],
                    ChangeType::Insertion => {
                        vec![MappingUpdate::Insertion(new_key, new_value)]
                    }
                    ChangeType::Deletion => {
                        // NOTE: We care about the value here since that allows _us_ to pinpoint the
                        // correct row in the table and delete it since for a mpping, we uniquely
                        // identify row per (mapping_key,mapping_value) (in the order dictated by
                        // the secondary index)
                        vec![MappingUpdate::Deletion(current_key, current_value)]
                    }
                    ChangeType::Update(u) => {
                        match u {
                            // update the non-indexed column
                            UpdateType::Rest => {
                                // check which one it is and change accordingly
                                match index_type {
                                    MappingIndex::Key(_) => {
                                        // we simply change the mapping value since the key is the secondary index
                                        vec![MappingUpdate::Update(
                                            current_key,
                                            current_value,
                                            new_value,
                                        )]
                                    }
                                    MappingIndex::Value(_) => {
                                        // TRICKY: in this case, the mapping key must change. But from the
                                        // onchain perspective, it means a transfer
                                        // mapping(old_key -> new_key,value)
                                        vec![
                                            MappingUpdate::Deletion(current_key, current_value),
                                            MappingUpdate::Insertion(new_key, current_value),
                                        ]
                                    }
                                }
                            }
                            UpdateType::SecondaryIndex => {
                                match index_type {
                                    MappingIndex::Key(_) => {
                                        // TRICKY: if the mapping key changes, it's a deletion then
                                        // insertion from onchain perspective
                                        vec![
                                            MappingUpdate::Deletion(current_key, current_value),
                                            // we insert the same value but with a new mapping key
                                            MappingUpdate::Insertion(new_key, current_value),
                                        ]
                                    }
                                    MappingIndex::Value(_) => {
                                        // if the value changes, it's a simple update in mapping
                                        vec![MappingUpdate::Update(
                                            current_key,
                                            current_value,
                                            new_value,
                                        )]
                                    }
                                }
                            }
                        }
                    }
                };
                // small iteration to always have a good updated list of mapping keys
                for update in mapping_updates.iter() {
                    match update {
                        MappingUpdate::Deletion(mkey, _) => {
                            info!("Removing key {} from mappping keys tracking", mkey);
                            let key_stored = mkey.to_be_bytes_trimmed_vec();
                            mapping.mapping_keys.retain(|u| u != &key_stored);
                        }
                        MappingUpdate::Insertion(mkey, _) => {
                            info!("Inserting key {} to mappping keys tracking", mkey);
                            mapping.mapping_keys.push(mkey.to_be_bytes_trimmed_vec());
                        }
                        // the mapping key doesn't change here so no need to update the list
                        MappingUpdate::Update(_, _, _) => {}
                    }
                }

                self.apply_update_to_contract(
                    ctx,
                    &UpdateSimpleStorage::Mapping(mapping_updates.clone()),
                )
                .await
                .unwrap();
                let new_block_number = ctx.block_number().await as BlockPrimaryIndex;
                let chain_id = ctx.rpc.get_chain_id().await.unwrap();
                // NOTE HERE is the interesting bit for dist system as this is the logic to execute
                // on receiving updates from scapper. This only needs to have the relevant
                // information from update and it will translate that to changes in the tree.
                self.mapping_to_table_update(
                    new_block_number,
                    mapping_updates,
                    index_type,
                    slot as u8,
                    chain_id,
                )
            }
            TableSourceSlot::SingleValues(_) => {
                let old_table_values = self.current_table_row_values(ctx).await;
                // we can take the first one since we're asking for single value and there is only
                // one row
                let old_table_values = &old_table_values[0];
                let mut current_values = self
                    .current_single_values(ctx)
                    .await
                    .expect("can't get current values");
                match c {
                    ChangeType::Silent => {}
                    ChangeType::Deletion => {
                        panic!("can't remove a single row from blockchain data over single values")
                    }
                    ChangeType::Insertion => {
                        panic!("can't add a new row for blockchain data over single values")
                    }
                    ChangeType::Update(u) => match u {
                        UpdateType::Rest => current_values.s4 = next_address(),
                        UpdateType::SecondaryIndex => {
                            current_values.s2 = next_value();
                        }
                    },
                };

                let contract_update = UpdateSimpleStorage::Single(current_values);
                self.apply_update_to_contract(ctx, &contract_update)
                    .await
                    .unwrap();
                let new_table_values = self.current_table_row_values(ctx).await;
                assert!(
                    new_table_values.len() == 1,
                    "there should be only a single row for single case"
                );
                old_table_values.compute_update(&new_table_values[0])
            }
        }
    }

    ///  1. get current table values
    ///  2. apply new update to contract
    ///  3. get new table values
    ///  4. compute the diff, i.e. the update to apply to the table and the trees
    async fn init_contract_data(
        &mut self,
        ctx: &mut TestContext,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        match self.source {
            TableSourceSlot::Mapping((ref mut mapping, _)) => {
                let index = mapping.index.clone();
                let slot = mapping.slot;
                let init_pair = (next_value(), next_address());
                // NOTE: here is the same address but for different mapping key (10,11)
                let pair2 = (next_value(), init_pair.1);
                let init_state = [init_pair, pair2, (next_value(), next_address())];
                // saving the keys we are tracking in the mapping
                mapping.mapping_keys.extend(
                    init_state
                        .iter()
                        .map(|u| u.0.to_be_bytes_trimmed_vec())
                        .collect::<Vec<_>>(),
                );
                let mapping_updates = init_state
                    .iter()
                    .map(|u| MappingUpdate::Insertion(u.0, u.1.into_word().into()))
                    .collect::<Vec<_>>();

                self.apply_update_to_contract(
                    ctx,
                    &UpdateSimpleStorage::Mapping(mapping_updates.clone()),
                )
                .await
                .unwrap();
                let new_block_number = ctx.block_number().await as BlockPrimaryIndex;
                let chain_id = ctx.rpc.get_chain_id().await.unwrap();
                self.mapping_to_table_update(
                    new_block_number,
                    mapping_updates,
                    index,
                    slot,
                    chain_id,
                )
            }
            TableSourceSlot::SingleValues(_) => {
                let contract_update = SimpleSingleValue {
                    s1: true,
                    s2: U256::from(10),
                    s3: "test".to_string(),
                    s4: next_address(),
                };
                // since the table is not created yet, we are giving an empty table row. When making the
                // diff with the new updated contract storage, the logic will detect it's an initialization
                // phase
                let old_table_values = TableRowValues::default();
                self.apply_update_to_contract(ctx, &UpdateSimpleStorage::Single(contract_update))
                    .await
                    .unwrap();
                let new_table_values = self.current_table_row_values(ctx).await;
                assert!(
                    new_table_values.len() == 1,
                    "single variable case should only have one row"
                );
                let update = old_table_values.compute_update(&new_table_values[0]);
                assert!(update.len() == 1, "one row at a time");
                assert_matches!(
                    update[0],
                    TableRowUpdate::Insertion(_, _),
                    "initialization of the contract's table should be init"
                );
                update
            }
        }
    }

    // construct a row of the table from the actual value in the contract by fetching from MPT
    async fn current_table_row_values(
        &self,
        ctx: &mut TestContext,
    ) -> Vec<TableRowValues<BlockPrimaryIndex>> {
        match self.source {
            TableSourceSlot::Mapping((_, _)) => unimplemented!("not use of it"),
            TableSourceSlot::SingleValues(ref args) => {
                let mut secondary_cell = None;
                let mut rest_cells = Vec::new();
                for slot_info in args.slots.iter() {
                    let slot = slot_info.slot().slot();
                    let query = ProofQuery::new_simple_slot(self.contract_address, slot as usize);
                    let id = identifier_single_var_column(
                        slot,
                        slot_info.metadata().evm_word(),
                        &self.contract_address,
                        ctx.rpc.get_chain_id().await.unwrap(),
                        vec![],
                    );
                    // Instead of manually setting the value to U256, we really extract from the
                    // MPT proof to mimick the way to "see" update. Also, it ensures we are getting
                    // the formatting and endianness right.
                    let value = ctx
                        .query_mpt_proof(&query, BlockNumberOrTag::Number(ctx.block_number().await))
                        .await
                        .storage_proof[0]
                        .value;
                    let cell = Cell::new(id, value);
                    // make sure we separate the secondary cells and rest of the cells separately.
                    if slot == INDEX_SLOT {
                        // we put 0 since we know there are no other rows with that secondary value since we are dealing
                        // we single values, so only 1 row.
                        secondary_cell = Some(SecondaryIndexCell::new_from(cell, 0));
                    } else {
                        rest_cells.push(cell);
                    }
                }
                vec![TableRowValues {
                    current_cells: rest_cells,
                    current_secondary: secondary_cell.unwrap(),
                    primary: ctx.block_number().await as BlockPrimaryIndex,
                }]
            }
        }
    }

    fn mapping_to_table_update(
        &self,
        block_number: BlockPrimaryIndex,
        updates: Vec<MappingUpdate>,
        index: MappingIndex,
        slot: u8,
        chain_id: u64,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        updates
            .iter()
            .flat_map(|mapping_change| {
                match mapping_change {
                    MappingUpdate::Deletion(mkey, mvalue) => {
                        // find the associated row key tree to that value
                        // HERE: there are multiple possibilities:
                        // * search for the entry at the previous block instead
                        // * passing inside the deletion the value deleted as well, so we can
                        // reconstruct the row key
                        // * or have this extra list of mapping keys
                        let entry = UniqueMappingEntry::new(mkey, mvalue);
                        vec![TableRowUpdate::Deletion(entry.to_row_key(&index))]
                    }
                    MappingUpdate::Insertion(mkey, mvalue) => {
                        // we transform the mapping entry into the "table notion" of row
                        let entry = UniqueMappingEntry::new(mkey, mvalue);
                        let (cells, index) = entry.to_update(
                            block_number,
                            &index,
                            slot,
                            &self.contract_address,
                            chain_id,
                            None,
                        );
                        vec![TableRowUpdate::Insertion(cells, index)]
                    }
                    MappingUpdate::Update(mkey, old_value, mvalue) => {
                        // NOTE: we need here to (a) delete current row and (b) insert new row
                        // Regardless of the change if it's on the mapping key or value, since a
                        // row is uniquely identified by its pair (key,value) then if one of those
                        // change, that means the row tree key needs to change as well, i.e. it's a
                        // deletion and addition.
                        let previous_entry = UniqueMappingEntry::new(mkey, old_value);
                        let previous_row_key = previous_entry.to_row_key(&index);
                        let new_entry = UniqueMappingEntry::new(mkey, mvalue);

                        let (mut cells, secondary_index) = new_entry.to_update(
                            block_number,
                            &index,
                            slot,
                            &self.contract_address,
                            // NOTE: here we provide the previous key such that we can
                            // reconstruct the cells tree as it was before and then apply
                            // the update and put it in a new row. Otherwise we don't know
                            // the update plan since we don't have a base tree to deal
                            // with.
                            // In the case the key is the cell, that's good, we don't need to do
                            // anything to the tree then since the doesn't change.
                            // In the case it's the value, then we'll have to reprove the cell.
                            chain_id,
                            Some(previous_row_key.clone()),
                        );
                        match index {
                            MappingIndex::Key(_) => {
                                // in this case, the mapping value changed, so the cells changed so
                                // we need to start from scratch. Telling there was no previous row
                                // key means it's treated as a full new cells tree.
                                cells.previous_row_key = Default::default();
                            }
                            MappingIndex::Value(_) => {
                                // This is a bit hacky way but essentially it means that there is
                                // no update in the cells tree to apply, even tho it's still a new
                                // insertion of a new row, since we pick up the cells tree form the
                                // previous location, and that cells tree didn't change (since it's
                                // based on the mapping key), then no need to update anything.
                                // TODO: maybe make a better API to express the different
                                // possibilities:
                                // * insertion with new cells tree
                                // * insertion without modification to cells tree
                                // * update with modification to cells tree (default)
                                cells.updated_cells = vec![];
                            }
                        };
                        vec![
                            TableRowUpdate::Deletion(previous_row_key),
                            TableRowUpdate::Insertion(cells, secondary_index),
                        ]
                    }
                }
            })
            .collect::<Vec<_>>()
    }
}

#[derive(Clone, Debug)]
enum UpdateSimpleStorage {
    Single(SimpleSingleValue),
    Mapping(Vec<MappingUpdate>),
}

#[derive(Clone, Debug)]
pub struct SimpleSingleValue {
    pub(crate) s1: bool,
    pub(crate) s2: U256,
    pub(crate) s3: String,
    pub(crate) s4: Address,
}

impl UpdateSimpleStorage {
    // This function applies the update in _one_ transaction so that Anvil only moves by one block
    // so we can test the "subsequent block"
    async fn apply_to<T: Transport + Clone, P: Provider<T, N>, N: Network>(
        &self,
        contract: &SimpleInstance<T, P, N>,
    ) {
        match self {
            UpdateSimpleStorage::Single(ref single) => {
                Self::update_single_values(contract, single).await
            }
            UpdateSimpleStorage::Mapping(ref updates) => {
                Self::update_mapping_values(contract, updates).await
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
        values: &[MappingUpdate],
    ) {
        let contract_changes = values
            .iter()
            .map(|tuple| {
                let op: MappingOperation = tuple.into();
                let (k, v) = match tuple {
                    MappingUpdate::Deletion(k, _) => (*k, DEFAULT_ADDRESS.clone()),
                    MappingUpdate::Update(k, _, v) | MappingUpdate::Insertion(k, v) => {
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
                    MappingUpdate::Deletion(k, _) => {
                        let res = contract.m1(*k).call().await.unwrap();
                        let vu: U256 = res._0.into_word().into();
                        let is_correct = vu == U256::from(0);
                        assert!(is_correct, "key deletion not correct on contract");
                    }
                    MappingUpdate::Insertion(k, v) => {
                        let res = contract.m1(*k).call().await.unwrap();
                        let newv: U256 = res._0.into_word().into();
                        let is_correct = newv == *v;
                        assert!(is_correct, "key insertion not correct on contract");
                    }
                    MappingUpdate::Update(k, _, v) => {
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
    pub current_secondary: SecondaryIndexCell,
    pub primary: PrimaryIndex,
}

impl<PrimaryIndex: Clone + Default + PartialEq + Eq> TableRowValues<PrimaryIndex> {
    // Compute the update from the current values and the new values
    fn compute_update(&self, new: &Self) -> Vec<TableRowUpdate<PrimaryIndex>> {
        // this is initialization
        if self == &Self::default() {
            let cells_update = CellsUpdate {
                previous_row_key: RowTreeKey::default(),
                new_row_key: (&new.current_secondary).into(),
                updated_cells: new.current_cells.clone(),
                primary: new.primary.clone(),
            };
            return vec![TableRowUpdate::Insertion(
                cells_update,
                new.current_secondary.clone(),
            )];
        }

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
            new_row_key: (&new.current_secondary).into(),
            previous_row_key: (&self.current_secondary).into(),
            updated_cells,
            primary: new.primary.clone(),
        };

        assert!(
            self.current_secondary.cell().identifier() == new.current_secondary.cell().identifier(),
            "ids are different between updates?"
        );
        assert!(
            self.current_secondary.rest() == new.current_secondary.rest(),
            "computing update from different row"
        );
        match self.current_secondary.cell() != new.current_secondary.cell() {
            true => vec![
                // We first delete then insert a new row in the case of a secondary index value
                // change
                TableRowUpdate::Deletion((&self.current_secondary).into()),
                TableRowUpdate::Insertion(cells_update, new.current_secondary.clone()),
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

/// Represents the update that can come from the chain
#[derive(Clone, Debug)]
enum MappingUpdate {
    // key, value
    Deletion(U256, U256),
    // key, previous_value, new_value
    Update(U256, U256, U256),
    // key, value
    Insertion(U256, U256),
}

/// passing form the rust type to the solidity type
impl From<&MappingUpdate> for MappingOperation {
    fn from(value: &MappingUpdate) -> Self {
        Self::from(match value {
            MappingUpdate::Deletion(_, _) => 0,
            MappingUpdate::Update(_, _, _) => 1,
            MappingUpdate::Insertion(_, _) => 2,
        })
    }
}
static SHIFT: AtomicU64 = AtomicU64::new(0);

use lazy_static::lazy_static;
lazy_static! {
    pub(crate) static ref BASE_VALUE: U256 = U256::from(10);
    static ref DEFAULT_ADDRESS: Address =
        Address::from_str("0xBA401cdAc1A3B6AEede21c9C4A483bE6c29F88C4").unwrap();
}

fn next_mapping_key() -> U256 {
    next_value()
}
fn next_address() -> Address {
    let shift = SHIFT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(shift);
    let slice = rng.gen::<[u8; 20]>();
    Address::from_slice(&slice)
}
fn next_value() -> U256 {
    let shift = SHIFT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let bv: U256 = *BASE_VALUE;
    bv + U256::from(shift)
}

/// Construct the storage slot information for the simple variable slots.
// bool public s1
// uint256 public s2
// string public s3
// address public s4
fn single_var_slot_info(contract_address: &Address, chain_id: u64) -> Vec<StorageSlotInfo> {
    const NUM_ACTUAL_COLUMNS: usize = 4;
    // bool, uint256, string, address
    const SINGLE_SLOT_LENGTHS: [usize; 4] = [1, 32, 32, 20];

    let table_info = SINGLE_SLOTS
        .into_iter()
        .zip_eq(SINGLE_SLOT_LENGTHS)
        .map(|(slot, length)| {
            let identifier = F::from_canonical_u64(identifier_single_var_column(
                slot,
                0,
                contract_address,
                chain_id,
                vec![],
            ));

            let slot = F::from_canonical_u8(slot);
            let length = F::from_canonical_usize(length);

            ColumnInfo::new(slot, identifier, F::ZERO, F::ZERO, length, F::ZERO)
        })
        .collect_vec();

    SINGLE_SLOTS
        .into_iter()
        .enumerate()
        .map(|(i, slot)| {
            // Create the simple slot.
            let slot = StorageSlot::Simple(slot as usize);

            // Create the metadata gadget.
            let metadata = MetadataGadget::new(
                table_info.clone(),
                slice::from_ref(&table_info[i].identifier()),
                NUM_ACTUAL_COLUMNS,
                0,
            );

            StorageSlotInfo::new(slot, metadata, F::ZERO, F::ZERO)
        })
        .collect_vec()
}
