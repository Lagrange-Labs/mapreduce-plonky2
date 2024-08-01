//! Test case for local Simple contract
//! Reference `test-contracts/src/Simple.sol` for the details of Simple contract.

use anyhow::{bail, Result};
use itertools::Unique;
use log::{debug, info};
use mp2_v1::values_extraction::{
    identifier_block_column, identifier_for_mapping_key_column,
    identifier_for_mapping_value_column, identifier_single_var_column,
};
use rand::{thread_rng, Rng};
use ryhope::{storage::RoEpochKvStorage, tree::TreeTopology};
use serde::Deserialize;

use crate::common::{
    bindings::simple::Simple::{self, MappingChange, MappingOperation},
    cases::{random_address, random_u256, MappingIndex},
    celltree::{Cell, TreeCell},
    proof_storage::{BlockPrimaryIndex, ProofKey, ProofStorage},
    rowtree::{CellCollection, Row, RowTreeKey, SecondaryIndexCell},
    table::{
        CellsUpdate, IndexType, IndexUpdate, Table, TableColumn, TableColumns, TableID,
        TreeRowUpdate, TreeUpdateType,
    },
    TestContext,
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
    rpc::types::Block,
};
use mp2_common::{
    eth::{left_pad32, ProofQuery, StorageSlot},
    proof::ProofWithVK,
    F,
};
use std::{assert_matches::assert_matches, collections::HashMap, str::FromStr};

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
impl TestCase {
    /// Deploy a simple contract, and insert some dummy values at first
    pub(crate) async fn new_local_simple_contract<P: ProofStorage>(
        ctx: &TestContext<P>,
    ) -> Result<Vec<Self>> {
        //let single = Self::single_value_test_case(ctx).await?;
        let mapping = Self::mapping_test_case(ctx).await?;
        Ok(vec![mapping])
    }

    pub(crate) async fn single_value_test_case<P: ProofStorage>(
        ctx: &TestContext<P>,
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
        let index_genesis_block = ctx.block_number().await;

        let source = TableSourceSlot::SingleValues(SingleValuesExtractionArgs {
            slots: SINGLE_SLOTS.to_vec(),
        });

        // + 1 because we are going to deploy some update to contract in a transaction, which for
        // Anvil means it's a new block
        // TODO: change sbbst such that it doesn't require this max . Though we still need the
        // correct shift.
        let indexing_genesis_block = ctx.block_number().await + 1;
        let table_id = TableID::new(index_genesis_block, contract_address, &source.slots());
        // Defining the columns structure of the table from the source slots
        // This is depending on what is our data source, mappings and CSV both have their o
        // own way of defining their table.
        let columns = TableColumns {
            primary: TableColumn {
                identifier: identifier_block_column(),
                index: IndexType::Primary,
            },
            secondary: TableColumn {
                identifier: identifier_single_var_column(INDEX_SLOT, contract_address),
                index: IndexType::Secondary,
            },
            rest: SINGLE_SLOTS
                .iter()
                .enumerate()
                .filter_map(|(i, slot)| match i {
                    _ if *slot == INDEX_SLOT => None,
                    _ => {
                        let identifier = identifier_single_var_column(*slot, contract_address);
                        Some(TableColumn {
                            identifier,
                            index: IndexType::None,
                        })
                    }
                })
                .collect::<Vec<_>>(),
        };
        Ok(Self {
            source: source.clone(),
            table: Table::new(indexing_genesis_block, table_id, columns),
            contract_address: *contract_address,
            contract_extraction: ContractExtractionArgs {
                slot: StorageSlot::Simple(CONTRACT_SLOT),
            },
        })
    }

    pub(crate) async fn mapping_test_case<P: ProofStorage>(ctx: &TestContext<P>) -> Result<Self> {
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
        let index_genesis_block = ctx.block_number().await + 1;
        // to toggle off and on
        let value_as_index = true;
        let value_id = identifier_for_mapping_value_column(MAPPING_SLOT, contract_address);
        let key_id = identifier_for_mapping_key_column(MAPPING_SLOT, contract_address);
        let (index_identifier, mapping_index, cell_identifier) = match value_as_index {
            true => (value_id, MappingIndex::Value(value_id), key_id),
            false => (key_id, MappingIndex::Key(key_id), value_id),
        };

        let mapping_args = MappingValuesExtractionArgs {
            slot: MAPPING_SLOT,
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

        let table_id = TableID::new(index_genesis_block, contract_address, &source.slots());
        // Defining the columns structure of the table from the source slots
        // This is depending on what is our data source, mappings and CSV both have their o
        // own way of defining their table.
        let columns = TableColumns {
            primary: TableColumn {
                identifier: identifier_block_column(),
                index: IndexType::Primary,
            },
            secondary: TableColumn {
                identifier: index_identifier,
                index: IndexType::Secondary,
            },
            rest: vec![TableColumn {
                identifier: cell_identifier,
                index: IndexType::None,
            }],
        };
        let table = Table::new(index_genesis_block, table_id, columns);
        Ok(Self {
            contract_extraction: ContractExtractionArgs {
                slot: StorageSlot::Simple(CONTRACT_SLOT),
            },
            contract_address: *contract_address,
            source,
            table,
        })
    }

    pub async fn run<P: ProofStorage>(
        &mut self,
        ctx: &mut TestContext<P>,
        changes: Vec<ChangeType>,
    ) -> Result<()> {
        // Call the contract function to set the test data.
        // TODO: make it return an update for a full table, right now it's only for one row.
        // to make when we deal with mappings
        let table_row_updates = self.init_contract_data(ctx).await;
        log::info!("Applying initial updates to contract done");
        let bn = ctx.block_number().await as BlockPrimaryIndex;

        // we first run the initial preprocessing and db creation.
        self.run_mpt_preprocessing(ctx, bn).await?;
        // then we run the creation of our tree
        self.run_lagrange_preprocessing(ctx, bn, table_row_updates)
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
            self.run_mpt_preprocessing(ctx, bn).await?;
            self.run_lagrange_preprocessing(ctx, bn, table_row_updates)
                .await?;
        }
        Ok(())
    }

    // separate function only dealing with preprocesisng MPT proofs
    // This function is "generic" as it can table a table description
    async fn run_lagrange_preprocessing<P: ProofStorage>(
        &mut self,
        ctx: &mut TestContext<P>,
        bn: BlockPrimaryIndex,
        // Note there is only one entry for a single variable update, but multiple for mappings for
        // example
        updates: Vec<TableRowUpdate>,
    ) -> Result<()> {
        let current_block = ctx.block_number().await;
        // apply the new cells to the trees
        // NOTE ONLY the rest of the cells, not including the secondary one !
        let rows_update = updates
            .iter()
            .map(|row_update| match row_update {
                TableRowUpdate::Insertion(ref new_cells, _) => {
                    let tree_update = self
                        .table
                        .apply_cells_update(new_cells.clone(), TreeUpdateType::Insertion)
                        .expect("can't insert in cells tree");
                    // no cells before, i.e. we return the same cells
                    let new_cell_collection =
                        row_update.updated_cells_collection(&CellCollection::default());
                    let new_row_key = tree_update.new_row_key.clone();
                    let row_payload =
                        ctx.prove_cells_tree(&self.table, new_cell_collection, tree_update);
                    TreeRowUpdate::Insertion(Row {
                        k: new_row_key,
                        payload: row_payload,
                    })
                }
                TableRowUpdate::Update(ref new_cells) => {
                    let tree_update = self
                        .table
                        .apply_cells_update(new_cells.clone(), TreeUpdateType::Update)
                        .expect("can't insert in cells tree");
                    // fetch all the current cells, merge with the new modified ones
                    let old_row = self
                        .table
                        .row
                        .try_fetch(&new_cells.previous_row_key)
                        .expect("unable to find preivous row");
                    let new_cell_collection = row_update.updated_cells_collection(&old_row.cells);
                    let new_row_key = tree_update.new_row_key.clone();
                    let row_payload =
                        ctx.prove_cells_tree(&self.table, new_cell_collection, tree_update);
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
            })
            .collect::<Vec<_>>();
        info!("Generated final CELLs tree proofs for block {current_block}");
        let updates = self.table.apply_row_update(rows_update)?;
        info!("Applied updates to row tree");
        let index_node = ctx
            .prove_update_row_tree(bn, &self.table, updates)
            .expect("unable to prove row tree");
        info!("Generated final ROWs tree proofs for block {current_block}");

        // NOTE the reason we separate and use block number as IndexTreeKey is because this index
        // could be different if we were using NOT block number. It should be the index of the
        // enumeration, something that may arise during the query when building a result tree.
        // NOTE2: There is no "init" field here since we _always_ insert in the index tree by
        // definition. This is a core assumption we currently have and that will not change in the
        // short term.
        let index_update = IndexUpdate {
            added_index: (ctx.block_number().await as BlockPrimaryIndex, index_node),
        };
        let updates = self
            .table
            .apply_index_update(index_update)
            .expect("can't update index tree");
        info!("Applied updates to index tree for block {current_block}");
        let root_proof_key = ctx
            .prove_update_index_tree(bn, &self.table, updates.plan)
            .await;
        info!("Generated final BLOCK tree proofs for block {current_block}");
        let _ = ctx.prove_ivc(&self.table.id, &self.table.index).await;
        info!("Generated final IVC proof for block {}", current_block,);

        Ok(())
    }

    // separate function only dealing with preprocessing MPT proofs
    async fn run_mpt_preprocessing<P: ProofStorage>(
        &self,
        ctx: &mut TestContext<P>,
        bn: BlockPrimaryIndex,
    ) -> Result<()> {
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

        let table_id = &self.table.id;
        // we construct the proof key for both mappings and single variable in the same way since
        // it is derived from the table id which should be different for any tables we create.
        let proof_key = ProofKey::ValueExtraction((table_id.clone(), bn as BlockPrimaryIndex));
        let (value_proof, compound, length) = match self.source {
            // first lets do without length
            TableSourceSlot::Mapping((ref mapping, _)) => {
                let mapping_root_proof = match ctx.storage.get_proof_exact(&proof_key) {
                    Ok(p) => p,
                    Err(_) => {
                        let mapping_values_proof = ctx
                            .prove_mapping_values_extraction(
                                &self.contract_address,
                                mapping.slot,
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
                // it's a compoound value type of proof since we're not using the length
                (mapping_root_proof, true, None)
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
                // we're just proving a single set of a value
                (single_value_proof, false, None)
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
        Ok(())
    }

    // Returns the table updated
    async fn apply_update_to_contract<P: ProofStorage>(
        &self,
        ctx: &TestContext<P>,
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

    async fn current_single_values<P: ProofStorage>(
        &self,
        ctx: &TestContext<P>,
    ) -> Result<SimpleSingleValue> {
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

    async fn random_contract_update<P: ProofStorage>(
        &mut self,
        ctx: &mut TestContext<P>,
        c: ChangeType,
    ) -> Vec<TableRowUpdate> {
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
                // for ease of debugging, just take incremental keys
                let new_key = mapping
                    .mapping_keys
                    .iter()
                    .map(|k| U256::from_be_slice(k))
                    .max()
                    .unwrap()
                    + U256::from(1);
                let query = ProofQuery::new_mapping_slot(*address, slot, mkey.to_owned());
                let response = ctx
                    .query_mpt_proof(&query, BlockNumberOrTag::Number(ctx.block_number().await))
                    .await;
                let current_value = response.storage_proof[0].value;
                let current_key = U256::from_be_slice(mkey);

                let mapping_updates = match c {
                    ChangeType::Insertion => {
                        let new_entry = (new_key, random_address());
                        vec![MappingUpdate::Insertion(
                            new_entry.0,
                            new_entry.1.into_word().into(),
                        )]
                    }
                    ChangeType::Deletion => {
                        // NOTE: We care about the value here since that allows _us_ to pinpoint the
                        // correct row in the table and delete it since for a mpping, we uniquely
                        // identify row per (mapping_key,mapping_value) (in the order dictated by
                        // the secondary index)
                        vec![MappingUpdate::Deletion(current_key, current_value)]
                    }
                    ChangeType::Update(u) => {
                        let new_value = random_address().into_word().into();
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
                                        // insertion
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
                // NOTE HERE is the interesting bit for dist system as this is the logic to execute
                // on receiving updates from scapper. This only needs to have the relevant
                // information from update and it will translate that to changes in the tree.
                self.mapping_to_table_update(mapping_updates, index_type, slot as u8)
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
                    ChangeType::Deletion => {
                        panic!("can't remove a single row from blockchain data over single values")
                    }
                    ChangeType::Insertion => {
                        panic!("can't add a new row for blockchain data over single values")
                    }
                    ChangeType::Update(u) => match u {
                        UpdateType::Rest => {
                            current_values.s4 =
                                Address::from_slice(&thread_rng().gen::<[u8; 20]>());
                        }
                        UpdateType::SecondaryIndex => {
                            current_values.s2 = U256::from_be_bytes(thread_rng().gen::<[u8; 32]>());
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
    async fn init_contract_data<P: ProofStorage>(
        &mut self,
        ctx: &mut TestContext<P>,
    ) -> Vec<TableRowUpdate> {
        match self.source {
            TableSourceSlot::Mapping((ref mut mapping, _)) => {
                let index = mapping.index.clone();
                let slot = mapping.slot;
                let init_state = [
                    (
                        U256::from(10),
                        Address::from_str("0xb90ed61bffed1df72f2ceebd965198ad57adfcbd").unwrap(),
                    ),
                    (
                        // NOTE: here is the same address but for different mapping key (10,11)
                        U256::from(11),
                        Address::from_str("0xb90ed61bffed1df72f2ceebd965198ad57adfcbd").unwrap(),
                    ),
                    (
                        U256::from(12),
                        Address::from_str("0xb90ed61bffed1df72f2ceebd965198ad57adfeee").unwrap(),
                    ),
                ];
                // saving the keys we are tracking in the mapping
                mapping.mapping_keys.extend(
                    init_state
                        .iter()
                        .map(|u| u.0.to_be_bytes_trimmed_vec())
                        .collect::<Vec<_>>(),
                );
                let mapping_updates = init_state
                    .iter()
                    .map(|u| MappingUpdate::Insertion(u.0.clone(), u.1.into_word().into()))
                    .collect::<Vec<_>>();

                self.apply_update_to_contract(
                    ctx,
                    &UpdateSimpleStorage::Mapping(mapping_updates.clone()),
                )
                .await
                .unwrap();
                self.mapping_to_table_update(mapping_updates, index, slot)
            }
            TableSourceSlot::SingleValues(_) => {
                let contract_update = SimpleSingleValue {
                    s1: true,
                    s2: U256::from(10),
                    s3: "test".to_string(),
                    s4: Address::from_str("0xb90ed61bffed1df72f2ceebd965198ad57adfcbd").unwrap(),
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

    async fn current_mapping_entries<P: ProofStorage>(
        &self,
        ctx: &mut TestContext<P>,
    ) -> Vec<UniqueMappingEntry> {
        match self.source {
            TableSourceSlot::Mapping((ref mapping, _)) => {
                let mut updates = Vec::new();
                for mkey in mapping.mapping_keys.iter() {
                    // for each mapping key we track, we fetch the associated value
                    let query = ProofQuery::new_mapping_slot(
                        self.contract_address,
                        mapping.slot as usize,
                        mkey.to_owned(),
                    );
                    let response = ctx
                        .query_mpt_proof(&query, BlockNumberOrTag::Number(ctx.block_number().await))
                        .await;
                    let unique_entry = UniqueMappingEntry::from((
                        response.storage_proof[0].key.0.into(),
                        response.storage_proof[0].value,
                    ));
                    updates.push(unique_entry);
                }
                updates
            }
            _ => panic!("invalid case"),
        }
    }

    // construct a row of the table from the actual value in the contract by fetching from MPT
    async fn current_table_row_values<P: ProofStorage>(
        &self,
        ctx: &mut TestContext<P>,
    ) -> Vec<TableRowValues> {
        match self.source {
            TableSourceSlot::Mapping((ref mapping, _)) => {
                let unique_entries = self.current_mapping_entries(ctx).await;
                unique_entries
                    .iter()
                    .map(|u| {
                        u.to_table_row_value(&mapping.index, mapping.slot, &self.contract_address)
                    })
                    .collect::<Vec<_>>()
            }
            TableSourceSlot::SingleValues(ref args) => {
                let mut secondary_cell = None;
                let mut rest_cells = Vec::new();
                for slot in args.slots.iter() {
                    let query = ProofQuery::new_simple_slot(self.contract_address, *slot as usize);
                    let id = identifier_single_var_column(*slot, &self.contract_address);
                    // Instead of manually setting the value to U256, we really extract from the
                    // MPT proof to mimick the way to "see" update. Also, it ensures we are getting
                    // the formatting and endianness right.
                    let value = ctx
                        .query_mpt_proof(&query, BlockNumberOrTag::Number(ctx.block_number().await))
                        .await
                        .storage_proof[0]
                        .value;
                    let cell = Cell { id, value };
                    // make sure we separate the secondary cells and rest of the cells separately.
                    if *slot == INDEX_SLOT {
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
                }]
            }
        }
    }

    fn mapping_to_table_update(
        &self,
        updates: Vec<MappingUpdate>,
        index: MappingIndex,
        slot: u8,
    ) -> Vec<TableRowUpdate> {
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
                        let (cells, index) =
                            entry.to_update(&index, slot, &self.contract_address, None);
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

                        let (mut cells, index) = new_entry.to_update(
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
                            Some(previous_row_key.clone()),
                        );
                        match index {
                            MappingIndex::Key(_) => {
                                // in this case, the mapping value changed, so the cells changed so
                                // we start from scratch (since)
                                cells.previous_row_key = Default::default();
                            }
                            MappingIndex::Value(_) => {
                                // This is a bit hacky way but essentially it means that there is
                                // no update in the cells tree to apply, even tho it's still a new
                                // insertion of a new row, since we pick up the cells tree form the
                                // previous location, and that cells tree didn't change (since it's
                                // based on the mapping key), then no need to update anything.
                                cells.updated_cells = vec![];
                            }
                        }
                        vec![
                            TableRowUpdate::Deletion(previous_row_key),
                            TableRowUpdate::Insertion(cells, index),
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
                    MappingUpdate::Deletion(k, _) => (*k, random_address()),
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
}

#[derive(Clone, Debug)]
pub enum UpdateType {
    SecondaryIndex,
    Rest,
}

/// Represents in a generic way the value present in a row from a table
/// TODO: add the first index in generic way as well for CSV
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct TableRowValues {
    // cells without the secondary index
    pub current_cells: Vec<Cell>,
    pub current_secondary: SecondaryIndexCell,
}

impl TableRowValues {
    // Compute the update from the current values and the new values
    fn compute_update(&self, new: &Self) -> Vec<TableRowUpdate> {
        // this is initialization
        if self == &Self::default() {
            let cells_update = CellsUpdate {
                previous_row_key: RowTreeKey::default(),
                new_row_key: (&new.current_secondary).into(),
                updated_cells: new.current_cells.clone(),
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
                    .find(|new| current.id == new.id)
                    .expect("missing cell");
                if new.value != current.value {
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
        };

        assert!(
            self.current_secondary.cell().id == new.current_secondary.cell().id,
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
            false => vec![TableRowUpdate::Update(cells_update)],
        }
    }
}

/// The structure representing the updates that have happened on a table
/// This is computed from the update of a contract in the case of the current test, but
/// should be given directly in case of CSV file.
#[derive(Clone, Debug)]
pub enum TableRowUpdate {
    /// A row to be deleted
    Deletion(RowTreeKey),
    /// NOTE : this only includes changes on the regular non indexed cells.
    /// This must NOT include an update on the secondary index value
    /// A new secondary index value is translated to a deletion and then a new insert
    /// since that is what must happen at the tree level where we delete the node corresponding to
    /// the previous secondary index value.
    Update(CellsUpdate),
    /// Used to insert a new row from scratch
    Insertion(CellsUpdate, SecondaryIndexCell),
}

impl TableRowUpdate {
    // Returns the full cell collection to put inside the JSON row payload
    fn updated_cells_collection(&self, previous: &CellCollection) -> CellCollection {
        let new_cells = match self {
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
        };
        previous.merge_with_update(&new_cells)
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
