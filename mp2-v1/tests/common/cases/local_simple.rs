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

        // TODO: change sbbst such that it doesn't require this max . Though we still need the
        // correct shift.
        // 2 because 1 tx to deploy contract, another one to call it
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
        let index_genesis_block = ctx.block_number().await;

        let mapping_args = MappingValuesExtractionArgs {
            slot: MAPPING_SLOT,
            index: MappingIndex::Value(identifier_for_mapping_value_column(
                MAPPING_SLOT,
                contract_address,
            )),
            // at the beginning there is no mapping key inserted
            // NOTE: This array is _one_ way to handle mapping updates. Another one could be that
            // during updates, the scrapper gives the previous value and the new value for updates.
            // That's really the main information missing that can avoid storing this array.
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
                identifier: identifier_for_mapping_key_column(MAPPING_SLOT, contract_address),
                index: IndexType::Secondary,
            },
            rest: vec![TableColumn {
                identifier: identifier_for_mapping_value_column(MAPPING_SLOT, contract_address),
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

    pub async fn run<P: ProofStorage>(&mut self, ctx: &mut TestContext<P>) -> Result<()> {
        // Call the contract function to set the test data.
        // TODO: make it return an update for a full table, right now it's only for one row.
        // to make when we deal with mappings
        let table_row_updates = self.init_contract_data(ctx).await;
        log::info!("Applying initial updates to contract done");

        // we first run the initial preprocessing and db creation.
        self.run_mpt_preprocessing(ctx).await?;
        // then we run the creation of our tree
        self.run_lagrange_preprocessing(ctx, table_row_updates)
            .await?;

        log::info!(
            "FIRST block {} finished proving. Moving on to update",
            ctx.block_number().await
        );

        let updates = vec![
            ChangeType::Update(UpdateType::Rest),
            ChangeType::Update(UpdateType::SecondaryIndex),
        ];
        for ut in updates {
            let table_row_updates = self.random_contract_update(ctx, ut).await;
            log::info!(
                "Applying follow up updates to contract done - now at block {}",
                ctx.block_number().await
            );
            // we first run the initial preprocessing and db creation.
            // NOTE: we don't show copy on write here - the fact of only reproving what has been
            // updated, as this is not new from v0.
            // TODO: implement copy on write mechanism for MPT
            self.run_mpt_preprocessing(ctx).await?;
            self.run_lagrange_preprocessing(ctx, table_row_updates)
                .await?;
        }
        Ok(())
    }

    // separate function only dealing with preprocesisng MPT proofs
    // This function is "generic" as it can table a table description
    async fn run_lagrange_preprocessing<P: ProofStorage>(
        &mut self,
        ctx: &mut TestContext<P>,
        // Note there is only one entry for a single variable update, but multiple for mappings for
        // example
        updates: Vec<TableRowUpdate>,
    ) -> Result<()> {
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
        info!("Generated final CELLs tree proofs for single variables");
        let updates = self.table.apply_row_update(rows_update)?;
        info!("Applied updates to row tree");
        let index_node = ctx.prove_update_row_tree(&self.table, updates).await;
        info!("Generated final ROWs tree proofs for single variables");

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
        info!("Applied updates to index tree");
        let root_proof_key = ctx.prove_update_index_tree(&self.table, updates.plan).await;
        info!("Generated final BLOCK tree proofs for single variables");
        let _ = ctx.prove_ivc(&self.table.id, &self.table.index).await;
        info!(
            "Generated final IVC proof for single variable - block {}",
            ctx.block_number().await
        );

        Ok(())
    }

    // separate function only dealing with preprocessing MPT proofs
    async fn run_mpt_preprocessing<P: ProofStorage>(&self, ctx: &mut TestContext<P>) -> Result<()> {
        let bn = ctx.block_number().await;
        let contract_proof_key =
            ProofKey::ContractExtraction((self.contract_address, bn as BlockPrimaryIndex));
        let contract_proof = match ctx.storage.get_proof(&contract_proof_key) {
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
        let block_proof = match ctx.storage.get_proof(&block_proof_key) {
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
        match self.source {
            TableSourceSlot::Mapping(_) => panic!("not yet implemented"),
            TableSourceSlot::SingleValues(ref args) => {
                let proof_key =
                    ProofKey::ValueExtraction((table_id.clone(), bn as BlockPrimaryIndex));
                let single_value_proof = match ctx.storage.get_proof(&proof_key) {
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
                            println!("[--] FINAL MPT DIGEST VALUE --> {:?} ", pi.values_digest());
                        }
                        single_values_proof
                    }
                };
                // final extraction for single variables combining the different proofs generated before
                let final_key =
                    ProofKey::FinalExtraction((table_id.clone(), bn as BlockPrimaryIndex));
                match ctx.storage.get_proof(&final_key) {
                    Ok(proof) => proof,
                    Err(_) => {
                        let proof = ctx
                            .prove_final_extraction(
                                contract_proof,
                                single_value_proof,
                                block_proof,
                                false,
                                None,
                            )
                            .await
                            .unwrap();
                        ctx.storage.store_proof(final_key, proof.clone())?;
                        debug!("SAVING final extraction key from {table_id:?} and {bn}");
                        info!("Generated Final Extraction (C.5.1) proof for single variables");
                        proof
                    }
                }
            }
        };

        info!("Generated ALL Single Variables MPT preprocessing proofs");
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
        let old_table_values = self.current_table_row_values(ctx).await;
        match self.source {
            // NOTE 1: The first part is just trying to construct the right input to simulate any
            // changes on a mapping. This is mostly irrelevant for dist system but needs to
            // manually construct our test cases here. The second part is more interesting as it looks at "what to do
            // when receiving an update from scrapper".
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
                let idx = thread_rng().gen_range(0..mapping.mapping_keys.len());
                let mkey = &mapping.mapping_keys[idx];
                let slot = mapping.slot as usize;
                let index_type = mapping.index.clone();
                let address = &self.contract_address.clone();

                let mapping_updates = match c {
                    ChangeType::Insertion => {
                        let new_entry = (random_u256(), random_address());
                        mapping
                            .mapping_keys
                            .push(new_entry.0.to_be_bytes_trimmed_vec());
                        vec![MappingUpdate::Insertion(
                            new_entry.0,
                            new_entry.1.into_word().into(),
                        )]
                    }
                    ChangeType::Deletion => {
                        // we just want to delete any row
                        // we dont care about the value here.
                        vec![MappingUpdate::Deletion(
                            U256::from_be_slice(&mkey),
                            random_u256(),
                        )]
                    }
                    ChangeType::Update(u) => {
                        let query =
                            ProofQuery::new_mapping_slot(address.clone(), slot, mkey.to_owned());
                        let response = ctx
                            .query_mpt_proof(
                                &query,
                                BlockNumberOrTag::Number(ctx.block_number().await),
                            )
                            .await;
                        let current_key = U256::from_be_slice(mkey);
                        let current_value = response.storage_proof[0].value;
                        let new_key = random_u256();
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
                                        // onchain perspective, it means it's first a deletion of
                                        // the mapping entry, with the insertion of a new one with
                                        // the same mapping value but a different mapping key.
                                        vec![
                                            MappingUpdate::Deletion(current_key, current_value),
                                            MappingUpdate::Insertion(new_key, new_value),
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

                let previous_entries = self.current_mapping_entries(ctx).await;
                self.apply_update_to_contract(
                    ctx,
                    &UpdateSimpleStorage::Mapping(mapping_updates.clone()),
                )
                .await
                .unwrap();
                // NOTE HERE is the interesting bit for dist system as this is the logic to execute
                // on receiving updates from scapper. This only needs to have the relevant
                // information from update and it will translate that to changes in the tree.
                for mapping_change in mapping_updates {
                    let _ = match mapping_change {
                        MappingUpdate::Deletion(mkey, mvalue) => {
                            // find the associated row key tree to that value
                            // HERE: there are multiple possibilities:
                            // * search for the entry at the previous block instead
                            // * passing inside the deletion the value deleted as well, so we can
                            // reconstruct the row key
                            // * or have this extra list of mapping keys
                            let entry = UniqueMappingEntry::from((mkey, mvalue));
                            vec![TableRowUpdate::Deletion(entry.to_row_key(&index_type))]
                        }
                        MappingUpdate::Insertion(mkey, mvalue) => {
                            // we transform the mapping entry into the "table notion" of row
                            let entry = UniqueMappingEntry::from((mkey, mvalue));
                            let (cells, index) = entry.to_update(&index_type, slot as u8, address);
                            vec![TableRowUpdate::Insertion(cells, index)]
                        }
                        MappingUpdate::Update(mkey, old_value, mvalue) => {
                            // TRICKY: here we must _find_ the current mapping entry
                            // being targeted to transform it to the table notion
                            // if the secondary index is the mapping value, that means
                            // we need to delete a row and insert a new row
                            // If the secondary index is the mapping key, then it's easy,
                            // it's a simple change in the row.
                            let previous_entry = UniqueMappingEntry::from((mkey, old_value));
                            let previous_row_key = previous_entry.to_row_key(&index_type);
                            let previous_table_value =
                                previous_entry.to_table_row_value(&index_type, slot as u8, address);
                            let new_entry = UniqueMappingEntry::from((mkey, mvalue));
                            match index_type {
                                MappingIndex::Key(_) => {
                                    // update the value, key == secondary index so it's a regular
                                    // update
                                    let mut cell = previous_table_value.current_cells[0].clone();
                                    cell.value = mvalue;
                                    let cells_update = CellsUpdate {
                                        previous_row_key: previous_row_key.clone(),
                                        new_row_key: previous_row_key,
                                        updated_cells: vec![cell],
                                    };
                                    vec![TableRowUpdate::Update(cells_update)]
                                }
                                MappingIndex::Value(_) => {
                                    // here we need to delete the previous entry
                                    // then to insert a new one
                                    let key_to_delete: RowTreeKey =
                                        previous_table_value.current_secondary.into();
                                    let (cells, index) =
                                        new_entry.to_update(&index_type, slot as u8, address);
                                    vec![
                                        TableRowUpdate::Deletion(key_to_delete),
                                        TableRowUpdate::Insertion(cells, index),
                                    ]
                                }
                            }
                        }
                    };
                }
                vec![]
            }
            TableSourceSlot::SingleValues(_) => {
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
                let update = [
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
                        Address::from_str("0xbbbbed61bffed1df72f2ceebd965198ad57adffff").unwrap(),
                    ),
                ];
                // saving the keys we are tracking in the mapping
                mapping.mapping_keys.extend(
                    update
                        .iter()
                        .map(|u| u.0.to_be_bytes_trimmed_vec())
                        .collect::<Vec<_>>(),
                );

                self.apply_update_to_contract(
                    ctx,
                    &UpdateSimpleStorage::Mapping(
                        update
                            .iter()
                            .map(|(a, b)| {
                                MappingUpdate::Insertion(a.to_owned(), b.into_word().into())
                            })
                            .collect::<Vec<_>>(),
                    ),
                )
                .await
                .unwrap();
                // Note it's ok to call that here since self.source.mapping have been updated with
                // all the keys to track. In dist system, this thing should be done by QE <->
                // Scrapper communication.
                let new_table_values = self.current_table_row_values(ctx).await;
                // Specially for initialization it's ok to compute update as the diff between the
                // two but for general mapping update, it's not as trivial.
                let updates = new_table_values
                    .into_iter()
                    .flat_map(|row| TableRowValues::default().compute_update(&row))
                    .collect::<Vec<_>>();

                updates
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
                return vec![TableRowValues {
                    current_cells: rest_cells,
                    current_secondary: secondary_cell.unwrap(),
                }];
            }
        }
    }
}

#[derive(Clone, Debug)]
enum UpdateSimpleStorage {
    Single(SimpleSingleValue),
    Mapping(Vec<MappingUpdate>),
}

// Note right now we only support changing one entry inside a single block since Anvil
// creates a new block per transaction.
// If we need more, we need to modify contract to support a vector of changes.
// That's ok as long as we do a single update
pub type SimpleMapping = Vec<(U256, Address)>;

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
                    MappingUpdate::Deletion(k, _) => (k.clone(), random_address()),
                    MappingUpdate::Update(k, _, v) | MappingUpdate::Insertion(k, v) => {
                        (k.clone(), Address::from_slice(&v.to_be_bytes_trimmed_vec()))
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
        log::info!("Updated simple contract single values");
    }
}

enum ChangeType {
    Deletion,
    Insertion,
    Update(UpdateType),
}

enum UpdateType {
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
