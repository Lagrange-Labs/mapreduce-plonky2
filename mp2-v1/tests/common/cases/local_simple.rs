//! Test case for local Simple contract
//! Reference `test-contracts/src/Simple.sol` for the details of Simple contract.

use anyhow::{bail, Result};
use log::{debug, info};
use mp2_v1::values_extraction::{identifier_block_column, identifier_single_var_column};
use rand::{thread_rng, Rng};
use ryhope::{storage::RoEpochKvStorage, tree::TreeTopology};
use serde::Deserialize;

use crate::common::{
    bindings::simple::Simple,
    celltree::{Cell, TreeCell},
    proof_storage::{BlockPrimaryIndex, ProofKey, ProofStorage},
    rowtree::{CellCollection, Row, RowTreeKey, SecondaryIndexCell},
    table::{
        CellsUpdate, IndexType, IndexUpdate, RowUpdate, Table, TableColumn, TableColumns, TableID,
    },
    TestContext,
};

use super::{
    super::bindings::simple::Simple::SimpleInstance, ContractExtractionArgs, LengthExtractionArgs,
    MappingKey, MappingValuesExtractionArgs, SingleValuesExtractionArgs, TableSourceSlot, TestCase,
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
    F,
};
use std::{collections::HashMap, str::FromStr};

/// Test slots for single values extraction
const SINGLE_SLOTS: [u8; 4] = [0, 1, 2, 3];
/// Define which slots is the secondary index. In this case, it's the U256
const INDEX_SLOT: u8 = 1;

/// Test slot for mapping values extraction
const MAPPING_SLOT: u8 = 4;

/// Test mapping addresses (keys) for mapping values extraction
const MAPPING_ADDRESSES: [&str; LENGTH_VALUE as usize] = [
    "0x3bf5733f695b2527acc7bd4c5350e57acfd9fbb5",
    "0x6cac7190535f4908d0524e7d55b3750376ea1ef7",
];

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
        let source = TableSourceSlot::SingleValues(SingleValuesExtractionArgs {
            slots: SINGLE_SLOTS.to_vec(),
        });

        // TODO: change sbbst such that it doesn't require this max . Though we still need the
        // correct shift.
        // 2 because 1 tx to deploy contract, another one to call it
        // TODO WARNING: this won't work with mappings, needs refactor somewhere
        let indexing_genesis_block = ctx.block_number().await + 1;
        let table_id = TableID::new(indexing_genesis_block, contract_address, &source.slots());
        // simply a mapping we need keep around to make sure we always give the right update to the
        // tree since it is not aware of the slots (this is blockchain specific info).
        let mut mapping = HashMap::default();
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
                        mapping.insert(*slot, identifier);
                        Some(TableColumn {
                            identifier,
                            index: IndexType::None,
                        })
                    }
                })
                .collect::<Vec<_>>(),
        };
        mapping.insert(INDEX_SLOT, columns.secondary_column().identifier);
        let single = Self {
            slots_to_id: mapping,
            source: source.clone(),
            table: Table::new(indexing_genesis_block, table_id, columns),
            contract_address: *contract_address,
            contract_extraction: ContractExtractionArgs {
                slot: StorageSlot::Simple(CONTRACT_SLOT),
            },
        };
        //let mapping = Self {
        //    contract_extraction: ContractExtractionArgs {
        //        slot: StorageSlot::Simple(CONTRACT_SLOT),
        //    },
        //    contract_address: *contract_address,
        //    source: TableSourceSlot::Mapping((
        //        MappingValuesExtractionArgs {
        //            slot: MAPPING_SLOT,
        //            mapping_keys: test_mapping_keys(),
        //        },
        //        Some(LengthExtractionArgs {
        //            slot: LENGTH_SLOT,
        //            value: LENGTH_VALUE,
        //        }),
        //    )),
        //};

        // Right now only single values. Moving to mapping values in subsequent PR
        //Ok(vec![single, mapping])
        Ok(vec![single])
    }

    pub async fn run<P: ProofStorage>(&mut self, ctx: &mut TestContext<P>) -> Result<()> {
        // Call the contract function to set the test data.
        // TODO: make it return an update for a full table, right now it's only for one row.
        // to make when we deal with mappings
        let table_row_update = self.init_contract_data(ctx).await;
        log::info!("Applying initial updates to contract done");

        // we first run the initial preprocessing and db creation.
        self.run_mpt_preprocessing(ctx).await?;
        // then we run the creation of our tree
        self.run_lagrange_preprocessing(ctx, vec![table_row_update])
            .await?;

        log::info!(
            "FIRST block {} finished proving. Moving on to update",
            ctx.block_number().await
        );

        let table_row_update = self.subsequent_contract_data(ctx, UpdateType::Rest).await;
        log::info!(
            "Applying follow up updates to contract done - now at block {}",
            ctx.block_number().await
        );
        // we first run the initial preprocessing and db creation.
        // NOTE: we don't show copy on write here - the fact of only reproving what has been
        // updated, as this is not new from v0.
        // TODO: implement copy on write mechanism for MPT
        self.run_mpt_preprocessing(ctx).await?;
        self.run_lagrange_preprocessing(ctx, vec![table_row_update])
            .await?;

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
        assert!(updates.len() == 1, "mappings are not implemented yet");
        let single_row_update = updates[0].clone();
        // apply the new cells to the trees
        // NOTE ONLY the rest of the cells, not including the secondary one !
        let update_cell_tree = self
            .table
            .apply_cells_update(single_row_update.updated_cells.clone())
            .expect("can not update cells tree");
        log::info!("Applied updates to cells tree");
        // find the all the cells, updated or not, including the secondary index because this is to
        // store in the row JSON description
        let row_cells = match single_row_update.is_init() {
            // initialization time = everything is "updated"
            true => single_row_update.full_collection(),
            false => {
                // fetch all the current cells, merge with the new modified ones
                let old_row = self
                    .table
                    .row
                    .fetch(&single_row_update.updated_cells.row_key);
                single_row_update.merge_with_old_row(old_row.cells)
            }
        };
        // prove the new cell tree and get the node row
        let row_payload = ctx
            .prove_cells_tree(&self.table, row_cells, update_cell_tree)
            .await;
        info!("Generated final CELLs tree proofs for single variables");
        // In the case of the scalars slots, there is a single node in the row tree.
        let rows = RowUpdate {
            init: single_row_update.is_init(),
            modified_rows: vec![Row {
                // TODO: this only considers the case where we handle a cells update but not a
                // secondary index value update
                k: single_row_update.updated_cells.row_key.clone(),
                payload: row_payload,
            }],
        };
        let updates = self.table.apply_row_update(rows)?;
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
        update: &UpdateSingleStorage,
    ) -> Result<()> {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());

        let contract = Simple::new(self.contract_address, &provider);
        update_contract_data(&contract, update).await;
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

    async fn subsequent_contract_data<P: ProofStorage>(
        &self,
        ctx: &mut TestContext<P>,
        u: UpdateType,
    ) -> TableRowUpdate {
        match self.source {
            TableSourceSlot::Mapping(_) => unimplemented!("yet"),
            TableSourceSlot::SingleValues(_) => {
                let old_table_values = self.current_table_row_values(ctx).await;
                let mut current_values = self
                    .current_single_values(ctx)
                    .await
                    .expect("can't get current values");
                match u {
                    UpdateType::Rest => {
                        current_values.s4 = Address::from_slice(&thread_rng().gen::<[u8; 20]>());
                    }
                    UpdateType::SecondaryIndex => {
                        // TODO: not yet fully implemented this part
                        current_values.s2 = U256::from_be_bytes(thread_rng().gen::<[u8; 32]>());
                        unimplemented!("not yet");
                    }
                };

                let contract_update = UpdateSingleStorage::Single(current_values);
                self.apply_update_to_contract(ctx, &contract_update)
                    .await
                    .unwrap();
                let new_table_values = self.current_table_row_values(ctx).await;
                old_table_values.compute_update(&new_table_values)
            }
        }
    }

    ///  1. get current table values
    ///  2. apply new update to contract
    ///  3. get new table values
    ///  4. compute the diff, i.e. the update to apply to the table and the trees
    async fn init_contract_data<P: ProofStorage>(
        &self,
        ctx: &mut TestContext<P>,
    ) -> TableRowUpdate {
        match self.source {
            TableSourceSlot::Mapping(_) => unimplemented!("yet"),
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
                self.apply_update_to_contract(ctx, &UpdateSingleStorage::Single(contract_update))
                    .await
                    .unwrap();
                let new_table_values = self.current_table_row_values(ctx).await;
                let update = old_table_values.compute_update(&new_table_values);
                assert!(
                    update.is_init(),
                    "initialization of the contract's table should be init"
                );
                update
            }
        }
    }

    //let mut rng = thread_rng();
    //for addr in MAPPING_ADDRESSES {
    //    let b = contract.setMapping(
    //        Address::from_str(addr).unwrap(),
    //        U256::from(rng.gen::<u64>()),
    //    );
    //    b.send().await.unwrap().watch().await.unwrap();
    //}

    //// addToArray(uint256 value)
    //for _ in 0..=LENGTH_VALUE {
    //    let b = contract.addToArray(U256::from(rng.gen::<u64>()));
    //    b.send().await.unwrap().watch().await.unwrap();
    //}
    //
    // construct a row of the table from the actual value in the contract by fetching from MPT
    async fn current_table_row_values<P: ProofStorage>(
        &self,
        ctx: &mut TestContext<P>,
    ) -> TableRowValues {
        let mut secondary_cell = None;
        let rest_cells = match self.source {
            TableSourceSlot::Mapping(_) => unimplemented!("to come"),
            TableSourceSlot::SingleValues(ref args) => {
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
                        secondary_cell = Some(SecondaryIndexCell::new(cell, 0));
                    } else {
                        rest_cells.push(cell);
                    }
                }
                rest_cells
            }
        };
        TableRowValues {
            current_cells: rest_cells,
            current_secondary: secondary_cell.unwrap(),
        }
    }
}

#[derive(Clone, Debug)]
enum UpdateSingleStorage {
    Single(SimpleSingleValue),
    // MAPPING ...
}

#[derive(Clone, Debug)]
pub struct SimpleSingleValue {
    pub(crate) s1: bool,
    pub(crate) s2: U256,
    pub(crate) s3: String,
    pub(crate) s4: Address,
}

// This function applies the update in _one_ transaction so that Anvil only moves by one block
// so we can test the "subsequent block"
async fn update_contract_data<T: Transport + Clone, P: Provider<T, N>, N: Network>(
    contract: &SimpleInstance<T, P, N>,
    update: &UpdateSingleStorage,
) {
    match update {
        UpdateSingleStorage::Single(ref single) => update_single_values(contract, single).await,
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

/// Convert the test mapping addresses to mapping keys.
fn test_mapping_keys() -> Vec<MappingKey> {
    MAPPING_ADDRESSES
        .iter()
        .map(|address| {
            let address = Address::from_str(address).unwrap();
            address.into_word().to_vec()
        })
        .collect()
}

enum UpdateType {
    SecondaryIndex,
    Rest,
}

/// Represents in a generic way the value present in a row from a table
/// TODO: add the first index in generic way as well for CSV
#[derive(Default, Clone, Debug, PartialEq, Eq)]
struct TableRowValues {
    // cells without the secondary index
    current_cells: Vec<Cell>,
    current_secondary: SecondaryIndexCell,
}

impl TableRowValues {
    // Compute the update from the current values and the new values
    fn compute_update(&self, new: &Self) -> TableRowUpdate {
        // this is initialization
        if self == &Self::default() {
            let cells_update = CellsUpdate {
                row_key: (&new.current_secondary).into(),
                updated_cells: new.current_cells.clone(),
                init: true,
            };
            return TableRowUpdate {
                updated_cells: cells_update,
                updated_secondary: Some(new.current_secondary.clone()),
            };
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
        assert!(
            self.current_secondary.cell().id == new.current_secondary.cell().id,
            "ids are different between updates?"
        );
        assert!(
            self.current_secondary.unique_index() == new.current_secondary.unique_index(),
            "computing update from different row"
        );
        let updated_secondary = match self.current_secondary.cell() != new.current_secondary.cell()
        {
            true => Some(new.current_secondary.clone()),
            // no update on the secondary index value
            false => None,
        };
        TableRowUpdate {
            updated_cells: CellsUpdate {
                // NOTE: here we MUST give the new row tree key because
                // (a) in case it didn't change, well, no problem
                // (b) in case it changed, we will actually have to "delete" the previous key
                // first, then "insert" the new row
                // TODO: add the previous one
                row_key: (&new.current_secondary).into(),
                updated_cells,
                init: false,
            },
            // TODO: not yet done the "delete then insert" mode
            updated_secondary,
        }
    }
}

#[derive(Clone, Debug)]
struct TableRowUpdate {
    // WITHOUT the secondary index value
    updated_cells: CellsUpdate,
    // TODO: in case of updated secondary, we must know the previous secondary value to "delete it"
    updated_secondary: Option<SecondaryIndexCell>,
    // NOTE: in ideal generic world, i.e. CSV, we would need to add primary here
}

impl TableRowUpdate {
    // Returns the full collection to be inserted in an "update" row from the previous cells
    // and the new updates contained in self
    fn merge_with_old_row(&self, previous: CellCollection) -> CellCollection {
        previous.replace_by(&self.full_collection())
    }
    fn full_collection(&self) -> CellCollection {
        let rest = self.updated_cells.updated_cells.clone();
        let secondary = self.updated_secondary.clone().unwrap_or_default();
        let mut full = vec![secondary.cell()];
        full.extend(rest);
        CellCollection(full)
    }
    fn is_init(&self) -> bool {
        self.updated_cells.init
    }
}
