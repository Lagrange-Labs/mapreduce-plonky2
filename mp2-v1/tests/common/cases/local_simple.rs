//! Test case for local Simple contract
//! Reference `test-contracts/src/Simple.sol` for the details of Simple contract.

use anyhow::{bail, Result};
use log::{debug, info};
use mp2_v1::values_extraction::{identifier_block_column, identifier_single_var_column};
use rand::{thread_rng, Rng};
use ryhope::{storage::RoEpochKvStorage, tree::TreeTopology};

use crate::common::{
    bindings::simple::Simple,
    celltree::Cell,
    index_tree::{IndexNode, IndexTreeKey, MerkleIndexTree},
    proof_storage::{BlockPrimaryIndex, ProofKey, ProofStorage},
    rowtree::{CellCollection, RowTreeKey},
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
    primitives::{Address, U256},
    providers::ProviderBuilder,
};
use mp2_common::{
    eth::{ProofQuery, StorageSlot},
    F,
};
use std::{collections::HashMap, str::FromStr};

/// Test slots for single values extraction
const SINGLE_SLOTS: [u8; 4] = [0, 1, 2, 3];
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

        let table_id = TableID::new(ctx.block_number().await, contract_address, &source.slots());
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
                    _ => Some(TableColumn {
                        identifier: identifier_single_var_column(*slot, contract_address),
                        index: IndexType::None,
                    }),
                })
                .collect::<Vec<_>>(),
        };
        // simply a mapping we need keep around to make sure we always give the right update to the
        // tree since it is not aware of the slots (this is blockchain specific info).
        let mut mapping = HashMap::default();
        mapping.insert(INDEX_SLOT, columns.secondary_column().identifier);
        for (i, slot) in SINGLE_SLOTS.iter().enumerate() {
            if *slot != INDEX_SLOT {
                // link the identifier to the slot
                mapping.insert(*slot, columns.rest[i].identifier);
            }
        }
        let single = Self {
            slots_to_id: mapping,
            source: source.clone(),
            table: Table::new(ctx.block_number().await, table_id, columns),
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

        // Right now only single values. Moving to values in subsequent PR
        //Ok(vec![single, mapping])
        Ok(vec![single])
    }

    pub async fn run<P: ProofStorage>(&mut self, ctx: &mut TestContext<P>) -> Result<()> {
        // Call the contract function to set the test data.
        let (contract_update, cells_update) = self.init_contract_data().await;
        self.apply_update_to_contract(ctx, &contract_update).await?;
        log::info!("Applying initial updates to contract done");

        // we first run the initial preprocessing and db creation.
        self.run_mpt_preprocessing(ctx).await?;
        // then we run the creation of our tree
        self.run_lagrange_preprocessing(ctx, vec![cells_update])
            .await?;

        log::info!("FIRST block {} finished proving. Moving on to update");

        let (contract_update, cells_update) =
            self.subsequent_contract_data(ctx, UpdateType::Rest).await;
        self.apply_update_to_contract(ctx, &contract_update).await?;
        log::info!("Applying follow up updates to contract done");
        // we first run the initial preprocessing and db creation.
        // NOTE: we don't show copy on write here - the fact of only reproving what has been
        // updated, as this is not new from v0.
        // TODO: implement copy on write mechanism for MPT
        self.run_mpt_preprocessing(ctx).await?;

        Ok(())
    }

    // separate function only dealing with preprocesisng MPT proofs
    // This function is "generic" as it can table a table description
    async fn run_lagrange_preprocessing<P: ProofStorage>(
        &mut self,
        ctx: &mut TestContext<P>,
        // cells we are modifying
        // Note there is only one entry for a single variable update, but multiple for mappings for
        // example
        updates: Vec<CellsUpdate>,
    ) -> Result<()> {
        assert!(updates.len() == 1, "mappings are not implemented yet");
        let updates = updates[0].clone();
        // apply the new cells to the trees
        let update_cell_tree = self
            .table
            .apply_cells_update(updates.clone())
            .expect("can not update cells tree");
        // find the all the cells, updated or not
        let all_cells = match updates.init {
            // in case it's init, then it's simply all the new cells
            true => CellCollection(updates.modified_cells.clone()),
            false => {
                // fetch all the current cells, merge with the new modified one
                let old_row = self.table.row.fetch(&updates.row_key);
                old_row
                    .cells
                    .replace_by(&CellCollection(updates.modified_cells))
            }
        };
        // prove the new cell tree and get the node row
        let row = ctx
            .prove_cells_tree(&self.table, all_cells, update_cell_tree)
            .await;
        info!("Generated final CELLs tree proofs for single variables");
        // In the case of the scalars slots, there is a single node in the row tree.
        let rows = RowUpdate {
            modified_rows: vec![row],
        };
        let updates = self.table.apply_row_update(rows)?;
        let index_node = ctx.prove_update_row_tree(&self.table, updates).await;
        info!("Generated final ROWs tree proofs for single variables");

        // NOTE the reason we separate and use block number as IndexTreeKey is because this index
        // could be different if we were using NOT block number. It should be the index of the
        // enumeration, something that may arise during the query when building a result tree.
        let index_update = IndexUpdate {
            added_index: (ctx.block_number().await as BlockPrimaryIndex, index_node),
        };
        let updates = self
            .table
            .apply_index_update(index_update)
            .expect("can't update index tree");
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

        info!("Generated Single Variables MPT preprocessing proofs");

        Ok(())
    }

    // Returns the table updated
    pub async fn apply_update_to_contract<P: ProofStorage>(
        &self,
        ctx: &TestContext<P>,
        update: &UpdateSingleStorage,
    ) -> Result<()> {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());

        let contract = Simple::new(self.contract_address, &provider);
        update_contract_data(&contract, &update).await;
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
        //) -> (UpdateSingleStorage, CellsUpdate) {
    ) -> (UpdateSingleStorage, CellsUpdate) {
        let mut current_values = self
            .current_single_values(ctx)
            .await
            .expect("can't get current values");
        let mut modified_cells = Vec::new();
        match u {
            UpdateType::Rest => {
                let s4_slot = 3;
                current_values.s4 = Address::from_slice(&thread_rng().gen::<[u8; 20]>());
                modified_cells.push(Cell {
                    id: self.slots_to_id.get(&s4_slot).cloned().unwrap_or_else(|| {
                        panic!("invalid slot ref {} on slot-id {:?}", 4, self.slots_to_id,)
                    }),
                    value: current_values.value_at_slot(4).unwrap(),
                    // we don't know yet its hash because the tree is not constructed
                    // this will be done by the Aggregate trait
                    // TODO: move that to a plonky2 agnostic hash
                    hash: Default::default(),
                });
            }
            UpdateType::SecondaryIndex => {
                current_values.s2 = U256::from_be_bytes(thread_rng().gen::<[u8; 32]>());
            }
        };
        let row_tree_key = RowTreeKey {
            value: current_values.s2,
            id: 0, // only one row with this value since it's a row tree for single variable
        };

        let contract_update = UpdateSingleStorage::Single(current_values);
        let table_update = CellsUpdate {
            init: false,
            row_key: row_tree_key,
            modified_cells,
        };
        (contract_update, table_update)
    }
    /// Defines the initial state of the contract, and thus initial state of our table as well
    async fn init_contract_data(&self) -> (UpdateSingleStorage, CellsUpdate) {
        let contract_update = SimpleSingleValue {
            s1: true,
            s2: U256::from(LENGTH_VALUE),
            s3: "test".to_string(),
            s4: Address::from_str("0xb90ed61bffed1df72f2ceebd965198ad57adfcbd").unwrap(),
        };
        let table_update = CellsUpdate {
            init: true,
            row_key: RowTreeKey {
                // s2 is the index in the formalism of this  single variable table
                value: contract_update.s2,
                // there is no other rows in this table for this block so the enumeration is simple
                id: 0,
            },
            // since we are proving the initial state of the contract, all the cells are modified
            // cells
            modified_cells: SINGLE_SLOTS
                .iter()
                .filter_map(|slot| {
                    // NOTE: we don't store the primary nor  secondary column in the cells tree, so we MUST skip it
                    if *slot == INDEX_SLOT {
                        return None;
                    }
                    Some(Cell {
                        id: self.slots_to_id.get(slot).cloned().unwrap_or_else(|| {
                            panic!(
                                "invalid slot ref {} on slot-id {:?}",
                                *slot, self.slots_to_id,
                            )
                        }),
                        // TODO: a bit hackyish way to store slots -> value update but that will do for
                        // now
                        value: contract_update.value_at_slot(*slot).unwrap(),
                        // we don't know yet its hash because the tree is not constructed
                        // this will be done by the Aggregate trait
                        // TODO: move that to a plonky2 agnostic hash
                        hash: Default::default(),
                    })
                })
                .collect(),
        };
        (UpdateSingleStorage::Single(contract_update), table_update)
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

impl SimpleSingleValue {
    pub fn value_at_slot(&self, slot_number: u8) -> Result<U256> {
        // just because the naming of the value start at 1 and slot number is at 0
        match slot_number + 1 {
            1 => Ok(U256::from(self.s1)),
            2 => Ok(self.s2),
            3 => Ok(U256::from_be_slice(self.s3.as_bytes())),
            // TODO:: is there a better way ?
            4 => Ok(U256::from_be_slice(self.s4.into_word().as_slice())),
            a => bail!("single contract only has 4 values while given {}", a),
        }
    }
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
