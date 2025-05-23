use std::{
    array,
    assert_matches::assert_matches,
    collections::{BTreeSet, HashMap},
    iter::once,
    marker::PhantomData,
    str::FromStr,
    sync::atomic::{AtomicU64, AtomicUsize},
};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, U256},
};
use anyhow::{bail, ensure, Result};
use futures::{future::BoxFuture, stream, FutureExt, StreamExt};
use itertools::Itertools;
use log::{debug, info};
use mp2_common::{
    eth::{ProofQuery, StorageSlot, StorageSlotNode},
    proof::ProofWithVK,
    types::HashOutput,
};
use mp2_v1::{
    api::{
        compute_table_info, merge_metadata_hash, metadata_hash, no_provable_metadata_hash,
        off_chain_data_commitment, SlotInput, SlotInputs, TableRow,
    },
    final_extraction::OffChainRootOfTrust,
    indexing::{
        block::BlockPrimaryIndex,
        cell::Cell,
        row::{RowTreeKey, RowTreeKeyNonce, ToNonce},
        ColumnID,
    },
    values_extraction::{
        gadgets::{column_gadget::extract_value, column_info::ColumnInfo},
        identifier_block_column, identifier_for_inner_mapping_key_column,
        identifier_for_mapping_key_column, identifier_for_outer_mapping_key_column,
        identifier_for_value_column, identifier_offchain_column, StorageSlotInfo,
    },
};
use plonky2::field::types::PrimeField64;
use rand::{
    distributions::{Alphanumeric, DistString},
    rngs::StdRng,
    thread_rng, Rng, SeedableRng,
};
use ryhope::{storage::RoEpochKvStorage, UserEpoch};
use serde::{Deserialize, Serialize};

use crate::common::{
    final_extraction::{
        ExtractionProofInput, ExtractionTableProof, MergeExtractionProof, OffChainExtractionProof,
    },
    proof_storage::{ProofKey, ProofStorage},
    rowtree::SecondaryIndexCell,
    table::{CellsUpdate, Table},
    TestContext, TEST_MAX_COLUMNS,
};

use super::{
    contract::{Contract, ContractController, MappingUpdate, SimpleSingleValues},
    indexing::{
        ChangeType, TableRowUpdate, TableRowValues, UpdateType, SINGLE_SLOTS, SINGLE_STRUCT_SLOT,
    },
    slot_info::{
        LargeStruct, MappingKey, MappingOfMappingsKey, StorageSlotMappingKey, StorageSlotValue,
    },
};

/// Save the columns information of same slot and EVM word.
#[derive(Debug)]
struct SlotEvmWordColumns(Vec<ColumnInfo>);

impl SlotEvmWordColumns {
    fn new(column_info: Vec<ColumnInfo>) -> Self {
        // Ensure the column information should have the same slot and EVM word.
        let slot = column_info[0].slot();
        let evm_word = column_info[0].evm_word();
        column_info[1..].iter().for_each(|col| {
            assert_eq!(col.slot(), slot);
            assert_eq!(col.evm_word(), evm_word);
        });

        Self(column_info)
    }
    fn slot(&self) -> u8 {
        // The columns should have the same slot.
        u8::try_from(self.0[0].slot().to_canonical_u64()).unwrap()
    }
    fn evm_word(&self) -> u32 {
        // The columns should have the same EVM word.
        u32::try_from(self.0[0].evm_word().to_canonical_u64()).unwrap()
    }
    fn column_info(&self) -> &[ColumnInfo] {
        &self.0
    }
}

/// What is the secondary index chosen for the table in the mapping.
/// Each entry contains the identifier of the column expected to store in our tree
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum MappingIndex {
    OuterKey(u64),
    InnerKey(u64),
    Value(u64),
    // This can happen if it is being part of a merge table and the secondary index is from the
    // other table
    None,
}

/// The key,value such that the combination is unique. This can be turned into a RowTreeKey.
/// to store in the row tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UniqueMappingEntry<K: StorageSlotMappingKey, V: StorageSlotValue> {
    key: K,
    value: V,
}

impl<K: StorageSlotMappingKey, V: StorageSlotValue> From<(K, V)> for UniqueMappingEntry<K, V> {
    fn from(pair: (K, V)) -> Self {
        Self {
            key: pair.0,
            value: pair.1,
        }
    }
}

impl<K: StorageSlotMappingKey, V: StorageSlotValue> UniqueMappingEntry<K, V> {
    pub fn new(key: K, value: V) -> Self {
        Self { key, value }
    }
    pub fn to_update(
        &self,
        block_number: BlockPrimaryIndex,
        contract: &Contract,
        mapping_index: &MappingIndex,
        slot_inputs: &[SlotInput],
        previous_row_key: Option<RowTreeKey>,
    ) -> (CellsUpdate<BlockPrimaryIndex>, SecondaryIndexCell) {
        let row_value = self.to_table_row_value(block_number, contract, mapping_index, slot_inputs);
        let cells_update = CellsUpdate {
            previous_row_key: previous_row_key.unwrap_or_default(),
            new_row_key: self.to_row_key(contract, mapping_index, slot_inputs),
            updated_cells: row_value.current_cells,
            primary: block_number,
        };
        let index_cell = row_value.current_secondary.unwrap_or_default();
        (cells_update, index_cell)
    }

    /// Return a row given this mapping entry, depending on the chosen index
    pub fn to_table_row_value(
        &self,
        primary: BlockPrimaryIndex,
        contract: &Contract,
        index: &MappingIndex,
        slot_inputs: &[SlotInput],
    ) -> TableRowValues<BlockPrimaryIndex> {
        let slot = slot_inputs[0].slot();
        // Ensure it's the same mapping slot.
        slot_inputs[1..]
            .iter()
            .for_each(|slot_input| assert_eq!(slot_input.slot(), slot));
        let [outer_key_cell, inner_key_cell] = match self.key.to_u256_vec().as_slice() {
            [mapping_key] => {
                let key_id = identifier_for_mapping_key_column(
                    slot,
                    &contract.address,
                    contract.chain_id,
                    vec![],
                );

                [Some(Cell::new(key_id, *mapping_key)), None]
            }
            [outer_key, inner_key] => {
                let outer_key_cell = {
                    let id = identifier_for_outer_mapping_key_column(
                        slot,
                        &contract.address,
                        contract.chain_id,
                        vec![],
                    );

                    Cell::new(id, *outer_key)
                };
                let inner_key_cell = {
                    let id = identifier_for_inner_mapping_key_column(
                        slot,
                        &contract.address,
                        contract.chain_id,
                        vec![],
                    );

                    Cell::new(id, *inner_key)
                };

                [Some(outer_key_cell), Some(inner_key_cell)]
            }
            _ => unreachable!(),
        };
        let mut current_cells = slot_inputs
            .iter()
            .zip_eq(self.value.to_u256_vec())
            .map(|(slot_input, field)| {
                let values_id = identifier_for_value_column(
                    slot_input,
                    &contract.address,
                    contract.chain_id,
                    vec![],
                );

                Cell::new(values_id, field)
            })
            .collect_vec();

        let secondary_cell = match index {
            MappingIndex::OuterKey(_) => {
                if let Some(cell) = inner_key_cell {
                    current_cells.push(cell);
                }

                outer_key_cell.unwrap()
            }
            MappingIndex::InnerKey(_) => {
                if let Some(cell) = outer_key_cell {
                    current_cells.push(cell);
                }

                inner_key_cell.unwrap()
            }
            MappingIndex::Value(secondary_value_id) => {
                let pos = current_cells
                    .iter()
                    .position(|c| &c.identifier() == secondary_value_id)
                    .unwrap();
                let secondary_cell = current_cells.remove(pos);

                [outer_key_cell, inner_key_cell]
                    .into_iter()
                    .for_each(|cell| {
                        if let Some(cell) = cell {
                            current_cells.push(cell);
                        }
                    });

                secondary_cell
            }
            MappingIndex::None => unreachable!(),
        };
        debug!(
            " --- MAPPING to row: secondary index {secondary_cell:?}  -- cells {current_cells:?}"
        );
        let current_secondary = Some(SecondaryIndexCell::new_from(secondary_cell, U256::from(0)));
        TableRowValues {
            current_cells,
            current_secondary,
            primary,
        }
    }

    pub fn to_row_key(
        &self,
        contract: &Contract,
        index: &MappingIndex,
        slot_inputs: &[SlotInput],
    ) -> RowTreeKey {
        let (row_key, rest) = match index {
            MappingIndex::OuterKey(_) => {
                // The mapping keys are unique for rows.
                let mapping_keys = self.key.to_u256_vec();
                let key = mapping_keys[0];
                let rest = mapping_keys.get(1).unwrap_or(&U256::ZERO).to_be_bytes_vec();

                (key, rest)
            }
            MappingIndex::InnerKey(_) => {
                // The mapping keys are unique for rows.
                let mapping_keys = self.key.to_u256_vec();
                let key = mapping_keys[1];
                let rest = mapping_keys[0].to_be_bytes_vec();

                (key, rest)
            }
            MappingIndex::Value(secondary_value_id) => {
                let pos = slot_inputs
                    .iter()
                    .position(|slot_input| {
                        &identifier_for_value_column(
                            slot_input,
                            &contract.address,
                            contract.chain_id,
                            vec![],
                        ) == secondary_value_id
                    })
                    .unwrap();
                let secondary_value = self.value.to_u256_vec().remove(pos);

                // The mapping key is unique for rows.
                let rest = self
                    .key
                    .to_u256_vec()
                    .into_iter()
                    .flat_map(|u| u.to_be_bytes_vec())
                    .collect_vec();

                (secondary_value, rest)
            }
            MappingIndex::None => unreachable!(),
        };

        RowTreeKey {
            value: row_key,
            rest: rest.to_nonce(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Hash, Clone, PartialEq, Eq)]
pub(crate) enum TableSource {
    /// Test arguments for simple slots which stores both single values and Struct values
    Single(SingleExtractionArgs),
    /// Test arguments for mapping slots which stores single values
    MappingValues(
        MappingExtractionArgs<MappingKey, Address>,
        Option<LengthExtractionArgs>,
    ),
    /// Test arguments for mapping slots which stores the Struct values
    MappingStruct(
        MappingExtractionArgs<MappingKey, LargeStruct>,
        Option<LengthExtractionArgs>,
    ),
    /// Test arguments for mapping of mappings slot which stores single values
    MappingOfSingleValueMappings(MappingExtractionArgs<MappingOfMappingsKey, U256>),
    /// Test arguments for mapping of mappings slot which stores the Struct values
    MappingOfStructMappings(MappingExtractionArgs<MappingOfMappingsKey, LargeStruct>),
    /// Test arguments for the merge source of both simple and mapping values
    Merge(MergeSource),
    OffChain(OffChainTableArgs),
}

impl TableSource {
    /// Return the provable data commitment flag to be provided as input for the IVC proof.
    /// The value of the flag depends on the type of the table
    pub fn provable_data_commitment_for_ivc(&self) -> bool {
        match self {
            TableSource::OffChain(off_chain_table_args) => {
                off_chain_table_args.provable_data_commitment
            }
            _ => false, // for all on-chain tables, we use block hash as root of trust, so this flag must
                        // always be false
        }
    }

    pub async fn generate_extraction_proof_inputs(
        &self,
        ctx: &mut TestContext,
        contract: &Option<Contract>,
        proof_key: ProofKey,
    ) -> Result<(ExtractionProofInput, HashOutput)> {
        match self {
            TableSource::Single(ref args) => {
                args.generate_extraction_proof_inputs(ctx, contract.as_ref().unwrap(), proof_key)
                    .await
            }
            TableSource::MappingValues(ref args, _) => {
                args.generate_extraction_proof_inputs(ctx, contract.as_ref().unwrap(), proof_key)
                    .await
            }
            TableSource::MappingStruct(ref args, _) => {
                args.generate_extraction_proof_inputs(ctx, contract.as_ref().unwrap(), proof_key)
                    .await
            }
            TableSource::MappingOfSingleValueMappings(ref args) => {
                args.generate_extraction_proof_inputs(ctx, contract.as_ref().unwrap(), proof_key)
                    .await
            }
            TableSource::MappingOfStructMappings(ref args) => {
                args.generate_extraction_proof_inputs(ctx, contract.as_ref().unwrap(), proof_key)
                    .await
            }
            TableSource::Merge(ref args) => {
                args.generate_extraction_proof_inputs(ctx, contract.as_ref().unwrap(), proof_key)
                    .await
            }
            TableSource::OffChain(ref off_chain) => {
                off_chain.generate_extraction_proof_inputs(ctx, proof_key)
            }
        }
    }

    #[allow(elided_named_lifetimes)]
    pub fn init_contract_data<'a>(
        &'a mut self,
        ctx: &'a mut TestContext,
        contract: &'a Contract,
    ) -> BoxFuture<Vec<TableRowUpdate<BlockPrimaryIndex>>> {
        async move {
            match self {
                TableSource::Single(ref mut args) => args.init_contract_data(ctx, contract).await,
                TableSource::MappingValues(ref mut args, _) => {
                    args.init_contract_data(ctx, contract).await
                }
                TableSource::MappingStruct(ref mut args, _) => {
                    args.init_contract_data(ctx, contract).await
                }
                TableSource::MappingOfSingleValueMappings(ref mut args) => {
                    args.init_contract_data(ctx, contract).await
                }
                TableSource::MappingOfStructMappings(ref mut args) => {
                    args.init_contract_data(ctx, contract).await
                }
                TableSource::Merge(ref mut args) => args.init_contract_data(ctx, contract).await,
                TableSource::OffChain(ref mut off_chain) => off_chain.init_data(),
            }
        }
        .boxed()
    }

    #[allow(elided_named_lifetimes)]
    pub fn random_contract_update<'a>(
        &'a mut self,
        ctx: &'a mut TestContext,
        contract: &'a Option<Contract>,
        change_type: ChangeType,
    ) -> BoxFuture<Vec<TableRowUpdate<BlockPrimaryIndex>>> {
        async move {
            match self {
                TableSource::Single(ref args) => {
                    args.random_contract_update(ctx, contract.as_ref().unwrap(), change_type)
                        .await
                }
                TableSource::MappingValues(ref mut args, _) => {
                    args.random_contract_update(ctx, contract.as_ref().unwrap(), change_type)
                        .await
                }
                TableSource::MappingStruct(ref mut args, _) => {
                    args.random_contract_update(ctx, contract.as_ref().unwrap(), change_type)
                        .await
                }
                TableSource::MappingOfSingleValueMappings(ref mut args) => {
                    args.random_contract_update(ctx, contract.as_ref().unwrap(), change_type)
                        .await
                }
                TableSource::MappingOfStructMappings(ref mut args) => {
                    args.random_contract_update(ctx, contract.as_ref().unwrap(), change_type)
                        .await
                }
                TableSource::Merge(ref mut args) => {
                    args.random_contract_update(ctx, contract.as_ref().unwrap(), change_type)
                        .await
                }
                TableSource::OffChain(ref mut off_chain) => off_chain.random_update(change_type),
            }
        }
        .boxed()
    }

    /// Get the latest epoch for the current source
    pub(crate) async fn latest_epoch(&self, ctx: &mut TestContext) -> BlockPrimaryIndex {
        match self {
            TableSource::OffChain(ref off_chain) => off_chain.last_update_epoch,
            _ => ctx.block_number().await as BlockPrimaryIndex,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Hash, Clone, PartialEq, Eq)]
pub struct MergeSource {
    // NOTE: this is a hardcore assumption currently that table_a is single and table_b is mapping for now
    // Extending to full merge between any table is not far - it requires some quick changes in
    // circuit but quite a lot of changes in integrated test.
    pub(crate) single: SingleExtractionArgs,
    pub(crate) mapping: MappingExtractionArgs<MappingKey, LargeStruct>,
}

impl MergeSource {
    pub fn new(
        single: SingleExtractionArgs,
        mapping: MappingExtractionArgs<MappingKey, LargeStruct>,
    ) -> Self {
        Self { single, mapping }
    }

    #[allow(elided_named_lifetimes)]
    pub fn generate_extraction_proof_inputs<'a>(
        &'a self,
        ctx: &'a mut TestContext,
        contract: &'a Contract,
        proof_key: ProofKey,
    ) -> BoxFuture<Result<(ExtractionProofInput, HashOutput)>> {
        async move {
            let ProofKey::ValueExtraction((id, bn)) = proof_key else {
                bail!("key wrong");
            };
            let id_a = id.clone() + "_a";
            let id_b = id + "_b";
            // generate the value extraction proof for the both table individually
            let (extract_single, _) = self
                .single
                .generate_extraction_proof_inputs(
                    ctx,
                    contract,
                    ProofKey::ValueExtraction((id_a, bn)),
                )
                .await?;
            let ExtractionProofInput::Single(extract_a) = extract_single else {
                bail!("can't merge non single tables")
            };
            let (extract_mappping, _) = self
                .mapping
                .generate_extraction_proof_inputs(
                    ctx,
                    contract,
                    ProofKey::ValueExtraction((id_b, bn)),
                )
                .await?;
            let ExtractionProofInput::Single(extract_b) = extract_mappping else {
                bail!("can't merge non single tables")
            };

            // add the metadata hashes together - this is mostly for debugging
            let md = merge_metadata_hash::<TEST_MAX_COLUMNS>(
                contract.address,
                contract.chain_id,
                vec![],
                SlotInputs::Simple(self.single.slot_inputs.clone()),
                SlotInputs::Mapping(self.mapping.slot_inputs.clone()),
            );
            assert!(extract_a != extract_b);
            Ok((
                ExtractionProofInput::Merge(MergeExtractionProof {
                    single: extract_a,
                    mapping: extract_b,
                }),
                md,
            ))
        }
        .boxed()
    }

    pub async fn init_contract_data(
        &mut self,
        ctx: &mut TestContext,
        contract: &Contract,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        // OK to call both sequentially since we only look a the block number after setting the
        // initial data
        let update_single = self.single.init_contract_data(ctx, contract).await;
        let update_mapping = self.mapping.init_contract_data(ctx, contract).await;
        // now we merge all the cells change from the single contract to the mapping contract
        update_mapping
            .into_iter()
            .flat_map(|um| {
                let refm = &um;
                // for each update from mapping, we "merge" all the updates from single, i.e. since
                // single is the multiplier table
                // NOTE: It assumes there is no secondary index on the single table right now.
                // NOTE: there should be only one update per block for single table. Here we just try
                // to make it a bit more general by saying each update of table a must be present for
                // all updates of table b
                update_single.iter().map(|us| match (refm, us) {
                    // We start by a few impossible methods
                    (_, TableRowUpdate::Deletion(_)) => panic!("no deletion on single table"),
                    (TableRowUpdate::Update(_), TableRowUpdate::Insertion(_, _)) => {
                        panic!("insertion on single only happens at genesis")
                    }
                    // WARNING: when a mapping row is deleted, it deletes the whole row even for single
                    // values
                    (TableRowUpdate::Deletion(ref d), _) => TableRowUpdate::Deletion(d.clone()),
                    // Regular update on both 
                    (TableRowUpdate::Update(ref update_a), TableRowUpdate::Update(update_b)) => {
                        let mut update_a = update_a.clone();
                        update_a.updated_cells.extend(update_b.updated_cells.iter().cloned());
                        TableRowUpdate::Update(update_a)
                    }
                    // a new mapping entry and and update in the single variable
                    (TableRowUpdate::Insertion(ref cells, sec), TableRowUpdate::Update(cellsb)) => {
                        let mut cells = cells.clone();
                        cells.updated_cells.extend(cellsb.updated_cells.iter().cloned());
                        TableRowUpdate::Insertion(cells, sec.clone())
                    }
                    // new case for both - likely genesis state
                    (
                        TableRowUpdate::Insertion(ref cella, seca),
                        TableRowUpdate::Insertion(cellb, secb),
                    ) => {
                        assert_eq!(*secb, SecondaryIndexCell::default(), "no secondary index on single supported at the moment in integrated test");
                        let mut cella = cella.clone();
                        cella.updated_cells.extend(cellb.updated_cells.iter().cloned());
                        TableRowUpdate::Insertion(cella,seca.clone())
                    }
                }).collect_vec()
            })
            .collect()
    }

    pub async fn random_contract_update(
        &mut self,
        ctx: &mut TestContext,
        contract: &Contract,
        c: ChangeType,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        // alternate between table a update or table b
        // TODO: implement mixed update
        match rotate() {
            // SINGLE UPDATE only part. Can only do it if change type is not insertion or deletion since we
            // can't insert a new row for single variables, there's only one... and we can't delete
            // it either then.
            // for single updates, we need to apply this update to all the mapping entries, that's
            // the "multiplier" part.
            0 if !matches!(c, ChangeType::Insertion) && !matches!(c, ChangeType::Deletion) => {
                let single_updates = self.single.random_contract_update(ctx, contract, c).await;
                let rsu = &single_updates;
                let bn = ctx.block_number().await;
                // we fetch the value of all mapping entries, and
                let mut all_updates = Vec::new();
                for mk in &self.mapping.mapping_keys {
                    let current_value = self.mapping.query_value(ctx, contract, mk).await;
                    let current_key = *mk;
                    let entry = UniqueMappingEntry::new(current_key, current_value);
                    // create one update for each update of the first table (note again there
                    // should be only one update since it's single var)
                    all_updates.extend(rsu.iter().map(|s| {
                        let TableRowUpdate::Update(su) = s else {
                            panic!("can't have anything else than update for single table");
                        };
                        TableRowUpdate::Update(CellsUpdate {
                            // the row key doesn't change since the mapping value doesn't change
                            previous_row_key: entry.to_row_key(
                                contract,
                                &self.mapping.index,
                                &self.mapping.slot_inputs,
                            ),
                            new_row_key: entry.to_row_key(
                                contract,
                                &self.mapping.index,
                                &self.mapping.slot_inputs,
                            ),
                            // only insert the new cells from the single update
                            updated_cells: su.updated_cells.clone(),
                            primary: bn as BlockPrimaryIndex,
                        })
                    }));
                }
                all_updates
            }
            // For mappings, it is the same, we need to append all the single cells to the mapping
            // cells for each new update
            _ => {
                let mapping_updates = self.mapping.random_contract_update(ctx, contract, c).await;
                // get the current single cells by emulating as if it's the first time we see them
                let single_values = self.single.current_table_row_values(ctx, contract).await;
                // since we know there is only a single row for the single case...
                let vec_update = TableRowValues::default().compute_update(&single_values[0]);
                let TableRowUpdate::Insertion(single_cells, _) = vec_update[0].clone() else {
                    panic!("can't re-create cells of single variable");
                };
                mapping_updates
                    .into_iter()
                    .map(|row_update| {
                        match row_update {
                            // nothing else to do for deletion
                            TableRowUpdate::Deletion(k) => TableRowUpdate::Deletion(k),
                            // NOTE: nothing else to do for update as well since we know the
                            // update comes from the mapping, so single didn't change, so no need
                            // to add anything.
                            TableRowUpdate::Update(c) => TableRowUpdate::Update(c),
                            // add the single cells to the new row
                            TableRowUpdate::Insertion(mut cells, sec) => {
                                cells
                                    .updated_cells
                                    .extend(single_cells.updated_cells.clone());
                                TableRowUpdate::Insertion(cells, sec)
                            }
                        }
                    })
                    .collect_vec()
            }
        }
    }
}

/// Length extraction arguments (C.2)
#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone)]
pub(crate) struct LengthExtractionArgs {
    /// Length slot
    pub(crate) slot: u8,
    /// Length value
    pub(crate) value: u8,
}

/// Contract extraction arguments (C.3)
#[derive(Debug)]
pub(crate) struct ContractExtractionArgs {
    /// Storage slot
    pub(crate) slot: StorageSlot,
}

static SHIFT: AtomicU64 = AtomicU64::new(0);
static ROTATOR: AtomicUsize = AtomicUsize::new(0);

use lazy_static::lazy_static;
lazy_static! {
    pub(crate) static ref BASE_VALUE: U256 = U256::from(10);
    pub static ref DEFAULT_ADDRESS: Address =
        Address::from_str("0xBA401cdAc1A3B6AEede21c9C4A483bE6c29F88C4").unwrap();
}

// can only be either 0 or 1
pub fn rotate() -> usize {
    ROTATOR.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 2
}
pub fn next_address() -> Address {
    let shift = SHIFT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(shift);
    let slice = rng.gen::<[u8; 20]>();
    Address::from_slice(&slice)
}

/// Extraction arguments for simple slots which stores both single values (Address or U256) and
/// Struct values (LargeStruct for testing)
#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone)]
pub(crate) struct SingleExtractionArgs {
    /// The index of below slot input vector to identify which is the secondardy index column
    pub(crate) secondary_index: Option<usize>,
    /// Slot inputs for this table
    pub(crate) slot_inputs: Vec<SlotInput>,
}

// This implementation includes the common function for extraction arguments of simple slots.
impl SingleExtractionArgs {
    pub(crate) fn new(secondary_index: Option<usize>, slot_inputs: Vec<SlotInput>) -> Self {
        Self {
            secondary_index,
            slot_inputs,
        }
    }

    pub(crate) fn secondary_index_slot_input(&self) -> Option<SlotInput> {
        self.secondary_index
            .map(|idx| self.slot_inputs[idx].clone())
    }

    pub(crate) fn rest_column_slot_inputs(&self) -> Vec<SlotInput> {
        let mut slot_inputs = self.slot_inputs.clone();
        if let Some(idx) = self.secondary_index {
            slot_inputs.remove(idx);
        }

        slot_inputs
    }

    async fn generate_extraction_proof_inputs(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
        proof_key: ProofKey,
    ) -> Result<(ExtractionProofInput, HashOutput)> {
        let ProofKey::ValueExtraction((_, bn)) = proof_key.clone() else {
            bail!("Invalid proof key");
        };
        let value_proof = match ctx.storage.get_proof_exact(&proof_key) {
            Ok(p) => p,
            Err(_) => {
                let storage_slot_info = self.storage_slot_info(contract);
                let root_proof = ctx
                    .prove_values_extraction(
                        &contract.address,
                        BlockNumberOrTag::Number(bn as u64),
                        &storage_slot_info,
                    )
                    .await;
                ctx.storage.store_proof(proof_key, root_proof.clone())?;
                info!("Generated extraction proof for simple slots");
                {
                    let pproof = ProofWithVK::deserialize(&root_proof).unwrap();
                    let pi =
                        mp2_v1::values_extraction::PublicInputs::new(&pproof.proof().public_inputs);
                    debug!(
                        "[--] SINGLE FINAL MPT DIGEST VALUE --> {:?} ",
                        pi.values_digest()
                    );
                    debug!(
                        "[--] SINGLE FINAL ROOT HASH --> {:?} ",
                        hex::encode(
                            pi.root_hash()
                                .into_iter()
                                .flat_map(|u| u.to_be_bytes())
                                .collect_vec(),
                        )
                    );
                }

                root_proof
            }
        };
        let slot_inputs = SlotInputs::Simple(self.slot_inputs.clone());
        let metadata_hash = metadata_hash::<TEST_MAX_COLUMNS>(
            slot_inputs,
            &contract.address,
            contract.chain_id,
            vec![],
        );
        let input = ExtractionProofInput::Single(ExtractionTableProof {
            value_proof,
            length_proof: None,
        });
        Ok((input, metadata_hash))
    }

    async fn current_table_row_values(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
    ) -> Vec<TableRowValues<BlockPrimaryIndex>> {
        let mut secondary_cell = None;
        let mut rest_cells = Vec::new();
        let secondary_id = self.secondary_index_identifier(contract);
        let evm_word_cols = self.evm_word_column_info(contract);
        let storage_slots = self.storage_slots(&evm_word_cols);
        for (evm_word_col, storage_slot) in evm_word_cols.into_iter().zip(storage_slots) {
            let query = ProofQuery::new(contract.address, storage_slot);
            let value = ctx
                .query_mpt_proof(&query, BlockNumberOrTag::Number(ctx.block_number().await))
                .await
                .storage_proof[0]
                .value;
            let value_bytes = value.to_be_bytes();
            evm_word_col.column_info().iter().for_each(|col_info| {
                let extracted_value = extract_value(&value_bytes, col_info);
                let extracted_value = U256::from_be_bytes(extracted_value);
                let id = col_info.identifier().to_canonical_u64();
                let cell = Cell::new(col_info.identifier().to_canonical_u64(), extracted_value);
                if Some(id) == secondary_id {
                    assert!(secondary_cell.is_none());
                    secondary_cell = Some(SecondaryIndexCell::new_from(cell, 0));
                } else {
                    rest_cells.push(cell);
                }
            });
        }
        vec![TableRowValues {
            current_cells: rest_cells,
            current_secondary: secondary_cell,
            primary: ctx.block_number().await as BlockPrimaryIndex,
        }]
    }

    fn secondary_index_identifier(&self, contract: &Contract) -> Option<u64> {
        self.secondary_index_slot_input().map(|slot_input| {
            identifier_for_value_column(&slot_input, &contract.address, contract.chain_id, vec![])
        })
    }

    fn table_info(&self, contract: &Contract) -> Vec<ColumnInfo> {
        table_info(contract, self.slot_inputs.clone())
    }

    fn evm_word_column_info(&self, contract: &Contract) -> Vec<SlotEvmWordColumns> {
        let table_info = table_info(contract, self.slot_inputs.clone());
        evm_word_column_info(&table_info)
    }

    fn storage_slots(&self, evm_word_cols: &[SlotEvmWordColumns]) -> Vec<StorageSlot> {
        evm_word_cols
            .iter()
            .map(|evm_word_col| {
                // The slot number and EVM word of extracted columns are same in the metadata.
                let slot = evm_word_col.slot();
                let evm_word = evm_word_col.evm_word();
                // We could assume it's a single value slot if the EVM word is 0, even if it's the
                // first field of a Struct. Since the computed slot location is same either it's
                // considered as a single value slot or the first field of a Struct slot.
                let storage_slot = StorageSlot::Simple(slot as usize);
                if evm_word == 0 {
                    storage_slot
                } else {
                    StorageSlot::Node(StorageSlotNode::new_struct(storage_slot, evm_word))
                }
            })
            .collect()
    }

    fn storage_slot_info(&self, contract: &Contract) -> Vec<StorageSlotInfo> {
        let table_info = self.table_info(contract);
        self.storage_slots(&self.evm_word_column_info(contract))
            .into_iter()
            .map(|storage_slot| StorageSlotInfo::new(storage_slot, table_info.clone()))
            .collect()
    }
}

// This implementation includes the functions only used for testing. Since we need to
// generate random data and interact with a specific contract.
impl SingleExtractionArgs {
    pub async fn init_contract_data(
        &mut self,
        ctx: &mut TestContext,
        contract: &Contract,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        // Generate a Rng with Send.
        let rng = &mut StdRng::from_entropy();
        let single_values = SimpleSingleValues {
            s1: rng.gen(),
            s2: U256::from_limbs(rng.gen()),
            s3: Alphanumeric.sample_string(rng, 10),
            s4: next_address(),
        };
        single_values.update_contract(ctx, contract).await;
        let single_struct = LargeStruct {
            field1: U256::from_limbs(rng.gen()),
            field2: rng.gen(),
            field3: rng.gen(),
        };
        single_struct.update_contract(ctx, contract).await;

        // Since the table is not created yet, we are giving an empty table row. When making the
        // diff with the new updated contract storage, the logic will detect it's an initialization
        // phase.
        let old_table_values = TableRowValues::default();
        let new_table_values = self.current_table_row_values(ctx, contract).await;
        assert_eq!(
            new_table_values.len(),
            1,
            "Single variable case should only have one row",
        );
        let updates = old_table_values.compute_update(&new_table_values[0]);
        assert_eq!(updates.len(), 1);
        assert_matches!(
            updates[0],
            TableRowUpdate::Insertion(_, _),
            "Initialization of the contract's table should be init"
        );

        updates
    }

    pub async fn random_contract_update(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
        change_type: ChangeType,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        let old_table_values = self.current_table_row_values(ctx, contract).await;
        // We can take the first one since we're asking for single value and there is only one row.
        let old_table_values = &old_table_values[0];
        match change_type {
            ChangeType::Silent => {}
            ChangeType::Insertion => {
                panic!("Can't add a new row for blockchain data over single values")
            }
            ChangeType::Deletion => {
                panic!("Can't remove a single row from blockchain data over single values")
            }
            ChangeType::Update(update) => {
                let index_slot_input = self.secondary_index_slot_input();
                match update {
                    UpdateType::Rest => {
                        let index_slot = index_slot_input.map(|slot_input| slot_input.slot());
                        if index_slot == Some(SINGLE_STRUCT_SLOT as u8) {
                            // Update the single value slots as `Rest` if single Struct slot is the index.
                            let mut current_values =
                                SimpleSingleValues::current_values(ctx, contract).await;
                            current_values.s4 = next_address();
                            current_values.update_contract(ctx, contract).await;
                        } else {
                            // Update the single Struct slot as `Rest` if one of single value slots is the index.
                            let mut current_struct =
                                LargeStruct::current_values(ctx, contract).await;
                            current_struct.field2 += 1;
                            current_struct.update_contract(ctx, contract).await;
                        }
                    }
                    UpdateType::SecondaryIndex => {
                        if let Some(index_slot_input) = index_slot_input {
                            let slot = index_slot_input.slot();
                            let rng = &mut StdRng::from_entropy();
                            if slot == SINGLE_STRUCT_SLOT as u8 {
                                let mut current_struct =
                                    LargeStruct::current_values(ctx, contract).await;
                                // We only update the secondary index value here.
                                current_struct.random_update(&index_slot_input);
                                current_struct.update_contract(ctx, contract).await;
                            } else {
                                let mut current_values =
                                    SimpleSingleValues::current_values(ctx, contract).await;
                                if slot == SINGLE_SLOTS[0] {
                                    current_values.s1 = !current_values.s1;
                                } else if slot == SINGLE_SLOTS[1] {
                                    current_values.s2 += U256::from(1);
                                } else if slot == SINGLE_SLOTS[2] {
                                    current_values.s3 = Alphanumeric.sample_string(rng, 10);
                                } else if slot == SINGLE_SLOTS[3] {
                                    current_values.s4 = next_address();
                                } else {
                                    panic!("Wrong slot number");
                                }
                                current_values.update_contract(ctx, contract).await;
                            }
                        }
                    }
                }
            }
        };

        let new_table_values = self.current_table_row_values(ctx, contract).await;
        assert_eq!(
            new_table_values.len(),
            1,
            "Single variable case should only have one row",
        );
        old_table_values.compute_update(&new_table_values[0])
    }
}

/// Mapping extraction arguments
#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone)]
pub(crate) struct MappingExtractionArgs<K: StorageSlotMappingKey, V: StorageSlotValue> {
    /// Mapping slot number
    slot: u8,
    /// Mapping index type
    index: MappingIndex,
    /// Slot input information
    slot_inputs: Vec<SlotInput>,
    /// Mapping keys: they are useful for two things:
    ///     * doing some controlled changes on the smart contract, since if we want to do an update we
    /// need to know an existing key
    ///     * doing the MPT proofs over, since this test doesn't implement the copy on write for MPT
    /// (yet), we're just recomputing all the proofs at every block and we need the keys for that.
    mapping_keys: BTreeSet<K>,
    /// Phantom
    _phantom: PhantomData<(K, V)>,
}

impl<K, V> MappingExtractionArgs<K, V>
where
    K: StorageSlotMappingKey,
    V: StorageSlotValue,
    Vec<MappingUpdate<K, V>>: ContractController,
{
    pub fn new(slot: u8, index: MappingIndex, slot_inputs: Vec<SlotInput>) -> Self {
        Self {
            slot,
            index,
            slot_inputs,
            mapping_keys: BTreeSet::new(),
            _phantom: Default::default(),
        }
    }

    pub fn slot_inputs(&self) -> &[SlotInput] {
        &self.slot_inputs
    }

    pub async fn init_contract_data(
        &mut self,
        ctx: &mut TestContext,
        contract: &Contract,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        let init_key_and_value: [_; 3] = array::from_fn(|_| (K::sample_key(), V::sample_value()));
        // Save the mapping keys.
        self.mapping_keys
            .extend(init_key_and_value.iter().map(|u| u.0.clone()).collect_vec());
        let updates = init_key_and_value
            .into_iter()
            .map(|(key, value)| MappingUpdate::Insertion(key, value))
            .collect_vec();

        updates.update_contract(ctx, contract).await;

        let new_block_number = ctx.block_number().await as BlockPrimaryIndex;
        self.mapping_to_table_update(new_block_number, contract, &updates)
    }

    async fn random_contract_update(
        &mut self,
        ctx: &mut TestContext,
        contract: &Contract,
        c: ChangeType,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        // NOTE 1: The first part is just trying to construct the right input to simulate any
        // changes on a mapping. This is mostly irrelevant for dist system but needs to manually
        // construct our test cases here. The second part is more interesting as it looks at
        // "what to do when receiving an update from scrapper". The core of the function is in
        // `mapping_to_table_update`
        //
        // NOTE 2: This implementation tries to emulate as much as possible what happens in dist
        // system. To compute the set of updates, it first simulate an update on the contract
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
        let current_key = self.mapping_keys.first().unwrap();
        let current_value = self.query_value(ctx, contract, current_key).await;
        let new_key = K::sample_key();
        let updates = match c {
            ChangeType::Silent => vec![],
            ChangeType::Insertion => {
                vec![MappingUpdate::Insertion(new_key, V::sample_value())]
            }
            ChangeType::Deletion => {
                vec![MappingUpdate::Deletion(current_key.clone(), current_value)]
            }
            ChangeType::Update(u) => {
                match u {
                    UpdateType::Rest => {
                        let new_value = V::sample_value();
                        match self.index {
                            MappingIndex::OuterKey(_) | MappingIndex::InnerKey(_) => {
                                // we simply change the mapping value since the key is the secondary index
                                vec![MappingUpdate::Update(
                                    current_key.clone(),
                                    current_value,
                                    new_value,
                                )]
                            }
                            MappingIndex::Value(_) => {
                                // TRICKY: in this case, the mapping key must change. But from the
                                // onchain perspective, it means a transfer mapping(old_key -> new_key,value)
                                vec![
                                    MappingUpdate::Deletion(
                                        current_key.clone(),
                                        current_value.clone(),
                                    ),
                                    MappingUpdate::Insertion(new_key, current_value),
                                ]
                            }
                            MappingIndex::None => {
                                // a random update of the mapping, we don't care which since it is
                                // not impacting the secondary index of the table since the mapping
                                // doesn't contain the column which is the secondary index, in case
                                // of the merge table case.
                                vec![MappingUpdate::Update(
                                    current_key.clone(),
                                    current_value,
                                    new_value,
                                )]
                            }
                        }
                    }
                    UpdateType::SecondaryIndex => {
                        match self.index {
                            MappingIndex::OuterKey(_) | MappingIndex::InnerKey(_) => {
                                // TRICKY: if the mapping key changes, it's a deletion then
                                // insertion from onchain perspective
                                vec![
                                    MappingUpdate::Deletion(
                                        current_key.clone(),
                                        current_value.clone(),
                                    ),
                                    // we insert the same value but with a new mapping key
                                    MappingUpdate::Insertion(new_key, current_value),
                                ]
                            }
                            MappingIndex::Value(secondary_value_id) => {
                                // We only update the second index value here.
                                let slot_input_to_update = self
                                    .slot_inputs
                                    .iter()
                                    .find(|slot_input| {
                                        identifier_for_value_column(
                                            slot_input,
                                            &contract.address,
                                            contract.chain_id,
                                            vec![],
                                        ) == secondary_value_id
                                    })
                                    .unwrap();
                                let mut new_value = current_value.clone();
                                new_value.random_update(slot_input_to_update);
                                // if the value changes, it's a simple update in mapping
                                vec![MappingUpdate::Update(
                                    current_key.clone(),
                                    current_value,
                                    new_value,
                                )]
                            }
                            MappingIndex::None => {
                                // empty vec since this table has no secondary index so it should
                                // give no updates
                                vec![]
                            }
                        }
                    }
                }
            }
        };
        // small iteration to always have a good updated list of mapping keys
        for update in &updates {
            match update {
                MappingUpdate::Deletion(key_to_delete, _) => {
                    info!("Removing key {key_to_delete:?} from tracking mapping keys");
                    self.mapping_keys.retain(|u| u != key_to_delete);
                }
                MappingUpdate::Insertion(key_to_insert, _) => {
                    info!("Inserting key {key_to_insert:?} to tracking mapping keys");
                    self.mapping_keys.insert(key_to_insert.clone());
                }
                // the mapping key doesn't change here so no need to update the list
                MappingUpdate::Update(_, _, _) => {}
            }
        }
        updates.update_contract(ctx, contract).await;

        let new_block_number = ctx.block_number().await as BlockPrimaryIndex;
        // NOTE HERE is the interesting bit for dist system as this is the logic to execute
        // on receiving updates from scapper. This only needs to have the relevant
        // information from update and it will translate that to changes in the tree.
        self.mapping_to_table_update(new_block_number, contract, &updates)
    }

    pub async fn generate_extraction_proof_inputs(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
        proof_key: ProofKey,
    ) -> Result<(ExtractionProofInput, HashOutput)> {
        let ProofKey::ValueExtraction((_, bn)) = proof_key.clone() else {
            bail!("invalid proof key");
        };
        let mapping_root_proof = match ctx.storage.get_proof_exact(&proof_key) {
            Ok(p) => p,
            Err(_) => {
                let storage_slot_info = self.all_storage_slot_info(contract);
                let mapping_values_proof = ctx
                    .prove_values_extraction(
                        &contract.address,
                        BlockNumberOrTag::Number(bn as u64),
                        &storage_slot_info,
                    )
                    .await;
                ctx.storage
                    .store_proof(proof_key, mapping_values_proof.clone())?;
                info!("Generated Values Extraction proof for mapping slot");
                {
                    let pproof = ProofWithVK::deserialize(&mapping_values_proof).unwrap();
                    let pi =
                        mp2_v1::values_extraction::PublicInputs::new(&pproof.proof().public_inputs);
                    debug!(
                        "[--] MAPPING FINAL MPT DIGEST VALUE --> {:?} ",
                        pi.values_digest()
                    );
                    debug!(
                        "[--] MAPPING FINAL ROOT HASH --> {:?} ",
                        hex::encode(
                            pi.root_hash()
                                .into_iter()
                                .flat_map(|u| u.to_be_bytes())
                                .collect_vec()
                        )
                    );
                }
                mapping_values_proof
            }
        };
        let metadata_hash = metadata_hash::<TEST_MAX_COLUMNS>(
            K::slot_inputs(self.slot_inputs.clone()),
            &contract.address,
            contract.chain_id,
            vec![],
        );
        // it's a compoound value type of proof since we're not using the length
        let input = ExtractionProofInput::Single(ExtractionTableProof {
            value_proof: mapping_root_proof,
            length_proof: None,
        });
        Ok((input, metadata_hash))
    }

    /// The generic parameter `V` could be set to an Uint256 as single value or a Struct.
    pub fn mapping_to_table_update(
        &self,
        block_number: BlockPrimaryIndex,
        contract: &Contract,
        updates: &[MappingUpdate<K, V>],
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        updates
            .iter()
            .flat_map(|update| {
                match update {
                    MappingUpdate::Insertion(key, value) => {
                        // we transform the mapping entry into the "table notion" of row
                        let entry = UniqueMappingEntry::new(key.clone(), value.clone());
                        let (cells, index) = entry.to_update(
                            block_number,
                            contract,
                            &self.index,
                            &self.slot_inputs,
                            None,
                        );
                        debug!(
                            "Insert mapping cells: secondary_index = {:?}, update_cell_len = {}",
                            index,
                            cells.updated_cells.len()
                        );
                        vec![TableRowUpdate::Insertion(cells, index)]
                    }
                    MappingUpdate::Deletion(key, value) => {
                        // find the associated row key tree to that value
                        // HERE: there are multiple possibilities:
                        // * search for the entry at the previous block instead
                        // * passing inside the deletion the value deleted as well, so we can
                        // reconstruct the row key
                        // * or have this extra list of mapping keys
                        let entry = UniqueMappingEntry::new(key.clone(), value.clone());
                        vec![TableRowUpdate::Deletion(entry.to_row_key(
                            contract,
                            &self.index,
                            &self.slot_inputs,
                        ))]
                    }
                    MappingUpdate::Update(key, old_value, new_value) => {
                        // NOTE: we need here to (a) delete current row and (b) insert new row
                        // Regardless of the change if it's on the mapping key or value, since a
                        // row is uniquely identified by its pair (key,value) then if one of those
                        // change, that means the row tree key needs to change as well, i.e. it's a
                        // deletion and addition.
                        let previous_entry =
                            UniqueMappingEntry::new(key.clone(), old_value.clone());
                        let previous_row_key =
                            previous_entry.to_row_key(contract, &self.index, &self.slot_inputs);
                        let new_entry = UniqueMappingEntry::new(key.clone(), new_value.clone());

                        let (mut cells, mut secondary_index) = new_entry.to_update(
                            block_number,
                            contract,
                            &self.index,
                            &self.slot_inputs,
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
                        match self.index {
                            MappingIndex::OuterKey(_) | MappingIndex::InnerKey(_) => {
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
                            MappingIndex::None => {
                                secondary_index = Default::default();
                            }
                        };
                        vec![
                            TableRowUpdate::Deletion(previous_row_key),
                            TableRowUpdate::Insertion(cells, secondary_index),
                        ]
                    }
                }
            })
            .collect_vec()
    }

    /// Construct a storage slot info by metadata and a mapping key.
    fn storage_slot_info(
        &self,
        evm_word: u32,
        table_info: Vec<ColumnInfo>,
        mapping_key: &K,
    ) -> StorageSlotInfo {
        let storage_slot = mapping_key.storage_slot(self.slot, evm_word);

        StorageSlotInfo::new(storage_slot, table_info)
    }

    /// Construct the storage slot info by the all mapping keys.
    fn all_storage_slot_info(&self, contract: &Contract) -> Vec<StorageSlotInfo> {
        let table_info = self.table_info(contract);
        let evm_word_cols = self.evm_word_column_info(contract);
        evm_word_cols
            .iter()
            .cartesian_product(self.mapping_keys.iter())
            .map(|(evm_word_col, mapping_key)| {
                self.storage_slot_info(evm_word_col.evm_word(), table_info.clone(), mapping_key)
            })
            .collect()
    }

    /// Query a storage slot value by a mapping key.
    async fn query_value(&self, ctx: &mut TestContext, contract: &Contract, mapping_key: &K) -> V {
        let mut extracted_values = vec![];
        let evm_word_cols = self.evm_word_column_info(contract);
        for evm_word_col in evm_word_cols {
            let storage_slot = mapping_key.storage_slot(self.slot, evm_word_col.evm_word());
            let query = ProofQuery::new(contract.address, storage_slot);
            let value = ctx
                .query_mpt_proof(&query, BlockNumberOrTag::Number(ctx.block_number().await))
                .await
                .storage_proof[0]
                .value;

            let value_bytes = value.to_be_bytes();
            evm_word_col.column_info().iter().for_each(|col_info| {
                let bytes = extract_value(&value_bytes, col_info);
                let value = U256::from_be_bytes(bytes);
                debug!("Mapping extract value: column: {col_info:?}, value = {value}");

                extracted_values.push(value);
            });
        }

        V::from_u256_slice(&extracted_values)
    }

    fn table_info(&self, contract: &Contract) -> Vec<ColumnInfo> {
        table_info(contract, self.slot_inputs.clone())
    }

    fn evm_word_column_info(&self, contract: &Contract) -> Vec<SlotEvmWordColumns> {
        let table_info = self.table_info(contract);
        evm_word_column_info(&table_info)
    }
}

/// Contruct the table information by the contract and slot inputs.
fn table_info(contract: &Contract, slot_inputs: Vec<SlotInput>) -> Vec<ColumnInfo> {
    compute_table_info(slot_inputs, &contract.address, contract.chain_id, vec![])
}

/// Construct the column information for each slot and EVM word.
fn evm_word_column_info(table_info: &[ColumnInfo]) -> Vec<SlotEvmWordColumns> {
    // Initialize a mapping of `(slot, evm_word) -> column_Identifier`.
    let mut column_info_map = HashMap::new();
    table_info.iter().for_each(|col| {
        column_info_map
            .entry((col.slot(), col.evm_word()))
            .and_modify(|cols: &mut Vec<_>| cols.push(col.clone()))
            .or_insert(vec![col.clone()]);
    });

    column_info_map
        .values()
        .cloned()
        .map(SlotEvmWordColumns::new)
        // This sort is used for the storage slot Struct extraction (in generic),
        // since we need to collect the Struct field in the right order.
        .sorted_by_key(|info| info.evm_word())
        .collect()
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Hash)]
pub(crate) struct OffChainTableArgs {
    pub(crate) table_name: String,
    pub(crate) secondary_index_column: ColumnMetadata,
    pub(crate) non_indexed_columns: Vec<ColumnMetadata>,
    // values found in each row of the table
    pub(crate) row_values: Vec<TableRowValues<BlockPrimaryIndex>>,
    // Last epoch where `row_values` were updated
    pub(crate) last_update_epoch: BlockPrimaryIndex,
    /// Boolean flag specifying whether the table is using as root ot trust
    /// a provable commitment
    pub(crate) provable_data_commitment: bool,
}

#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone)]
/// Data structure employed to specify information a column of an off-chain table
pub(crate) enum ColumnMetadata {
    /// Name for a column which is part of the primary key of the table. Note that the
    /// primary key for a table is a subset of the columns of the table that uniquely
    /// identifies each row.
    PrimaryKey(String),
    /// Name for a column which is not part of the primary key of the table
    NoPrimaryKey(String),
}

impl ColumnMetadata {
    pub(crate) fn column_name(&self) -> &str {
        match self {
            ColumnMetadata::PrimaryKey(name) => name,
            ColumnMetadata::NoPrimaryKey(name) => name,
        }
    }
}

impl OffChainTableArgs {
    pub(crate) fn new(
        table_name: String,
        secondary_index_column: ColumnMetadata,
        non_indexed_columns: Vec<ColumnMetadata>,
        provable_data_commitment: bool,
    ) -> Self {
        Self {
            table_name,
            secondary_index_column,
            non_indexed_columns,
            row_values: vec![], // instantiate with no rows
            last_update_epoch: 0,
            provable_data_commitment,
        }
    }

    pub(crate) async fn expected_root_of_trust(&self, table: &Table) -> Result<HashOutput> {
        let primary_index_id = table.columns.primary.identifier();
        if self.provable_data_commitment {
            // fetch all rows from the table
            let current_epoch = table.index.current_epoch().await?;
            let primary_indexes = table.index.keys_at(current_epoch).await;
            let rows = stream::iter(primary_indexes)
                .then(|index| async move {
                    table
                        .row
                        .pairs_at(index as UserEpoch)
                        .await
                        .unwrap()
                        .into_values()
                        .map(move |row| {
                            TableRow::new(
                                Cell::new(primary_index_id, U256::from(index)),
                                row.cells
                                    .0
                                    .into_iter()
                                    .map(|(id, c)| Cell::new(id, c.value))
                                    .collect(),
                            )
                        })
                })
                .flat_map(stream::iter)
                .collect::<Vec<_>>()
                .await;
            off_chain_data_commitment(&rows, &self.primary_key_column_ids())
        } else {
            Ok(OffChainRootOfTrust::Dummy.hash())
        }
    }

    /// Compute the column identifiers of all the columns of the table,
    /// except for the primary index column (which has a fixed identifier for now)
    pub(crate) fn column_ids(&self) -> Vec<ColumnID> {
        once(self.secondary_index_column_id())
            .chain(self.non_indexed_column_ids())
            .collect()
    }

    /// Return the set of columns that are part of the primary key for each row
    pub(crate) fn primary_key_columns(&self) -> Vec<&ColumnMetadata> {
        once(&self.secondary_index_column)
            .chain(&self.non_indexed_columns)
            .filter(|column| matches!(column, ColumnMetadata::PrimaryKey(_)))
            .collect()
    }

    /// Return the columns identifiers of the columns which are part of the primary key
    /// for each row
    pub(crate) fn primary_key_column_ids(&self) -> Vec<ColumnID> {
        self.primary_key_columns()
            .into_iter()
            .map(|column_data| self.compute_column_id(column_data))
            .collect()
    }

    /// Compute the column identifier of the column of the table corresponding to `column_data`
    pub(crate) fn compute_column_id(&self, column_data: &ColumnMetadata) -> ColumnID {
        identifier_offchain_column(&self.table_name, column_data.column_name())
    }

    /// Compute the generic `ColumnInfo` for the column of the table with id `column_id`
    pub(crate) fn compute_column_info(&self, column_id: ColumnID) -> ColumnInfo {
        let slot_input = SlotInput::default();
        ColumnInfo::new_from_slot_input(column_id, &slot_input)
    }

    pub(crate) fn primary_index_column_id(&self) -> ColumnID {
        identifier_block_column()
    }

    /// Compute the column identifier of secondary index column
    pub(crate) fn secondary_index_column_id(&self) -> ColumnID {
        self.compute_column_id(&self.secondary_index_column)
    }

    /// Compute the identifiers of non-indexed columns
    pub(crate) fn non_indexed_column_ids(&self) -> Vec<ColumnID> {
        self.non_indexed_columns
            .iter()
            .map(|column_data| self.compute_column_id(column_data))
            .collect()
    }

    /// Generate a new row with random values
    pub(crate) fn generate_new_row(&self) -> TableRowValues<BlockPrimaryIndex> {
        let rng = &mut thread_rng();
        // primary key for this row, to be filled with values of columns found included
        // in the primary key
        let mut primary_key = vec![];
        let mut process_column_data = |column_data: &ColumnMetadata, column_value: U256| {
            // add column value to primary key bytes only if the column is part of the primary key
            if let ColumnMetadata::PrimaryKey(_) = column_data {
                if &self.secondary_index_column != column_data {
                    // we add current column value to primary key only if the current
                    // column being processed is not the secondary index column, as
                    // the secondary index column is already part of the `RowTreeKey`
                    primary_key.extend_from_slice(&column_value.to_be_bytes_trimmed_vec());
                }
            }
            Cell::new(self.compute_column_id(column_data), column_value)
        };
        let secondary_index_cell =
            process_column_data(&self.secondary_index_column, U256::from(rng.gen::<u128>()));
        let rest_cells = self
            .non_indexed_columns
            .iter()
            .map(|column_data| process_column_data(column_data, U256::from(rng.gen::<u128>())))
            .collect();
        let secondary_index_cell = SecondaryIndexCell::new_from(secondary_index_cell, primary_key);
        TableRowValues {
            current_cells: rest_cells,
            current_secondary: Some(secondary_index_cell),
            primary: self.last_update_epoch,
        }
    }

    /// Initialize the rows of the table with random values
    pub(crate) fn init_data(&mut self) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        let rng = &mut thread_rng();
        // generate the initial primary index. All the rows to initialize the table will have
        // this value of the primary index, as this is acting as an epoch/block number
        let primary_index: BlockPrimaryIndex = rng.gen_range(1..=u32::MAX as usize);
        self.last_update_epoch = primary_index;
        // number of rows to be added to the table
        const NUM_ROWS: usize = 10;
        // for each row, we generate random values.
        self.row_values = (0..NUM_ROWS).map(|_| self.generate_new_row()).collect();
        // since the table is not created yet, we are giving an empty table row. When making the
        // diff with the new updated contract storage, the logic will detect it's an initialization
        // phase
        let old_table_values = TableRowValues::default();
        self.row_values
            .iter()
            .flat_map(|row_value| old_table_values.compute_update(row_value))
            .collect()
    }

    /// Compute the nonce (i.e., the set of data that makes the row unique in the table) for the row
    /// at `row_index`
    fn compute_nonce_for_row(&self, row_index: usize) -> Result<RowTreeKeyNonce> {
        let row = self.row_values.get(row_index);
        ensure!(
            row.is_some(),
            format!(
                "Invalid row index provided: {}, num rows is {}",
                row_index,
                self.row_values.len()
            )
        );
        Ok(row
            .unwrap()
            .current_cells
            .iter()
            .zip(&self.non_indexed_columns)
            .flat_map(|(cell, column)| {
                // double check that `cell` column identifier
                // corresponds to column name, which should be
                // guaranteed by how we construct rows
                assert_eq!(cell.identifier(), self.compute_column_id(column),);
                // if current cell is part of primary key, accumulate
                // its value as bytes, otherwise we return an empty byte string
                match column {
                    ColumnMetadata::PrimaryKey(_) => cell.value().to_be_bytes_trimmed_vec(),
                    ColumnMetadata::NoPrimaryKey(_) => vec![],
                }
            })
            .collect())
    }

    /// Replace with a random value the value of the non-indexed column identified by `column_data`
    /// in the row at `row_index`
    fn update_non_indexed_column(
        &mut self,
        row_index: usize,
        column_data: &ColumnMetadata,
    ) -> Result<Vec<TableRowUpdate<BlockPrimaryIndex>>> {
        let rng = &mut thread_rng();
        let row = self.row_values.get_mut(row_index);
        ensure!(
            row.is_some(),
            format!(
                "Invalid row index provided: {}, num rows is {}",
                row_index,
                self.row_values.len()
            )
        );
        let row = row.unwrap();
        Ok(match column_data {
            ColumnMetadata::PrimaryKey(name) => {
                // in this case, we need to delete the existing row
                // and insert a new one with only the value of the specific
                // column being different
                let current_secondary = row.current_secondary.as_mut().unwrap();
                let deletion = TableRowUpdate::Deletion(current_secondary.clone().into());
                // update the specific column in `row` in `self.row_values`
                let column_id = identifier_offchain_column(&self.table_name, name);
                row.current_cells
                    .iter_mut()
                    .find(|row| column_id == row.identifier())
                    .map(|cell| *cell = Cell::new(cell.identifier(), U256::from(rng.gen::<u128>())))
                    .ok_or(anyhow::Error::msg(
                        "Provided an invalid column to be updated",
                    ))?;
                // update row in self.row_values with the recomputed nonce
                let secondary_cell = current_secondary.cell();
                let new_nonce = self.compute_nonce_for_row(row_index)?;
                // redefine reference to make compiler happy with mutable references when calling
                // `compute_nonce_for_row`
                let row = &mut self.row_values[row_index];
                row.current_secondary =
                    Some(SecondaryIndexCell::new_from(secondary_cell, new_nonce));
                // update primary index value
                row.primary = self.last_update_epoch;
                // generate insertion update
                let old_table_values = TableRowValues::default();
                let insertion = old_table_values.compute_update(row);
                // return deletion + insertion updates
                once(deletion).chain(insertion).collect_vec()
            }
            ColumnMetadata::NoPrimaryKey(name) => {
                // in this case, we need to update an existing node in the tree
                let old_row = row.clone();
                // update the specific column in `row` in `self.row_values`
                let column_id = identifier_offchain_column(&self.table_name, name);
                row.current_cells
                    .iter_mut()
                    .find(|row| column_id == row.identifier())
                    .map(|cell| *cell = Cell::new(cell.identifier(), U256::from(rng.gen::<u128>())))
                    .ok_or(anyhow::Error::msg(
                        "Provided an invalid column to be updated",
                    ))?;
                // update primary index value
                row.primary = self.last_update_epoch;
                // compute update w.r.t. old row
                old_row.compute_update(row)
            }
        })
    }

    /// Update the rows in `self` according to the change type specified as input
    pub(crate) fn random_update(
        &mut self,
        c: ChangeType,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        let num_rows = self.row_values.len();
        let rng = &mut thread_rng();
        if let ChangeType::Silent = c {
            // no changes, return empty vector
            return vec![];
        }

        self.last_update_epoch += rng.gen_range(1..10);
        match c {
            ChangeType::Deletion => {
                // randomly choose a couple of rows to delete
                (0..2)
                    .map(|i| {
                        let row_to_delete = rng.gen_range(0..(num_rows - i));
                        let deleted_row = self.row_values.swap_remove(row_to_delete);
                        TableRowUpdate::Deletion(deleted_row.current_secondary.unwrap().into())
                    })
                    .collect()
            }
            ChangeType::Insertion => {
                // add a couple of rows
                let new_rows: Vec<TableRowValues<BlockPrimaryIndex>> =
                    (0..2).map(|_| self.generate_new_row()).collect();
                // generate updates
                new_rows
                    .into_iter()
                    .flat_map(|row| {
                        // since the table is not created yet, we are giving an empty table row. When making the
                        // diff with the new updated contract storage, the logic will detect it's an initialization
                        // phase
                        let old_table_values = TableRowValues::default();
                        let update = old_table_values.compute_update(&row);
                        self.row_values.push(row);
                        update
                    })
                    .collect()
            }
            ChangeType::Update(update_type) => {
                // we choose a couple of rows to update
                let rows_to_update = [0; 2].map(|_| rng.gen_range(0..num_rows));
                match update_type {
                    UpdateType::SecondaryIndex => {
                        // in this case, we need to delete and insert a new row, since
                        // the secondary index is part of `RowTreeKey`; the new row
                        // will have the same values of the old row for all the non-indexed
                        // columns
                        rows_to_update
                            .into_iter()
                            .flat_map(|row_index| {
                                let row = &mut self.row_values[row_index];
                                let current_secondary = row.current_secondary.as_mut().unwrap();
                                let deletion =
                                    TableRowUpdate::Deletion(current_secondary.clone().into());
                                // update row in self.row_values with a randomly generated secondary index cell
                                let current_nonce = current_secondary.rest();
                                let secondary_index_column_id =
                                    self.compute_column_id(&self.secondary_index_column);
                                let row = &mut self.row_values[row_index];
                                row.current_secondary = Some(SecondaryIndexCell::new_from(
                                    Cell::new(
                                        secondary_index_column_id,
                                        U256::from(rng.gen::<u128>()),
                                    ),
                                    current_nonce,
                                ));
                                row.primary = self.last_update_epoch;
                                let old_table_values = TableRowValues::default();
                                let insertion = old_table_values.compute_update(row);
                                once(deletion).chain(insertion).collect_vec()
                            })
                            .collect()
                    }
                    UpdateType::Rest => {
                        // in this case, we update one row by changing a non-indexed column
                        // which is part of the primary key (if any), and another row by
                        // changing a non-indexed column which is not part of the primary key
                        let (primary_key_columns, non_primary_key_columns): (Vec<_>, Vec<_>) = self
                            .non_indexed_columns
                            .iter()
                            .partition(|column_data| match column_data {
                                ColumnMetadata::PrimaryKey(_) => true,
                                ColumnMetadata::NoPrimaryKey(_) => false,
                            });
                        let columns_to_update = if primary_key_columns.is_empty() {
                            // no primary key columns among non-indexed columns,
                            // so we update 2 columns at random
                            [0; 2].map(|_| {
                                non_primary_key_columns
                                    [rng.gen_range(0..non_primary_key_columns.len())]
                                .clone()
                            })
                        } else {
                            [
                                non_primary_key_columns
                                    [rng.gen_range(0..non_primary_key_columns.len())]
                                .clone(),
                                primary_key_columns[rng.gen_range(0..primary_key_columns.len())]
                                    .clone(),
                            ]
                        };
                        rows_to_update
                            .into_iter()
                            .zip(columns_to_update)
                            .flat_map(|(row_index, column_data)| {
                                self.update_non_indexed_column(row_index, &column_data)
                                    .unwrap()
                            })
                            .collect()
                    }
                }
            }
            ChangeType::Silent => vec![], // no changes
        }
    }

    pub(crate) fn generate_extraction_proof_inputs(
        &self,
        ctx: &mut TestContext,
        proof_key: ProofKey,
    ) -> Result<(ExtractionProofInput, HashOutput)> {
        // convert current row values to row cells
        let rows = self
            .row_values
            .iter()
            .map(|row| row.to_table_row(self.primary_index_column_id()))
            .collect::<Result<Vec<_>>>()?;
        // This could be computed from the table data according to any logic,
        // here for simplicity we just use a fixed dummy value
        let hash = OffChainRootOfTrust::Dummy;
        // fetch previous IVC proof, if any
        let prev_proof = ctx.storage.get_proof_exact(&proof_key).ok();

        let metadata_hash =
            no_provable_metadata_hash(self.column_ids(), self.provable_data_commitment);
        let input = ExtractionProofInput::Offchain(OffChainExtractionProof {
            hash,
            prev_proof,
            primary_index: self.last_update_epoch,
            rows,
            primary_key_columns: self.primary_key_column_ids(),
        });
        Ok((input, metadata_hash))
    }
}
