use std::{
    array,
    assert_matches::assert_matches,
    collections::{BTreeSet, HashMap},
    fmt::Debug,
    future::Future,
    hash::Hash,
    str::FromStr,
    sync::atomic::{AtomicU64, AtomicUsize},
};

use alloy::{
    consensus::TxReceipt,
    eips::BlockNumberOrTag,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
};
use anyhow::{bail, Result};
use futures::{future::BoxFuture, FutureExt};
use itertools::Itertools;
use log::{debug, info};
use mp2_common::{
    eth::{EventLogInfo, ProofQuery, ReceiptProofInfo, StorageSlot, StorageSlotNode},
    proof::ProofWithVK,
    types::HashOutput,
};
use mp2_v1::{
    api::{
        combine_digest_and_block, compute_table_info, merge_metadata_hash,
        metadata_hash as metadata_hash_function, SlotInput, SlotInputs,
    },
    indexing::{
        block::BlockPrimaryIndex,
        cell::Cell,
        row::{RowTreeKey, ToNonce},
    },
    values_extraction::{
        gadgets::{column_info::ExtractedColumnInfo, metadata_gadget::TableMetadata},
        identifier_for_inner_mapping_key_column, identifier_for_mapping_key_column,
        identifier_for_outer_mapping_key_column, identifier_for_tx_index_column,
        identifier_for_value_column,
        planner::Extractable,
        StorageSlotInfo,
    },
};
use plonky2::field::types::PrimeField64;
use rand::{
    distributions::{Alphanumeric, DistString},
    rngs::StdRng,
    Rng, SeedableRng,
};

use crate::common::{
    cases::{
        contract::EventContract,
        indexing::{ReceiptUpdate, TableRowValues},
    },
    final_extraction::{ExtractionProofInput, ExtractionTableProof, MergeExtractionProof},
    proof_storage::{ProofKey, ProofStorage},
    rowtree::SecondaryIndexCell,
    table::CellsUpdate,
    Deserialize, MetadataHash, Serialize, TestContext,
};

use super::{
    contract::{Contract, ContractController, MappingUpdate, SimpleSingleValues, TestContract},
    indexing::{ChangeType, TableRowUpdate, UpdateType, SINGLE_SLOTS, SINGLE_STRUCT_SLOT},
    slot_info::{LargeStruct, MappingInfo, StorageSlotMappingKey, StorageSlotValue, StructMapping},
};

fn metadata_hash(
    slot_input: SlotInputs,
    contract_address: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> MetadataHash {
    metadata_hash_function(slot_input, contract_address, chain_id, extra)
}

/// Save the columns information of same slot and EVM word.
#[derive(Debug, Clone)]
struct SlotEvmWordColumns(Vec<ExtractedColumnInfo>);

impl SlotEvmWordColumns {
    fn new(column_info: Vec<ExtractedColumnInfo>) -> Self {
        // Ensure the column information should have the same slot and EVM word.

        let slot = column_info[0].extraction_id()[7].0 as u8;
        let evm_word = column_info[0].location_offset().0 as u32;
        column_info[1..].iter().for_each(|col| {
            let col_slot = col.extraction_id()[7].0 as u8;
            let col_word = col.location_offset().0 as u32;
            assert_eq!(col_slot, slot);
            assert_eq!(col_word, evm_word);
        });

        Self(column_info)
    }
    fn slot(&self) -> u8 {
        // The columns should have the same slot.
        u8::try_from(self.0[0].extraction_id()[7].to_canonical_u64()).unwrap()
    }
    fn evm_word(&self) -> u32 {
        // The columns should have the same EVM word.
        u32::try_from(self.0[0].location_offset().to_canonical_u64()).unwrap()
    }
    fn column_info(&self) -> &[ExtractedColumnInfo] {
        &self.0
    }
}

/// What is the secondary index chosen for the table in the mapping.
/// Each entry contains the identifier of the column expected to store in our tree
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Copy)]
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
            " --- MAPPING to row: secondary index {:?}  -- cells {:?}",
            secondary_cell, current_cells,
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

pub(crate) trait TableSource {
    type Metadata;

    fn get_data(&self) -> Self::Metadata;

    fn init_contract_data<'a>(
        &'a mut self,
        ctx: &'a mut TestContext,
        contract: &'a Contract,
    ) -> BoxFuture<'a, Vec<TableRowUpdate<BlockPrimaryIndex>>>;

    fn generate_extraction_proof_inputs(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
        value_key: ProofKey,
    ) -> impl Future<Output = Result<(ExtractionProofInput, HashOutput)>>;

    fn random_contract_update<'a>(
        &'a mut self,
        ctx: &'a mut TestContext,
        contract: &'a Contract,
        c: ChangeType,
    ) -> BoxFuture<'a, Vec<TableRowUpdate<BlockPrimaryIndex>>>;

    fn metadata_hash(&self, contract_address: Address, chain_id: u64) -> MetadataHash;

    fn can_query(&self) -> bool;
}

impl TableSource for SingleExtractionArgs {
    type Metadata = SlotInputs;

    fn get_data(&self) -> SlotInputs {
        SlotInputs::Simple(self.slot_inputs.clone())
    }

    fn init_contract_data<'a>(
        &'a mut self,
        ctx: &'a mut TestContext,
        contract: &'a Contract,
    ) -> BoxFuture<'a, Vec<TableRowUpdate<BlockPrimaryIndex>>> {
        async move { SingleExtractionArgs::init_contract_data(self, ctx, contract).await }.boxed()
    }

    async fn generate_extraction_proof_inputs(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
        value_key: ProofKey,
    ) -> Result<(ExtractionProofInput, HashOutput)> {
        SingleExtractionArgs::generate_extraction_proof_inputs(self, ctx, contract, value_key).await
    }

    fn random_contract_update<'a>(
        &'a mut self,
        ctx: &'a mut TestContext,
        contract: &'a Contract,
        c: ChangeType,
    ) -> BoxFuture<'a, Vec<TableRowUpdate<BlockPrimaryIndex>>> {
        async move { SingleExtractionArgs::random_contract_update(self, ctx, contract, c).await }
            .boxed()
    }

    fn metadata_hash(&self, contract_address: Address, chain_id: u64) -> MetadataHash {
        let slot = self.get_data();
        metadata_hash(slot, &contract_address, chain_id, vec![])
    }

    fn can_query(&self) -> bool {
        false
    }
}

impl TableSource for MergeSource {
    type Metadata = (SlotInputs, SlotInputs);

    fn get_data(&self) -> Self::Metadata {
        (self.single.get_data(), self.mapping.get_data())
    }

    fn init_contract_data<'a>(
        &'a mut self,
        ctx: &'a mut TestContext,
        contract: &'a Contract,
    ) -> BoxFuture<'a, Vec<TableRowUpdate<BlockPrimaryIndex>>> {
        async move { MergeSource::init_contract_data(self, ctx, contract).await }.boxed()
    }

    async fn generate_extraction_proof_inputs(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
        value_key: ProofKey,
    ) -> Result<(ExtractionProofInput, HashOutput)> {
        MergeSource::generate_extraction_proof_inputs(self, ctx, contract, value_key).await
    }

    fn random_contract_update<'a>(
        &'a mut self,
        ctx: &'a mut TestContext,
        contract: &'a Contract,
        c: ChangeType,
    ) -> BoxFuture<'a, Vec<TableRowUpdate<BlockPrimaryIndex>>> {
        async move { MergeSource::random_contract_update(self, ctx, contract, c).await }.boxed()
    }

    fn metadata_hash(&self, contract_address: Address, chain_id: u64) -> MetadataHash {
        let (single, mapping) = self.get_data();
        merge_metadata_hash(contract_address, chain_id, vec![], single, mapping)
    }

    fn can_query(&self) -> bool {
        true
    }
}

#[derive(Serialize, Deserialize, Debug, Hash, Clone, PartialEq, Eq)]
pub struct MergeSource {
    // NOTE: this is a hardcore assumption currently that table_a is single and table_b is mapping for now
    // Extending to full merge between any table is not far - it requires some quick changes in
    // circuit but quite a lot of changes in integrated test.
    pub(crate) single: SingleExtractionArgs,
    pub(crate) mapping: MappingExtractionArgs<StructMapping>,
}

impl MergeSource {
    pub fn new(
        single: SingleExtractionArgs,
        mapping: MappingExtractionArgs<StructMapping>,
    ) -> Self {
        Self { single, mapping }
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
                    (_, TableRowUpdate::Deletion(_)) | (_, TableRowUpdate::DeleteAll) => panic!("no deletion on single table"),
                    (TableRowUpdate::Update(_), TableRowUpdate::Insertion(_, _)) => {
                        panic!("insertion on single only happens at genesis")
                    }
                    // WARNING: when a mapping row is deleted, it deletes the whole row even for single
                    // values
                    (TableRowUpdate::Deletion(ref d), _) => TableRowUpdate::Deletion(d.clone()),
                    (TableRowUpdate::DeleteAll, _) => panic!("Cannot currently delete all mapping entries"),
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
                            TableRowUpdate::DeleteAll => panic!("Cannot delete all for a mapping"),
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
            let (simple, mapping) = self.get_data();
            let md =
                merge_metadata_hash(contract.address, contract.chain_id, vec![], simple, mapping);
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
}

/// Length extraction arguments (C.2)
#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone, Copy)]
pub(crate) struct LengthExtractionArgs {
    /// Length slot
    pub(crate) slot: u8,
    /// Length value
    pub(crate) value: u8,
}

pub trait ReceiptExtractionArgs:
    Serialize + for<'de> Deserialize<'de> + Debug + Hash + Eq + PartialEq + Clone + Copy
{
    const NO_TOPICS: usize;
    const MAX_DATA_WORDS: usize;

    fn new(address: Address, event_signature: &str) -> Self
    where
        Self: Sized;

    fn get_event(&self) -> EventLogInfo<{ Self::NO_TOPICS }, { Self::MAX_DATA_WORDS }>;

    fn get_index(&self) -> u64;

    fn to_table_rows<PrimaryIndex: Clone>(
        proof_infos: &[ReceiptProofInfo],
        event: &EventLogInfo<{ Self::NO_TOPICS }, { Self::MAX_DATA_WORDS }>,
        block: PrimaryIndex,
    ) -> Vec<TableRowUpdate<PrimaryIndex>> {
        let metadata = TableMetadata::from(*event);

        let (_, row_id) = metadata.input_value_digest(&[&[0u8; 32]; 2]);
        let input_columns_ids = metadata
            .input_columns()
            .iter()
            .map(|col| col.identifier().0)
            .collect::<Vec<u64>>();
        let extracted_column_ids = metadata
            .extracted_columns()
            .iter()
            .map(|col| col.identifier().0)
            .collect::<Vec<u64>>();

        std::iter::once(TableRowUpdate::DeleteAll)
            .chain(proof_infos.iter().flat_map(|info| {
                let receipt_with_bloom = info.to_receipt().unwrap();

                let tx_index_cell = Cell::new(input_columns_ids[0], U256::from(info.tx_index));

                let gas_used_cell = Cell::new(
                    input_columns_ids[1],
                    U256::from(receipt_with_bloom.receipt.cumulative_gas_used),
                );

                receipt_with_bloom
                    .logs()
                    .iter()
                    .filter_map(|log| {
                        if log.address == event.address
                            && log.topics()[0].0 == event.event_signature
                        {
                            Some(log.clone())
                        } else {
                            None
                        }
                    })
                    .map(|log| {
                        let log = log.clone();
                        let (topics, data) = log.data.split();
                        let topics_cells = topics
                            .into_iter()
                            .skip(1)
                            .enumerate()
                            .map(|(j, topic)| Cell::new(extracted_column_ids[j], topic.into()))
                            .collect::<Vec<Cell>>();

                        let data_start = topics_cells.len();
                        let data_cells = data
                            .chunks(32)
                            .enumerate()
                            .map(|(j, data_slice)| {
                                Cell::new(
                                    extracted_column_ids[data_start + j],
                                    U256::from_be_slice(data_slice),
                                )
                            })
                            .collect::<Vec<Cell>>();

                        let secondary =
                            SecondaryIndexCell::new_from(tx_index_cell, row_id.0.to_vec());

                        let collection = CellsUpdate::<PrimaryIndex> {
                            previous_row_key: RowTreeKey::default(),
                            new_row_key: RowTreeKey::from(&secondary),
                            updated_cells: [vec![gas_used_cell], topics_cells, data_cells].concat(),
                            primary: block.clone(),
                        };

                        TableRowUpdate::<PrimaryIndex>::Insertion(collection, secondary)
                    })
                    .collect::<Vec<TableRowUpdate<PrimaryIndex>>>()
            }))
            .collect::<Vec<TableRowUpdate<PrimaryIndex>>>()
    }
}

impl<const NO_TOPICS: usize, const MAX_DATA_WORDS: usize> ReceiptExtractionArgs
    for EventLogInfo<NO_TOPICS, MAX_DATA_WORDS>
{
    const MAX_DATA_WORDS: usize = MAX_DATA_WORDS;
    const NO_TOPICS: usize = NO_TOPICS;

    fn new(address: Address, event_signature: &str) -> Self
    where
        Self: Sized,
    {
        EventLogInfo::<NO_TOPICS, MAX_DATA_WORDS>::new(address, event_signature)
    }

    fn get_event(&self) -> EventLogInfo<{ Self::NO_TOPICS }, { Self::MAX_DATA_WORDS }>
    where
        [(); Self::NO_TOPICS]:,
        [(); Self::MAX_DATA_WORDS]:,
    {
        let topics: [usize; Self::NO_TOPICS] = self
            .topics
            .into_iter()
            .collect::<Vec<usize>>()
            .try_into()
            .unwrap();
        let data: [usize; Self::MAX_DATA_WORDS] = self
            .data
            .into_iter()
            .collect::<Vec<usize>>()
            .try_into()
            .unwrap();
        EventLogInfo::<{ Self::NO_TOPICS }, { Self::MAX_DATA_WORDS }> {
            size: self.size,
            address: self.address,
            add_rel_offset: self.add_rel_offset,
            event_signature: self.event_signature,
            sig_rel_offset: self.sig_rel_offset,
            topics,
            data,
        }
    }

    fn get_index(&self) -> u64 {
        identifier_for_tx_index_column(&self.event_signature, &self.address, &[])
    }
}

impl<R: ReceiptExtractionArgs> TableSource for R
where
    [(); <R as ReceiptExtractionArgs>::NO_TOPICS]:,
    [(); <R as ReceiptExtractionArgs>::MAX_DATA_WORDS]:,
{
    type Metadata = EventLogInfo<{ R::NO_TOPICS }, { R::MAX_DATA_WORDS }>;

    fn can_query(&self) -> bool {
        true
    }

    fn get_data(&self) -> Self::Metadata {
        self.get_event()
    }

    fn init_contract_data<'a>(
        &'a mut self,
        ctx: &'a mut TestContext,
        contract: &'a Contract,
    ) -> BoxFuture<'a, Vec<TableRowUpdate<BlockPrimaryIndex>>> {
        let event = self.get_event();
        async move {
            let contract_update =
                ReceiptUpdate::new((R::NO_TOPICS as u8, R::MAX_DATA_WORDS as u8), 1, 5);

            let provider = ProviderBuilder::new()
                .with_recommended_fillers()
                .wallet(ctx.wallet())
                .on_http(ctx.rpc_url.parse().unwrap());

            let event_emitter = EventContract::new(contract.address(), provider.root());
            event_emitter
                .apply_update(ctx, &contract_update)
                .await
                .unwrap();

            let block_number = ctx.block_number().await;
            let new_block_number = block_number as BlockPrimaryIndex;

            let (proof_infos, _) = event
                .query_receipt_proofs(provider.root(), block_number.into())
                .await
                .unwrap();

            R::to_table_rows(&proof_infos, &event, new_block_number)
        }
        .boxed()
    }

    async fn generate_extraction_proof_inputs(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
        value_key: ProofKey,
    ) -> Result<(ExtractionProofInput, HashOutput)> {
        let event = self.get_event();

        let ProofKey::ValueExtraction((_, bn)) = value_key else {
            bail!("key wrong");
        };

        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());

        let value_proof = event
            .prove_value_extraction::<32, 512, _>(
                bn as u64,
                ctx.params().get_value_extraction_params(),
                provider.root(),
            )
            .await?;
        Ok((
            ExtractionProofInput::Receipt(value_proof),
            self.metadata_hash(contract.address(), contract.chain_id()),
        ))
    }

    fn random_contract_update<'a>(
        &'a mut self,
        ctx: &'a mut TestContext,
        contract: &'a Contract,
        c: ChangeType,
    ) -> BoxFuture<'a, Vec<TableRowUpdate<BlockPrimaryIndex>>> {
        let event = self.get_event();
        async move {
            let ChangeType::Receipt(relevant, others) = c else {
                panic!("Need ChangeType::Receipt, got: {:?}", c);
            };
            let contract_update = ReceiptUpdate::new(
                (R::NO_TOPICS as u8, R::MAX_DATA_WORDS as u8),
                relevant,
                others,
            );

            let provider = ProviderBuilder::new()
                .with_recommended_fillers()
                .wallet(ctx.wallet())
                .on_http(ctx.rpc_url.parse().unwrap());

            let event_emitter = EventContract::new(contract.address(), provider.root());
            event_emitter
                .apply_update(ctx, &contract_update)
                .await
                .unwrap();

            let block_number = ctx.block_number().await;
            let new_block_number = block_number as BlockPrimaryIndex;

            let (proof_infos, _) = event
                .query_receipt_proofs(provider.root(), block_number.into())
                .await
                .unwrap();

            R::to_table_rows(&proof_infos, &event, new_block_number)
        }
        .boxed()
    }

    fn metadata_hash(&self, _contract_address: Address, _chain_id: u64) -> MetadataHash {
        let table_metadata = TableMetadata::from(self.get_event());
        let digest = table_metadata.digest();
        combine_digest_and_block(digest)
    }
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
    pub(crate) static ref BASE_VALUE: U256 = U256::from(10u8);
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
        self.secondary_index.map(|idx| self.slot_inputs[idx])
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
        let metadata_hash =
            metadata_hash(slot_inputs, &contract.address, contract.chain_id, vec![]);
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
            let value_bytes: [u8; 32] = value.to_be_bytes();
            evm_word_col.column_info().iter().for_each(|col_info| {
                let extracted_value = col_info.extract_value(value_bytes.as_slice());
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

    fn table_info(&self, contract: &Contract) -> Vec<ExtractedColumnInfo> {
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
            ChangeType::Receipt(..) => {
                panic!("Can't add a new receipt change for storage variable")
            }
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

#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone)]
pub(crate) struct MappingExtractionArgs<T: MappingInfo> {
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
    mapping_keys: BTreeSet<T>,
    /// The optional length extraction parameters
    length_args: Option<LengthExtractionArgs>,
}

impl<T> TableSource for MappingExtractionArgs<T>
where
    T: MappingInfo,
    Vec<MappingUpdate<T, T::Value>>: ContractController,
{
    type Metadata = SlotInputs;

    fn get_data(&self) -> Self::Metadata {
        if let Some(l_args) = self.length_args.as_ref() {
            T::slot_inputs(self.slot_inputs.clone(), Some(l_args.slot))
        } else {
            T::slot_inputs(self.slot_inputs.clone(), None)
        }
    }

    fn init_contract_data<'a>(
        &'a mut self,
        ctx: &'a mut TestContext,
        contract: &'a Contract,
    ) -> BoxFuture<'a, Vec<TableRowUpdate<BlockPrimaryIndex>>> {
        async {
            let init_key_and_value: [_; 3] =
                array::from_fn(|_| (T::sample_key(), <T as MappingInfo>::Value::sample_value()));
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
        .boxed()
    }

    async fn generate_extraction_proof_inputs(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
        value_key: ProofKey,
    ) -> Result<(ExtractionProofInput, HashOutput)> {
        let ProofKey::ValueExtraction((_, bn)) = value_key.clone() else {
            bail!("invalid proof key");
        };
        let mapping_root_proof = match ctx.storage.get_proof_exact(&value_key) {
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
                    .store_proof(value_key, mapping_values_proof.clone())?;
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
        let metadata_hash = self.metadata_hash(contract.address(), contract.chain_id());
        // it's a compoound value type of proof since we're not using the length
        let input = ExtractionProofInput::Single(ExtractionTableProof {
            value_proof: mapping_root_proof,
            length_proof: None,
        });
        Ok((input, metadata_hash))
    }

    fn random_contract_update<'a>(
        &'a mut self,
        ctx: &'a mut TestContext,
        contract: &'a Contract,
        c: ChangeType,
    ) -> BoxFuture<'a, Vec<TableRowUpdate<BlockPrimaryIndex>>> {
        async move {
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
            let new_key = T::sample_key();
            let updates = match c {
                ChangeType::Receipt(..) => {
                    panic!("Can't add a new receipt change for storage variable")
                }
                ChangeType::Silent => vec![],
                ChangeType::Insertion => {
                    vec![MappingUpdate::Insertion(
                        new_key,
                        <T as MappingInfo>::Value::sample_value(),
                    )]
                }
                ChangeType::Deletion => {
                    vec![MappingUpdate::Deletion(current_key.clone(), current_value)]
                }
                ChangeType::Update(u) => {
                    match u {
                        UpdateType::Rest => {
                            let new_value = <T as MappingInfo>::Value::sample_value();
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
        .boxed()
    }

    fn metadata_hash(&self, contract_address: Address, chain_id: u64) -> MetadataHash {
        metadata_hash(self.get_data(), &contract_address, chain_id, vec![])
    }

    fn can_query(&self) -> bool {
        true
    }
}

impl<T: MappingInfo> MappingExtractionArgs<T> {
    pub fn new(
        slot: u8,
        index: MappingIndex,
        slot_inputs: Vec<SlotInput>,
        length_args: Option<LengthExtractionArgs>,
    ) -> Self {
        Self {
            slot,
            index,
            slot_inputs,
            mapping_keys: BTreeSet::new(),
            length_args,
        }
    }
    /// The generic parameter `V` could be set to an Uint256 as single value or a Struct.
    pub fn mapping_to_table_update(
        &self,
        block_number: BlockPrimaryIndex,
        contract: &Contract,
        updates: &[MappingUpdate<T, T::Value>],
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
        table_info: Vec<ExtractedColumnInfo>,
        mapping_key: &T,
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
    async fn query_value(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
        mapping_key: &T,
    ) -> T::Value {
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

            let value_bytes: [u8; 32] = value.to_be_bytes();
            evm_word_col.column_info().iter().for_each(|col_info| {
                let bytes = col_info.extract_value(&value_bytes);
                let value = U256::from_be_bytes(bytes);
                debug!(
                    "Mapping extract value: column: {:?}, value = {}",
                    col_info, value,
                );

                extracted_values.push(value);
            });
        }

        <T as MappingInfo>::Value::from_u256_slice(&extracted_values)
    }

    fn table_info(&self, contract: &Contract) -> Vec<ExtractedColumnInfo> {
        table_info(contract, self.slot_inputs.clone())
    }

    fn evm_word_column_info(&self, contract: &Contract) -> Vec<SlotEvmWordColumns> {
        let table_info = self.table_info(contract);
        evm_word_column_info(&table_info)
    }
}

/// Contruct the table information by the contract and slot inputs.
fn table_info(contract: &Contract, slot_inputs: Vec<SlotInput>) -> Vec<ExtractedColumnInfo> {
    compute_table_info(slot_inputs, &contract.address, contract.chain_id, vec![])
}

/// Construct the column information for each slot and EVM word.
fn evm_word_column_info(table_info: &[ExtractedColumnInfo]) -> Vec<SlotEvmWordColumns> {
    // Initialize a mapping of `(slot, evm_word) -> column_Identifier`.
    let mut column_info_map = HashMap::new();
    table_info.iter().for_each(|col| {
        column_info_map
            .entry((
                col.extraction_id()[7].0 as u8,
                col.location_offset().0 as u32,
            ))
            .and_modify(|cols: &mut Vec<_>| cols.push(*col))
            .or_insert(vec![*col]);
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
