use std::{
    assert_matches::assert_matches,
    str::FromStr,
    sync::atomic::{AtomicU64, AtomicUsize},
};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, U256},
};
use anyhow::{bail, Result};
use futures::{future::BoxFuture, FutureExt};
use itertools::Itertools;
use log::{debug, info};
use mp2_common::{
    digest::TableDimension,
    eth::{ProofQuery, StorageSlot, StorageSlotNode},
    proof::ProofWithVK,
    types::HashOutput,
};
use mp2_v1::{
    api::{merge_metadata_hash, metadata_hash, SlotInput, SlotInputs},
    indexing::{
        block::BlockPrimaryIndex,
        cell::Cell,
        row::{RowTreeKey, ToNonce},
    },
    values_extraction::{
        compute_leaf_single_metadata_digest,
        gadgets::{column_gadget::extract_value, column_info::ColumnInfo},
        identifier_for_mapping_key_column, identifier_for_value_column,
    },
};
use plonky2::field::types::PrimeField64;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};

use crate::common::{
    cases::indexing::{
        LargeStruct, MappingStructUpdate, MappingValuesUpdate, SimpleSingleValue, TableRowValues,
    },
    final_extraction::{ExtractionProofInput, ExtractionTableProof, MergeExtractionProof},
    proof_storage::{ProofKey, ProofStorage},
    rowtree::SecondaryIndexCell,
    table::CellsUpdate,
    MetadataGadget, StorageSlotInfo, TestContext, TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM,
};

use super::{
    contract::Contract,
    indexing::{
        ChangeType, TableRowUpdate, UpdateSimpleStorage, UpdateType, MAPPING_SLOT,
        MAPPING_STRUCT_SLOT, SINGLE_SLOTS, SINGLE_STRUCT_SLOT,
    },
};

/// The key,value such that the combination is unique. This can be turned into a RowTreeKey.
/// to store in the row tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UniqueMappingEntry {
    key: U256,
    value: U256,
}

impl From<(U256, U256)> for UniqueMappingEntry {
    fn from(pair: (U256, U256)) -> Self {
        Self {
            key: pair.0,
            value: pair.1,
        }
    }
}

/// What is the secondary index chosen for the table in the mapping.
/// Each entry contains the identifier of the column expected to store in our tree
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum MappingIndex {
    Key(u64),
    Value(u64),
    // This can happen if it is being part of a merge table and the secondary index is from the
    // other table
    None,
}

impl UniqueMappingEntry {
    pub fn new(k: &U256, v: &U256) -> Self {
        Self { key: *k, value: *v }
    }
    pub fn to_update(
        &self,
        block_number: BlockPrimaryIndex,
        mapping_index: &MappingIndex,
        slot_input: &SlotInput,
        contract: &Address,
        chain_id: u64,
        previous_row_key: Option<RowTreeKey>,
    ) -> (CellsUpdate<BlockPrimaryIndex>, SecondaryIndexCell) {
        let row_value =
            self.to_table_row_value(block_number, mapping_index, slot_input, contract, chain_id);
        let cells_update = CellsUpdate {
            previous_row_key: previous_row_key.unwrap_or_default(),
            new_row_key: self.to_row_key(mapping_index),
            updated_cells: row_value.current_cells,
            primary: block_number,
        };
        let index_cell = row_value.current_secondary.unwrap_or_default();
        (cells_update, index_cell)
    }

    /// Return a row given this mapping entry, depending on the chosen index
    pub fn to_table_row_value(
        &self,
        block_number: BlockPrimaryIndex,
        index: &MappingIndex,
        slot_input: &SlotInput,
        contract: &Address,
        chain_id: u64,
    ) -> TableRowValues<BlockPrimaryIndex> {
        // we construct the two associated cells in the table. One of them will become
        // a SecondaryIndexCell depending on the secondary index type we have chosen
        // for this mapping.
        let extract_key = MappingIndex::Key(identifier_for_mapping_key_column(
            slot_input.slot(),
            contract,
            chain_id,
            vec![],
        ));
        let key_cell = self.to_cell(extract_key);
        let extract_key = MappingIndex::Value(identifier_for_value_column(
            slot_input,
            contract,
            chain_id,
            vec![],
        ));
        let value_cell = self.to_cell(extract_key);
        // then we look at which one is must be the secondary cell, if any
        let (secondary, rest_cells) = match index {
            MappingIndex::Key(_) => (
                // by definition, mapping key is unique, so there is no need for a specific
                // nonce for the tree in that case
                SecondaryIndexCell::new_from(key_cell, U256::from(0)),
                vec![value_cell],
            ),
            MappingIndex::Value(_) => {
                // Here we take the tuple (value,key) as uniquely identifying a row in the
                // table
                (
                    SecondaryIndexCell::new_from(value_cell, self.key),
                    vec![key_cell],
                )
            }
            MappingIndex::None => (Default::default(), vec![value_cell, key_cell]),
        };
        debug!(
            " --- MAPPING: to row: secondary index {:?}  -- cell {:?}",
            secondary, rest_cells
        );
        TableRowValues {
            current_cells: rest_cells,
            current_secondary: Some(secondary),
            primary: block_number,
        }
    }

    // using MappingIndex is a misleading name but it allows us to choose which part of the mapping
    // we want to extract
    pub fn to_cell(&self, index: MappingIndex) -> Cell {
        match index {
            MappingIndex::Key(id) => Cell::new(id, self.key),
            MappingIndex::Value(id) => Cell::new(id, self.value),
            MappingIndex::None => panic!("this should never happen"),
        }
    }

    pub fn to_row_key(&self, index: &MappingIndex) -> RowTreeKey {
        match index {
            MappingIndex::Key(_) => RowTreeKey {
                // tree key indexed by mapping key
                value: self.key,
                rest: self.value.to_nonce(),
            },
            MappingIndex::Value(_) => RowTreeKey {
                // tree key indexed by mapping value
                value: self.value,
                rest: self.key.to_nonce(),
            },
            MappingIndex::None => RowTreeKey::default(),
        }
    }
}

/// The combination of key and struct value is unique.
/// This can be turned into a RowTreeKey to store in the row tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UniqueMappingStructEntry {
    key: U256,
    value: LargeStruct,
}

impl From<(U256, LargeStruct)> for UniqueMappingStructEntry {
    fn from(pair: (U256, LargeStruct)) -> Self {
        Self {
            key: pair.0,
            value: pair.1,
        }
    }
}

impl UniqueMappingStructEntry {
    pub fn new(k: &U256, v: &LargeStruct) -> Self {
        Self {
            key: *k,
            value: v.clone(),
        }
    }

    pub fn to_update(
        &self,
        block_number: BlockPrimaryIndex,
        contract: &Contract,
        previous_row_key: Option<RowTreeKey>,
    ) -> (CellsUpdate<BlockPrimaryIndex>, SecondaryIndexCell) {
        let row_value = self.to_table_row_value(block_number, contract);
        let cells_update = CellsUpdate {
            previous_row_key: previous_row_key.unwrap_or_default(),
            new_row_key: self.to_row_key(),
            updated_cells: row_value.current_cells,
            primary: block_number,
        };
        let index_cell = row_value.current_secondary.unwrap_or_default();
        (cells_update, index_cell)
    }

    /// Return a row given this mapping entry, depending on the chosen index
    pub fn to_table_row_value(
        &self,
        block_number: BlockPrimaryIndex,
        contract: &Contract,
    ) -> TableRowValues<BlockPrimaryIndex> {
        let key_cell = {
            let key_id = identifier_for_mapping_key_column(
                MAPPING_STRUCT_SLOT as u8,
                &contract.address,
                contract.chain_id,
                vec![],
            );

            Cell::new(key_id, self.key)
        };
        let value_ids = LargeStruct::slot_inputs(MAPPING_STRUCT_SLOT as u8)
            .iter()
            .map(|slot_input| {
                identifier_for_value_column(
                    slot_input,
                    &contract.address,
                    contract.chain_id,
                    vec![],
                )
            })
            .collect_vec();
        assert_eq!(value_ids.len(), LargeStruct::FIELD_NUM);
        let current_cells = vec![
            Cell::new(value_ids[0], self.value.field1),
            Cell::new(value_ids[1], U256::from(self.value.field2)),
            Cell::new(value_ids[2], U256::from(self.value.field3)),
        ];

        let current_secondary = Some(SecondaryIndexCell::new_from(key_cell, U256::from(0)));
        debug!(
            " --- MAPPING STRUCT: to row: secondary index {:?}  -- cell {:?}",
            current_secondary, current_cells,
        );
        TableRowValues {
            current_cells,
            current_secondary,
            primary: block_number,
        }
    }

    pub fn to_row_key(&self) -> RowTreeKey {
        RowTreeKey {
            // tree key indexed by mapping key
            value: self.key,
            rest: self.value.to_bytes().to_nonce(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Hash, Clone, PartialEq, Eq)]
pub(crate) enum TableSource {
    /// Test arguments for single values extraction (C.1)
    SingleValues(SingleValuesExtractionArgs),
    /// Test arguments for mapping values extraction (C.1)
    /// We can test with and without the length
    MappingValues((MappingValuesExtractionArgs, Option<LengthExtractionArgs>)),
    /// Test arguments for single struct extraction
    SingleStruct(SingleStructExtractionArgs),
    /// Test arguments for mapping struct extraction
    MappingStruct((MappingStructExtractionArgs, Option<LengthExtractionArgs>)),
    Merge(MergeSource),
}

impl TableSource {
    pub fn slot_input(&self) -> SlotInputs {
        match self {
            TableSource::SingleValues(_) => {
                SlotInputs::Simple(SingleValuesExtractionArgs::slot_inputs())
            }
            TableSource::MappingValues(_) => {
                SlotInputs::Mapping(vec![MappingValuesExtractionArgs::slot_input()])
            }
            TableSource::SingleStruct(_) => {
                SlotInputs::Simple(SingleStructExtractionArgs::slot_inputs())
            }
            TableSource::MappingStruct(_) => {
                SlotInputs::Mapping(MappingStructExtractionArgs::slot_inputs())
            }
            // TODO: Support for mapping of mappings.
            TableSource::Merge(_) => panic!("can't call slot inputs on merge table"),
        }
    }

    pub fn init_contract_data<'a>(
        &'a mut self,
        ctx: &'a mut TestContext,
        contract: &'a Contract,
    ) -> BoxFuture<Vec<TableRowUpdate<BlockPrimaryIndex>>> {
        async move {
            match self {
                TableSource::SingleValues(ref mut s) => s.init_contract_data(ctx, contract).await,
                TableSource::MappingValues((ref mut m, _)) => {
                    m.init_contract_data(ctx, contract).await
                }
                TableSource::SingleStruct(ref mut s) => s.init_contract_data(ctx, contract).await,
                TableSource::MappingStruct((ref mut m, _)) => {
                    m.init_contract_data(ctx, contract).await
                }
                TableSource::Merge(ref mut merge) => merge.init_contract_data(ctx, contract).await,
            }
        }
        .boxed()
    }

    pub async fn generate_extraction_proof_inputs(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
        value_key: ProofKey,
    ) -> Result<(ExtractionProofInput, HashOutput)> {
        match self {
            TableSource::SingleValues(ref s) => {
                s.generate_extraction_proof_inputs(ctx, contract, value_key)
                    .await
            }
            // first lets do without length
            TableSource::MappingValues((ref m, _)) => {
                m.generate_extraction_proof_inputs(ctx, contract, value_key)
                    .await
            }
            TableSource::SingleStruct(ref s) => {
                s.generate_extraction_proof_inputs(ctx, contract, value_key)
                    .await
            }
            TableSource::MappingStruct((ref m, _)) => {
                m.generate_extraction_proof_inputs(ctx, contract, value_key)
                    .await
            }
            TableSource::Merge(ref merge) => {
                merge
                    .generate_extraction_proof_inputs(ctx, contract, value_key)
                    .await
            }
        }
    }

    pub fn random_contract_update<'a>(
        &'a mut self,
        ctx: &'a mut TestContext,
        contract: &'a Contract,
        c: ChangeType,
    ) -> BoxFuture<Vec<TableRowUpdate<BlockPrimaryIndex>>> {
        async move {
            match self {
                TableSource::SingleValues(ref s) => {
                    s.random_contract_update(ctx, contract, c).await
                }
                TableSource::MappingValues((ref mut m, _)) => {
                    m.random_contract_update(ctx, contract, c).await
                }
                TableSource::SingleStruct(ref s) => {
                    s.random_contract_update(ctx, contract, c).await
                }
                TableSource::MappingStruct((ref mut m, _)) => {
                    m.random_contract_update(ctx, contract, c).await
                }
                TableSource::Merge(ref mut merge) => {
                    merge.random_contract_update(ctx, contract, c).await
                }
            }
        }
        .boxed()
    }
}

/// Single values extraction arguments (C.1)
#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone)]
pub(crate) struct SingleValuesExtractionArgs {
    // in case of merge table, there might not be any index slot for single table
    pub(crate) index_slot: Option<u8>,
}

impl SingleValuesExtractionArgs {
    pub fn new(index_slot: Option<u8>) -> Self {
        Self { index_slot }
    }
    pub fn slot_inputs() -> Vec<SlotInput> {
        vec![
            // bool
            SlotInput::new(SINGLE_SLOTS[0], 0, 0, 256, 0),
            // uint256
            SlotInput::new(SINGLE_SLOTS[1], 0, 0, 256, 0),
            // string
            SlotInput::new(SINGLE_SLOTS[2], 0, 0, 256, 0),
            // address
            SlotInput::new(SINGLE_SLOTS[3], 0, 0, 256, 0),
        ]
    }
    pub fn table_info(contract: &Contract) -> Vec<ColumnInfo> {
        Self::slot_inputs()
            .iter()
            .map(|slot_input| {
                let id = identifier_for_value_column(
                    slot_input,
                    &contract.address,
                    contract.chain_id,
                    vec![],
                );
                ColumnInfo::new_from_slot_input(id, slot_input)
            })
            .collect_vec()
    }
    async fn init_contract_data(
        &mut self,
        ctx: &mut TestContext,
        contract: &Contract,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        let contract_update = SimpleSingleValue {
            s1: true,
            s2: U256::from(123),
            s3: "test".to_string(),
            s4: next_address(),
        };
        // since the table is not created yet, we are giving an empty table row. When making the
        // diff with the new updated contract storage, the logic will detect it's an initialization
        // phase
        let old_table_values = TableRowValues::default();
        contract
            .apply_update(ctx, &UpdateSimpleStorage::SingleValues(contract_update))
            .await
            .unwrap();
        let new_table_values = self.current_table_row_values(ctx, contract).await;
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

    pub async fn random_contract_update(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
        c: ChangeType,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        let old_table_values = self.current_table_row_values(ctx, contract).await;
        // we can take the first one since we're asking for single value and there is only
        // one row
        let old_table_values = &old_table_values[0];
        let mut current_values = contract
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

        let contract_update = UpdateSimpleStorage::SingleValues(current_values);
        contract.apply_update(ctx, &contract_update).await.unwrap();
        let new_table_values = self.current_table_row_values(ctx, contract).await;
        assert!(
            new_table_values.len() == 1,
            "there should be only a single row for single case"
        );
        old_table_values.compute_update(&new_table_values[0])
    }

    // construct a row of the table from the actual value in the contract by fetching from MPT
    async fn current_table_row_values(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
    ) -> Vec<TableRowValues<BlockPrimaryIndex>> {
        let mut secondary_cell = None;
        let mut rest_cells = Vec::new();
        for slot_input in Self::slot_inputs().iter() {
            let query = ProofQuery::new_simple_slot(contract.address, slot_input.slot() as usize);
            let id = identifier_for_value_column(
                slot_input,
                &contract.address,
                contract.chain_id,
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
            if let Some(index) = self.index_slot
                && index == slot_input.slot()
            {
                // we put 0 since we know there are no other rows with that secondary value since we are dealing
                // we single values, so only 1 row.
                secondary_cell = Some(SecondaryIndexCell::new_from(cell, 0));
            } else {
                // This is triggered for every cells that are not secondary index. If there is no
                // secondary index, then all the values will end up there.
                rest_cells.push(cell);
            }
        }
        vec![TableRowValues {
            current_cells: rest_cells,
            current_secondary: secondary_cell,
            primary: ctx.block_number().await as BlockPrimaryIndex,
        }]
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
        let single_value_proof = match ctx.storage.get_proof_exact(&proof_key) {
            Ok(p) => p,
            Err(_) => {
                let table_info = Self::table_info(contract);
                let metadata_digest = compute_leaf_single_metadata_digest::<
                    TEST_MAX_COLUMNS,
                    TEST_MAX_FIELD_PER_EVM,
                >(table_info.clone());
                let metadata_digest = metadata_digest.to_weierstrass();
                debug!("SINGLE VALUE metadata digest: {metadata_digest:?}");
                let storage_slot_info = table_info
                    .iter()
                    .map(|c| {
                        let id = c.identifier().to_canonical_u64();
                        let evm_word = c.evm_word().to_canonical_u64() as u32;
                        let slot = StorageSlot::Simple(c.slot().to_canonical_u64() as usize);
                        let metadata = MetadataGadget::new(table_info.clone(), &[id], evm_word);
                        StorageSlotInfo::new(slot, metadata, None, None)
                    })
                    .collect_vec();
                let single_values_proof = ctx
                    .prove_values_extraction(
                        &contract.address,
                        BlockNumberOrTag::Number(bn as u64),
                        &storage_slot_info,
                    )
                    .await;
                ctx.storage
                    .store_proof(proof_key, single_values_proof.clone())?;
                info!("Generated Values Extraction (C.1) proof for single variables");
                {
                    let pproof = ProofWithVK::deserialize(&single_values_proof).unwrap();
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
                single_values_proof
            }
        };
        let slot_inputs = SlotInputs::Simple(Self::slot_inputs());
        let metadata_hash = metadata_hash::<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>(
            slot_inputs,
            &contract.address,
            contract.chain_id,
            vec![],
        );
        // we're just proving a single set of a value
        let input = ExtractionProofInput::Single(ExtractionTableProof {
            dimension: TableDimension::Compound,
            value_proof: single_value_proof,
            length_proof: None,
        });
        Ok((input, metadata_hash))
    }
}

/// Mapping values extraction arguments (C.1)
#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone)]
pub(crate) struct MappingValuesExtractionArgs {
    /// Mapping index
    pub(crate) index: MappingIndex,
    /// Mapping keys: they are useful for two things:
    ///     * doing some controlled changes on the smart contract, since if we want to do an update we
    /// need to know an existing key
    ///     * doing the MPT proofs over, since this test doesn't implement the copy on write for MPT
    /// (yet), we're just recomputing all the proofs at every block and we need the keys for that.
    pub(crate) mapping_keys: Vec<Vec<u8>>,
}

impl MappingValuesExtractionArgs {
    pub fn new(index: MappingIndex) -> Self {
        Self {
            index,
            mapping_keys: vec![],
        }
    }
    pub fn slot_input() -> SlotInput {
        SlotInput::new(MAPPING_SLOT, 0, 0, 256, 0)
    }
    pub async fn init_contract_data(
        &mut self,
        ctx: &mut TestContext,
        contract: &Contract,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        let index = self.index.clone();
        let init_pair = (next_value(), next_address());
        // NOTE: here is the same address but for different mapping key (10,11)
        let pair2 = (next_value(), init_pair.1);
        let init_state = [init_pair, pair2, (next_value(), next_address())];
        // NOTE: uncomment this for simpler testing
        //let init_state = [init_pair];
        // saving the keys we are tracking in the mapping
        self.mapping_keys.extend(
            init_state
                .iter()
                .map(|u| u.0.to_be_bytes_trimmed_vec())
                .collect::<Vec<_>>(),
        );
        let mapping_updates = init_state
            .iter()
            .map(|u| MappingValuesUpdate::Insertion(u.0, u.1.into_word().into()))
            .collect::<Vec<_>>();

        contract
            .apply_update(
                ctx,
                &UpdateSimpleStorage::MappingValues(mapping_updates.clone()),
            )
            .await
            .unwrap();
        let new_block_number = ctx.block_number().await as BlockPrimaryIndex;
        self.mapping_to_table_update(new_block_number, mapping_updates, index, contract)
    }

    async fn random_contract_update(
        &mut self,
        ctx: &mut TestContext,
        contract: &Contract,
        c: ChangeType,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
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
        let idx = 0;
        let mkey = &self.mapping_keys[idx].clone();
        let index_type = self.index.clone();
        let address = &contract.address.clone();
        let query = ProofQuery::new_mapping_slot(*address, MAPPING_SLOT as usize, mkey.to_owned());
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
                vec![MappingValuesUpdate::Insertion(new_key, new_value)]
            }
            ChangeType::Deletion => {
                // NOTE: We care about the value here since that allows _us_ to pinpoint the
                // correct row in the table and delete it since for a mpping, we uniquely
                // identify row per (mapping_key,mapping_value) (in the order dictated by
                // the secondary index)
                vec![MappingValuesUpdate::Deletion(current_key, current_value)]
            }
            ChangeType::Update(u) => {
                match u {
                    // update the non-indexed column
                    UpdateType::Rest => {
                        // check which one it is and change accordingly
                        match index_type {
                            MappingIndex::Key(_) => {
                                // we simply change the mapping value since the key is the secondary index
                                vec![MappingValuesUpdate::Update(
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
                                    MappingValuesUpdate::Deletion(current_key, current_value),
                                    MappingValuesUpdate::Insertion(new_key, current_value),
                                ]
                            }
                            MappingIndex::None => {
                                // a random update of the mapping, we don't care which since it is
                                // not impacting the secondary index of the table since the mapping
                                // doesn't contain the column which is the secondary index, in case
                                // of the merge table case.
                                vec![MappingValuesUpdate::Update(
                                    current_key,
                                    current_value,
                                    new_value,
                                )]
                            }
                        }
                    }
                    UpdateType::SecondaryIndex => {
                        match index_type {
                            MappingIndex::Key(_) => {
                                // TRICKY: if the mapping key changes, it's a deletion then
                                // insertion from onchain perspective
                                vec![
                                    MappingValuesUpdate::Deletion(current_key, current_value),
                                    // we insert the same value but with a new mapping key
                                    MappingValuesUpdate::Insertion(new_key, current_value),
                                ]
                            }
                            MappingIndex::Value(_) => {
                                // if the value changes, it's a simple update in mapping
                                vec![MappingValuesUpdate::Update(
                                    current_key,
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
        for update in mapping_updates.iter() {
            match update {
                MappingValuesUpdate::Deletion(mkey, _) => {
                    info!("Removing key {} from mappping keys tracking", mkey);
                    let key_stored = mkey.to_be_bytes_trimmed_vec();
                    self.mapping_keys.retain(|u| u != &key_stored);
                }
                MappingValuesUpdate::Insertion(mkey, _) => {
                    info!("Inserting key {} to mappping keys tracking", mkey);
                    self.mapping_keys.push(mkey.to_be_bytes_trimmed_vec());
                }
                // the mapping key doesn't change here so no need to update the list
                MappingValuesUpdate::Update(_, _, _) => {}
            }
        }

        contract
            .apply_update(
                ctx,
                &UpdateSimpleStorage::MappingValues(mapping_updates.clone()),
            )
            .await
            .unwrap();
        let new_block_number = ctx.block_number().await as BlockPrimaryIndex;
        // NOTE HERE is the interesting bit for dist system as this is the logic to execute
        // on receiving updates from scapper. This only needs to have the relevant
        // information from update and it will translate that to changes in the tree.
        self.mapping_to_table_update(new_block_number, mapping_updates, index_type, contract)
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
        let slot_input = Self::slot_input();
        let key_id = identifier_for_mapping_key_column(
            MAPPING_SLOT,
            &contract.address,
            contract.chain_id,
            vec![],
        );
        let value_id =
            identifier_for_value_column(&slot_input, &contract.address, contract.chain_id, vec![]);
        let column_info = ColumnInfo::new_from_slot_input(value_id, &slot_input);
        let mapping_root_proof = match ctx.storage.get_proof_exact(&proof_key) {
            Ok(p) => p,
            Err(_) => {
                let storage_slot_info = self
                    .mapping_keys
                    .iter()
                    .map(|mapping_key| {
                        let slot = StorageSlot::Mapping(mapping_key.clone(), MAPPING_SLOT as usize);
                        let metadata =
                            MetadataGadget::new(vec![column_info.clone()], &[value_id], 0);
                        StorageSlotInfo::new(slot, metadata, Some(key_id), None)
                    })
                    .collect_vec();
                let mapping_values_proof = ctx
                    .prove_values_extraction(
                        &contract.address,
                        BlockNumberOrTag::Number(bn as u64),
                        &storage_slot_info,
                    )
                    .await;

                ctx.storage
                    .store_proof(proof_key, mapping_values_proof.clone())?;
                info!("Generated Values Extraction (C.1) proof for mapping slots");
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
                                .collect_vec(),
                        )
                    );
                }
                mapping_values_proof
            }
        };
        let metadata_hash = metadata_hash::<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>(
            SlotInputs::Mapping(vec![Self::slot_input()]),
            &contract.address,
            contract.chain_id,
            vec![],
        );
        // it's a compoound value type of proof since we're not using the length
        let input = ExtractionProofInput::Single(ExtractionTableProof {
            dimension: TableDimension::Compound,
            value_proof: mapping_root_proof,
            length_proof: None,
        });
        Ok((input, metadata_hash))
    }

    pub fn mapping_to_table_update(
        &self,
        block_number: BlockPrimaryIndex,
        updates: Vec<MappingValuesUpdate>,
        index: MappingIndex,
        contract: &Contract,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        let slot_input = Self::slot_input();
        updates
            .iter()
            .flat_map(|mapping_change| {
                match mapping_change {
                    MappingValuesUpdate::Deletion(mkey, mvalue) => {
                        // find the associated row key tree to that value
                        // HERE: there are multiple possibilities:
                        // * search for the entry at the previous block instead
                        // * passing inside the deletion the value deleted as well, so we can
                        // reconstruct the row key
                        // * or have this extra list of mapping keys
                        let entry = UniqueMappingEntry::new(mkey, mvalue);
                        vec![TableRowUpdate::Deletion(entry.to_row_key(&index))]
                    }
                    MappingValuesUpdate::Insertion(mkey, mvalue) => {
                        // we transform the mapping entry into the "table notion" of row
                        let entry = UniqueMappingEntry::new(mkey, mvalue);
                        let (cells, index) = entry.to_update(
                            block_number,
                            &index,
                            &slot_input,
                            &contract.address,
                            contract.chain_id,
                            None,
                        );
                        vec![TableRowUpdate::Insertion(cells, index)]
                    }
                    MappingValuesUpdate::Update(mkey, old_value, mvalue) => {
                        // NOTE: we need here to (a) delete current row and (b) insert new row
                        // Regardless of the change if it's on the mapping key or value, since a
                        // row is uniquely identified by its pair (key,value) then if one of those
                        // change, that means the row tree key needs to change as well, i.e. it's a
                        // deletion and addition.
                        let previous_entry = UniqueMappingEntry::new(mkey, old_value);
                        let previous_row_key = previous_entry.to_row_key(&index);
                        let new_entry = UniqueMappingEntry::new(mkey, mvalue);

                        let (mut cells, mut secondary_index) = new_entry.to_update(
                            block_number,
                            &index,
                            &slot_input,
                            &contract.address,
                            contract.chain_id,
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
            .collect::<Vec<_>>()
    }
}

#[derive(Serialize, Deserialize, Debug, Hash, Clone, PartialEq, Eq)]
pub struct MergeSource {
    // NOTE: this is a hardcore assumption currently that  table_a is single and table_b is mapping for now
    // Extending to full merge between any table is not far - it requires some quick changes in
    // circuit but quite a lot of changes in integrated test.
    pub(crate) single: SingleValuesExtractionArgs,
    pub(crate) mapping: MappingValuesExtractionArgs,
}

impl MergeSource {
    pub fn new(single: SingleValuesExtractionArgs, mapping: MappingValuesExtractionArgs) -> Self {
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
            .map(|um| {
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
                        assert_eq!(*secb,SecondaryIndexCell::default(),"no secondary index on single supported at the moment in integrated test");
                        let mut cella = cella.clone();
                        cella.updated_cells.extend(cellb.updated_cells.iter().cloned());
                        TableRowUpdate::Insertion(cella,seca.clone())
                    }
                }).collect::<Vec<_>>()
            })
            .flatten()
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
                let address = &contract.address.clone();
                // we fetch the value of all mapping entries, and
                let mut all_updates = Vec::new();
                for mk in &self.mapping.mapping_keys {
                    let query = ProofQuery::new_mapping_slot(
                        *address,
                        MAPPING_SLOT as usize,
                        mk.to_owned(),
                    );
                    let response = ctx
                        .query_mpt_proof(&query, BlockNumberOrTag::Number(ctx.block_number().await))
                        .await;
                    let current_value = response.storage_proof[0].value;
                    let current_key = U256::from_be_slice(&mk);
                    let entry = UniqueMappingEntry::new(&current_key, &current_value);
                    // create one update for each update of the first table (note again there
                    // should be only one update since it's single var)
                    all_updates.extend(rsu.iter().map(|s| {
                        let TableRowUpdate::Update(su) = s else {
                            panic!("can't have anything else than update for single table");
                        };
                        TableRowUpdate::Update(CellsUpdate {
                            // the row key doesn't change since the mapping value doesn't change
                            previous_row_key: entry.to_row_key(&self.mapping.index),
                            new_row_key: entry.to_row_key(&self.mapping.index),
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
                    .collect::<Vec<_>>()
            }
        }
    }

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
            let md = merge_metadata_hash::<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>(
                contract.address,
                contract.chain_id,
                vec![],
                TableSource::SingleValues(self.single.clone()).slot_input(),
                TableSource::MappingValues((self.mapping.clone(), None)).slot_input(),
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
pub fn next_mapping_key() -> U256 {
    next_value()
}
pub fn next_address() -> Address {
    let shift = SHIFT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(shift);
    let slice = rng.gen::<[u8; 20]>();
    Address::from_slice(&slice)
}
pub fn next_value() -> U256 {
    let shift = SHIFT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let bv: U256 = *BASE_VALUE;
    bv + U256::from(shift)
}

/// Single struct extraction arguments
#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone)]
pub(crate) struct SingleStructExtractionArgs {
    /// Metadata information
    metadata: Vec<MetadataGadget>,
}

impl SingleStructExtractionArgs {
    pub fn new(contract: &Contract) -> Self {
        let metadata = LargeStruct::metadata(
            SINGLE_STRUCT_SLOT as u8,
            contract.chain_id,
            &contract.address,
        );

        Self { metadata }
    }

    pub fn slot_inputs() -> Vec<SlotInput> {
        LargeStruct::slot_inputs(SINGLE_STRUCT_SLOT as u8)
    }

    pub fn secondary_index_slot_input() -> SlotInput {
        let mut slot_inputs = Self::slot_inputs();
        slot_inputs.remove(1)
    }

    pub fn secondary_index_identifier(contract: &Contract) -> u64 {
        identifier_for_value_column(
            &Self::secondary_index_slot_input(),
            &contract.address,
            contract.chain_id,
            vec![],
        )
    }

    pub fn rest_slot_inputs() -> Vec<SlotInput> {
        let mut slot_inputs = Self::slot_inputs();
        slot_inputs.remove(1);

        slot_inputs
    }

    async fn init_contract_data(
        &mut self,
        ctx: &mut TestContext,
        contract: &Contract,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        let contract_update = LargeStruct {
            field1: U256::from(1234),
            field2: 1,
            field3: 2,
        };
        let old_table_values = TableRowValues::default();
        contract
            .apply_update(ctx, &UpdateSimpleStorage::SingleStruct(contract_update))
            .await
            .unwrap();
        let new_table_values = self.current_table_row_values(ctx, contract).await;
        assert!(
            new_table_values.len() == 1,
            "single struct case should only have one row"
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

    pub async fn random_contract_update(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
        c: ChangeType,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        let old_table_values = self.current_table_row_values(ctx, contract).await;
        let old_table_values = &old_table_values[0];
        let mut current_struct = contract.current_single_struct(ctx).await.unwrap();
        match c {
            ChangeType::Silent => {}
            ChangeType::Deletion => {
                panic!("can't remove a single row from blockchain data over single values")
            }
            ChangeType::Insertion => {
                panic!("can't add a new row for blockchain data over single values")
            }
            ChangeType::Update(u) => match u {
                UpdateType::Rest => current_struct.field3 += 1,
                UpdateType::SecondaryIndex => current_struct.field2 += 1,
            },
        };

        let contract_update = UpdateSimpleStorage::SingleStruct(current_struct);
        contract.apply_update(ctx, &contract_update).await.unwrap();
        let new_table_values = self.current_table_row_values(ctx, contract).await;
        assert!(
            new_table_values.len() == 1,
            "there should be only a single row for single struct case"
        );
        old_table_values.compute_update(&new_table_values[0])
    }

    async fn current_table_row_values(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
    ) -> Vec<TableRowValues<BlockPrimaryIndex>> {
        let secondary_identifier = Self::secondary_index_identifier(contract);
        let mut secondary_cell = None;
        let mut rest_cells = Vec::new();
        let parent_slot = StorageSlot::Simple(SINGLE_STRUCT_SLOT);
        for metadata in &self.metadata {
            let storage_slot = StorageSlot::Node(StorageSlotNode::new_struct(
                parent_slot.clone(),
                metadata.evm_word(),
            ));
            let query = ProofQuery::new(contract.address, storage_slot);
            let value = ctx
                .query_mpt_proof(&query, BlockNumberOrTag::Number(ctx.block_number().await))
                .await
                .storage_proof[0]
                .value;
            let value_bytes = value.to_be_bytes();
            metadata
                .extracted_table_info()
                .iter()
                .for_each(|column_info| {
                    let extracted_value = extract_value(&value_bytes, column_info);
                    let extracted_value = U256::from_be_bytes(extracted_value);
                    let id = column_info.identifier().to_canonical_u64();
                    let cell =
                        Cell::new(column_info.identifier().to_canonical_u64(), extracted_value);
                    if id == secondary_identifier {
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

    pub async fn generate_extraction_proof_inputs(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
        proof_key: ProofKey,
    ) -> Result<(ExtractionProofInput, HashOutput)> {
        let ProofKey::ValueExtraction((_, bn)) = proof_key.clone() else {
            bail!("invalid proof key");
        };
        let single_struct_proof = match ctx.storage.get_proof_exact(&proof_key) {
            Ok(p) => p,
            Err(_) => {
                let parent_slot = StorageSlot::Simple(SINGLE_STRUCT_SLOT);
                let storage_slot_info = self
                    .metadata
                    .iter()
                    .map(|metadata| {
                        let storage_slot = StorageSlot::Node(StorageSlotNode::new_struct(
                            parent_slot.clone(),
                            metadata.evm_word(),
                        ));
                        StorageSlotInfo::new(storage_slot, metadata.clone(), None, None)
                    })
                    .collect_vec();
                let single_struct_proof = ctx
                    .prove_values_extraction(
                        &contract.address,
                        BlockNumberOrTag::Number(bn as u64),
                        &storage_slot_info,
                    )
                    .await;
                ctx.storage
                    .store_proof(proof_key, single_struct_proof.clone())?;
                info!("Generated Values Extraction (C.1) proof for single struct");
                {
                    let pproof = ProofWithVK::deserialize(&single_struct_proof).unwrap();
                    let pi =
                        mp2_v1::values_extraction::PublicInputs::new(&pproof.proof().public_inputs);
                    debug!(
                        "[--] SINGLE STRUCT FINAL MPT DIGEST VALUE --> {:?} ",
                        pi.values_digest()
                    );
                    debug!(
                        "[--] SINGLE STRUCT FINAL ROOT HASH --> {:?} ",
                        hex::encode(
                            pi.root_hash()
                                .into_iter()
                                .flat_map(|u| u.to_be_bytes())
                                .collect_vec()
                        )
                    );
                }
                single_struct_proof
            }
        };
        let metadata_hash = metadata_hash::<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>(
            SlotInputs::Simple(Self::slot_inputs()),
            &contract.address,
            contract.chain_id,
            vec![],
        );
        // we're just proving a single set of a value
        let input = ExtractionProofInput::Single(ExtractionTableProof {
            dimension: TableDimension::Compound,
            value_proof: single_struct_proof,
            length_proof: None,
        });
        Ok((input, metadata_hash))
    }
}

/// Mapping struct extraction arguments
#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone)]
pub(crate) struct MappingStructExtractionArgs {
    /// Mapping index type
    index: MappingIndex,
    /// Metadata information
    metadata: Vec<MetadataGadget>,
    /// Mapping keys: they are useful for two things:
    ///     * doing some controlled changes on the smart contract, since if we want to do an update we
    /// need to know an existing key
    ///     * doing the MPT proofs over, since this test doesn't implement the copy on write for MPT
    /// (yet), we're just recomputing all the proofs at every block and we need the keys for that.
    mapping_keys: Vec<Vec<u8>>,
}

impl MappingStructExtractionArgs {
    pub fn new(index: MappingIndex, contract: &Contract) -> Self {
        let metadata = LargeStruct::metadata(
            MAPPING_STRUCT_SLOT as u8,
            contract.chain_id,
            &contract.address,
        );

        Self {
            index,
            metadata,
            mapping_keys: vec![],
        }
    }

    pub fn slot_inputs() -> Vec<SlotInput> {
        LargeStruct::slot_inputs(MAPPING_STRUCT_SLOT as u8)
    }

    pub async fn init_contract_data(
        &mut self,
        ctx: &mut TestContext,
        contract: &Contract,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        let struct_value1 = LargeStruct {
            field1: U256::from(1234),
            field2: 1,
            field3: 2,
        };
        let mut struct_value2 = struct_value1.clone();
        struct_value2.field2 += 1;
        let mut struct_value3 = struct_value2.clone();
        struct_value3.field3 += 1;
        let mapping_pairs = [
            (next_value(), struct_value1),
            (next_value(), struct_value2),
            (next_value(), struct_value3),
        ];
        // Save the update mapping keys.
        self.mapping_keys.extend(
            mapping_pairs
                .iter()
                .map(|u| u.0.to_be_bytes_trimmed_vec())
                .collect_vec(),
        );
        let mapping_updates = mapping_pairs
            .into_iter()
            .map(|u| MappingStructUpdate::Insertion(u.0, u.1))
            .collect_vec();

        contract
            .apply_update(
                ctx,
                &UpdateSimpleStorage::MappingStruct(mapping_updates.clone()),
            )
            .await
            .unwrap();
        let new_block_number = ctx.block_number().await as BlockPrimaryIndex;
        self.mapping_to_table_update(new_block_number, mapping_updates, contract)
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
        // `from_mapping_to_table_update`
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
        let mkey = &self.mapping_keys[0];
        let parent_slot = StorageSlot::Mapping(mkey.clone(), MAPPING_STRUCT_SLOT);
        let mut fields = vec![];
        for metadata in &self.metadata {
            let storage_slot = StorageSlot::Node(StorageSlotNode::new_struct(
                parent_slot.clone(),
                metadata.evm_word(),
            ));
            let query = ProofQuery::new(contract.address, storage_slot);
            let value = ctx
                .query_mpt_proof(&query, BlockNumberOrTag::Number(ctx.block_number().await))
                .await
                .storage_proof[0]
                .value;

            let table_info = metadata.extracted_table_info();
            let value_bytes = value.to_be_bytes();
            table_info.iter().for_each(|column_info| {
                let bytes = extract_value(&value_bytes, column_info);
                debug!(
                    "Mapping struct extract value: column: {:?}, field = {}",
                    column_info,
                    U256::from_be_slice(&bytes),
                );

                fields.push(bytes);
            });
        }
        assert_eq!(fields.len(), LargeStruct::FIELD_NUM);
        let current_struct = LargeStruct::from(fields.as_slice());
        let current_key = U256::from_be_slice(mkey);
        let new_key = next_mapping_key();
        let new_struct = LargeStruct::new(
            current_struct.field1 + U256::from(1),
            current_struct.field2 + 1,
            current_struct.field3 + 1,
        );
        debug!("To update mapping struct: current = {current_struct:?}, new = {new_struct:?}");
        let mapping_updates = match c {
            ChangeType::Silent => vec![],
            ChangeType::Insertion => {
                vec![MappingStructUpdate::Insertion(new_key, new_struct)]
            }
            ChangeType::Deletion => {
                vec![MappingStructUpdate::Deletion(current_key, current_struct)]
            }
            ChangeType::Update(u) => {
                match u {
                    UpdateType::Rest => {
                        match self.index {
                            MappingIndex::Key(_) => {
                                // we simply change the mapping value since the key is the secondary index
                                vec![MappingStructUpdate::Update(
                                    current_key,
                                    current_struct,
                                    new_struct,
                                )]
                            }
                            MappingIndex::Value(_) => {
                                // TRICKY: in this case, the mapping key must change. But from the
                                // onchain perspective, it means a transfer mapping(old_key -> new_key,value)
                                vec![
                                    MappingStructUpdate::Deletion(
                                        current_key,
                                        current_struct.clone(),
                                    ),
                                    MappingStructUpdate::Insertion(new_key, current_struct),
                                ]
                            }
                            MappingIndex::None => {
                                // a random update of the mapping, we don't care which since it is
                                // not impacting the secondary index of the table since the mapping
                                // doesn't contain the column which is the secondary index, in case
                                // of the merge table case.
                                vec![MappingStructUpdate::Update(
                                    current_key,
                                    current_struct,
                                    new_struct,
                                )]
                            }
                        }
                    }
                    UpdateType::SecondaryIndex => {
                        match self.index {
                            MappingIndex::Key(_) => {
                                // TRICKY: if the mapping key changes, it's a deletion then
                                // insertion from onchain perspective
                                vec![
                                    MappingStructUpdate::Deletion(
                                        current_key,
                                        current_struct.clone(),
                                    ),
                                    // we insert the same value but with a new mapping key
                                    MappingStructUpdate::Insertion(new_key, current_struct),
                                ]
                            }
                            MappingIndex::Value(_) => {
                                // if the value changes, it's a simple update in mapping
                                vec![MappingStructUpdate::Update(
                                    current_key,
                                    current_struct,
                                    new_struct,
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
        for update in mapping_updates.iter() {
            match update {
                MappingStructUpdate::Deletion(mkey, _) => {
                    info!("Removing key {} from mappping keys tracking", mkey);
                    let key_stored = mkey.to_be_bytes_trimmed_vec();
                    self.mapping_keys.retain(|u| u != &key_stored);
                }
                MappingStructUpdate::Insertion(mkey, _) => {
                    info!("Inserting key {} to mappping keys tracking", mkey);
                    self.mapping_keys.push(mkey.to_be_bytes_trimmed_vec());
                }
                // the mapping key doesn't change here so no need to update the list
                MappingStructUpdate::Update(_, _, _) => {}
            }
        }

        contract
            .apply_update(
                ctx,
                &UpdateSimpleStorage::MappingStruct(mapping_updates.clone()),
            )
            .await
            .unwrap();
        let new_block_number = ctx.block_number().await as BlockPrimaryIndex;
        // NOTE HERE is the interesting bit for dist system as this is the logic to execute
        // on receiving updates from scapper. This only needs to have the relevant
        // information from update and it will translate that to changes in the tree.
        self.mapping_to_table_update(new_block_number, mapping_updates, contract)
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
        let key_id = identifier_for_mapping_key_column(
            MAPPING_STRUCT_SLOT as u8,
            &contract.address,
            contract.chain_id,
            vec![],
        );
        let mapping_root_proof = match ctx.storage.get_proof_exact(&proof_key) {
            Ok(p) => p,
            Err(_) => {
                let storage_slot_info = self
                    .metadata
                    .iter()
                    .cartesian_product(self.mapping_keys.iter())
                    .map(|(metadata, mapping_key)| {
                        let parent_slot =
                            StorageSlot::Mapping(mapping_key.clone(), MAPPING_STRUCT_SLOT);
                        let storage_slot = StorageSlot::Node(StorageSlotNode::new_struct(
                            parent_slot.clone(),
                            metadata.evm_word(),
                        ));
                        StorageSlotInfo::new(storage_slot, metadata.clone(), Some(key_id), None)
                    })
                    .collect_vec();
                let mapping_values_proof = ctx
                    .prove_values_extraction(
                        &contract.address,
                        BlockNumberOrTag::Number(bn as u64),
                        &storage_slot_info,
                    )
                    .await;
                ctx.storage
                    .store_proof(proof_key, mapping_values_proof.clone())?;
                info!("Generated Values Extraction proof for mapping struct slots");
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
        let metadata_hash = metadata_hash::<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>(
            SlotInputs::Mapping(Self::slot_inputs()),
            &contract.address,
            contract.chain_id,
            vec![],
        );
        // it's a compoound value type of proof since we're not using the length
        let input = ExtractionProofInput::Single(ExtractionTableProof {
            dimension: TableDimension::Compound,
            value_proof: mapping_root_proof,
            length_proof: None,
        });
        Ok((input, metadata_hash))
    }

    pub fn mapping_to_table_update(
        &self,
        block_number: BlockPrimaryIndex,
        updates: Vec<MappingStructUpdate>,
        contract: &Contract,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        updates
            .iter()
            .flat_map(|mapping_change| {
                match mapping_change {
                    MappingStructUpdate::Deletion(mkey, mvalue) => {
                        // find the associated row key tree to that value
                        // HERE: there are multiple possibilities:
                        // * search for the entry at the previous block instead
                        // * passing inside the deletion the value deleted as well, so we can
                        // reconstruct the row key
                        // * or have this extra list of mapping keys
                        let entry = UniqueMappingStructEntry::new(mkey, mvalue);
                        vec![TableRowUpdate::Deletion(entry.to_row_key())]
                    }
                    MappingStructUpdate::Insertion(mkey, mvalue) => {
                        // we transform the mapping entry into the "table notion" of row
                        let entry = UniqueMappingStructEntry::new(mkey, mvalue);
                        let (cells, index) = entry.to_update(block_number, contract, None);
                        debug!("Update mapping struct cells: secondary_index = {:?}, update_cell_len = {}", index, cells.updated_cells.len());
                        vec![TableRowUpdate::Insertion(cells, index)]
                    }
                    MappingStructUpdate::Update(mkey, old_value, mvalue) => {
                        // NOTE: we need here to (a) delete current row and (b) insert new row
                        // Regardless of the change if it's on the mapping key or value, since a
                        // row is uniquely identified by its pair (key,value) then if one of those
                        // change, that means the row tree key needs to change as well, i.e. it's a
                        // deletion and addition.
                        let previous_entry = UniqueMappingStructEntry::new(mkey, old_value);
                        let previous_row_key = previous_entry.to_row_key();
                        let new_entry = UniqueMappingStructEntry::new(mkey, mvalue);

                        let (mut cells, mut secondary_index) = new_entry.to_update(
                            block_number,
                            contract,
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
}
