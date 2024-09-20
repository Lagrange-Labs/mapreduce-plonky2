use std::{assert_matches::assert_matches, str::FromStr, sync::atomic::AtomicU64};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, U256},
    providers::Provider,
};
use anyhow::Result;
use log::{debug, info};
use mp2_common::{
    digest::TableDimension,
    eth::{ProofQuery, StorageSlot},
    proof::ProofWithVK,
    types::HashOutput,
};
use mp2_v1::{
    api::{metadata_hash, SlotInputs},
    indexing::{
        block::BlockPrimaryIndex,
        cell::Cell,
        row::{RowTreeKey, ToNonce},
    },
    values_extraction::{
        identifier_for_mapping_key_column, identifier_for_mapping_value_column,
        identifier_single_var_column,
    },
};
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};

use crate::common::{
    cases::indexing::{MappingUpdate, SimpleSingleValue, TableRowValues},
    proof_storage::{ProofKey, ProofStorage},
    rowtree::SecondaryIndexCell,
    table::CellsUpdate,
    TestContext,
};

use super::{
    contract::Contract,
    indexing::{ChangeType, TableRowUpdate, UpdateSimpleStorage, UpdateType},
    TableIndexing,
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
}

impl UniqueMappingEntry {
    pub fn new(k: &U256, v: &U256) -> Self {
        Self { key: *k, value: *v }
    }
    pub fn to_update(
        &self,
        block_number: BlockPrimaryIndex,
        mapping_index: &MappingIndex,
        slot: u8,
        contract: &Address,
        chain_id: u64,
        previous_row_key: Option<RowTreeKey>,
    ) -> (CellsUpdate<BlockPrimaryIndex>, SecondaryIndexCell) {
        let row_value =
            self.to_table_row_value(block_number, mapping_index, slot, contract, chain_id);
        let cells_update = CellsUpdate {
            previous_row_key: previous_row_key.unwrap_or_default(),
            new_row_key: self.to_row_key(mapping_index),
            updated_cells: row_value.current_cells,
            primary: block_number,
        };
        let index_cell = row_value.current_secondary;
        (cells_update, index_cell)
    }

    /// Return a row given this mapping entry, depending on the chosen index
    pub fn to_table_row_value(
        &self,
        block_number: BlockPrimaryIndex,
        index: &MappingIndex,
        slot: u8,
        contract: &Address,
        chain_id: u64,
    ) -> TableRowValues<BlockPrimaryIndex> {
        // we construct the two associated cells in the table. One of them will become
        // a SecondaryIndexCell depending on the secondary index type we have chosen
        // for this mapping.
        let extract_key = MappingIndex::Key(identifier_for_mapping_key_column(
            slot,
            contract,
            chain_id,
            vec![],
        ));
        let key_cell = self.to_cell(extract_key);
        let extract_key = MappingIndex::Value(identifier_for_mapping_value_column(
            slot,
            contract,
            chain_id,
            vec![],
        ));
        let value_cell = self.to_cell(extract_key);
        // then we look at which one is must be the secondary cell
        let (secondary, rest) = match index {
            MappingIndex::Key(_) => (
                // by definition, mapping key is unique, so there is no need for a specific
                // nonce for the tree in that case
                SecondaryIndexCell::new_from(key_cell, U256::from(0)),
                value_cell,
            ),
            MappingIndex::Value(_) => {
                // Here we take the tuple (value,key) as uniquely identifying a row in the
                // table
                (SecondaryIndexCell::new_from(value_cell, self.key), key_cell)
            }
        };
        debug!(
            " --- MAPPING: to row: secondary index {:?}  -- cell {:?}",
            secondary, rest
        );
        TableRowValues {
            current_cells: vec![rest],
            current_secondary: secondary,
            primary: block_number,
        }
    }

    // using MappingIndex is a misleading name but it allows us to choose which part of the mapping
    // we want to extract
    pub fn to_cell(&self, index: MappingIndex) -> Cell {
        match index {
            MappingIndex::Key(id) => Cell::new(id, self.key),
            MappingIndex::Value(id) => Cell::new(id, self.value),
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
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Hash, Clone, PartialEq, Eq)]
pub(crate) enum TableSource {
    /// Test arguments for single values extraction (C.1)
    SingleValues(SingleValuesExtractionArgs),
    /// Test arguments for mapping values extraction (C.1)
    /// We can test with and without the length
    Mapping((MappingValuesExtractionArgs, Option<LengthExtractionArgs>)),
    Merge(MergeSource),
}

#[derive(Serialize, Deserialize, Debug, Hash, Clone, PartialEq, Eq)]
pub struct MergeSource {
    table_a: Box<TableSource>,
    table_b: Box<TableSource>,
    is_multiplier_a: bool,
}

impl MergeSource {
    pub fn new(table_a: TableSource, table_b: TableSource, is_multiplier_a: bool) -> Self {
        Self {
            table_a: Box::new(table_a),
            table_b: Box::new(table_b),
            is_multiplier_a,
        }
    }
}

pub struct ValueExtractionOutput {
    pub(crate) value_proof: Vec<u8>,
    pub(crate) table_dimension: TableDimension,
    pub(crate) length_proof: Option<Vec<u8>>,
    pub(crate) metadata_hash: HashOutput,
}

impl TableSource {
    pub fn slots(&self) -> Vec<u8> {
        match self {
            Self::SingleValues(s) => s.slots.clone(),
            Self::Mapping((mapping, len)) => {
                let mut slots = vec![mapping.slot];
                if let Some(l) = len {
                    slots.push(l.slot);
                }
                slots
            }
            Self::Merge(m) => {
                let mut a = m.table_a.slots();
                a.extend(m.table_b.slots());
                a
            }
        }
    }

    pub async fn init_contract_data(
        &mut self,
        ctx: &mut TestContext,
        contract: &Contract,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        match self {
            TableSource::SingleValues(ref mut s) => s.init_contract_data(ctx, contract).await,
            TableSource::Mapping((ref mut m, _)) => m.init_contract_data(ctx, contract).await,
            TableSource::Merge(ref m) => unimplemented!("yet"),
        }
    }

    pub async fn generate_extraction_proof(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
        proof_key: ProofKey,
    ) -> Result<ValueExtractionOutput> {
        match self {
            // first lets do without length
            TableSource::Mapping((ref mapping, _)) => {
                mapping
                    .generate_extraction_proof(ctx, contract, proof_key)
                    .await
            }
            TableSource::SingleValues(ref args) => {
                args.generate_extraction_proof(ctx, contract, proof_key)
                    .await
            }
            TableSource::Merge(ref merge) => unimplemented!("yet"),
        }
    }

    pub async fn random_contract_update(
        &mut self,
        ctx: &mut TestContext,
        contract: &Contract,
        c: ChangeType,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        match self {
            TableSource::Mapping((ref mut mapping, _)) => {
                mapping.random_contract_update(ctx, contract, c).await
            }
            TableSource::SingleValues(ref v) => v.random_contract_update(ctx, contract, c).await,
            TableSource::Merge(_) => unimplemented!("yet"),
        }
    }
}

/// Single values extraction arguments (C.1)
#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone)]
pub(crate) struct SingleValuesExtractionArgs {
    /// Simple slots
    pub(crate) slots: Vec<u8>,
    pub(crate) index_slot: u8,
}

impl SingleValuesExtractionArgs {
    async fn init_contract_data(
        &mut self,
        ctx: &mut TestContext,
        contract: &Contract,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
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
        contract
            .apply_update(ctx, &UpdateSimpleStorage::Single(contract_update))
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

        let contract_update = UpdateSimpleStorage::Single(current_values);
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
        for slot in self.slots.iter() {
            let query = ProofQuery::new_simple_slot(contract.address, *slot as usize);
            let id = identifier_single_var_column(
                *slot,
                &contract.address,
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
            if *slot == self.index_slot {
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

    pub async fn generate_extraction_proof(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
        proof_key: ProofKey,
    ) -> Result<ValueExtractionOutput> {
        let chain_id = ctx.rpc.get_chain_id().await?;

        let single_value_proof = match ctx.storage.get_proof_exact(&proof_key) {
            Ok(p) => p,
            Err(_) => {
                let single_values_proof = ctx
                    .prove_single_values_extraction(&contract.address, &self.slots)
                    .await;
                ctx.storage
                    .store_proof(proof_key, single_values_proof.clone())?;
                info!("Generated Values Extraction (C.1) proof for single variables");
                {
                    let pproof = ProofWithVK::deserialize(&single_values_proof).unwrap();
                    let pi =
                        mp2_v1::values_extraction::PublicInputs::new(&pproof.proof().public_inputs);
                    debug!("[--] FINAL MPT DIGEST VALUE --> {:?} ", pi.values_digest());
                }
                single_values_proof
            }
        };
        let slot_input = SlotInputs::Simple(self.slots.clone());
        let metadata_hash = metadata_hash(slot_input, &contract.address, chain_id, vec![]);
        // we're just proving a single set of a value
        Ok(ValueExtractionOutput {
            value_proof: single_value_proof,
            table_dimension: TableDimension::Single,
            length_proof: None,
            metadata_hash,
        })
    }
}

/// Mapping values extraction arguments (C.1)
#[derive(Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone)]
pub(crate) struct MappingValuesExtractionArgs {
    /// Mapping slot number
    pub(crate) slot: u8,
    pub(crate) index: MappingIndex,
    /// Mapping keys: they are useful for two things:
    ///     * doing some controlled changes on the smart contract, since if we want to do an update we
    /// need to know an existing key
    ///     * doing the MPT proofs over, since this test doesn't implement the copy on write for MPT
    /// (yet), we're just recomputing all the proofs at every block and we need the keys for that.
    pub(crate) mapping_keys: Vec<Vec<u8>>,
}

impl MappingValuesExtractionArgs {
    pub async fn init_contract_data(
        &mut self,
        ctx: &mut TestContext,
        contract: &Contract,
    ) -> Vec<TableRowUpdate<BlockPrimaryIndex>> {
        let index = self.index.clone();
        let slot = self.slot;
        let init_pair = (next_value(), next_address());
        // NOTE: here is the same address but for different mapping key (10,11)
        let pair2 = (next_value(), init_pair.1);
        let init_state = [init_pair, pair2, (next_value(), next_address())];
        // saving the keys we are tracking in the mapping
        self.mapping_keys.extend(
            init_state
                .iter()
                .map(|u| u.0.to_be_bytes_trimmed_vec())
                .collect::<Vec<_>>(),
        );
        let mapping_updates = init_state
            .iter()
            .map(|u| MappingUpdate::Insertion(u.0, u.1.into_word().into()))
            .collect::<Vec<_>>();

        contract
            .apply_update(ctx, &UpdateSimpleStorage::Mapping(mapping_updates.clone()))
            .await
            .unwrap();
        let new_block_number = ctx.block_number().await as BlockPrimaryIndex;
        self.mapping_to_table_update(new_block_number, mapping_updates, index, slot, contract)
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
        let slot = self.slot as usize;
        let index_type = self.index.clone();
        let address = &contract.address.clone();
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
                                vec![MappingUpdate::Update(current_key, current_value, new_value)]
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
                                vec![MappingUpdate::Update(current_key, current_value, new_value)]
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
                    self.mapping_keys.retain(|u| u != &key_stored);
                }
                MappingUpdate::Insertion(mkey, _) => {
                    info!("Inserting key {} to mappping keys tracking", mkey);
                    self.mapping_keys.push(mkey.to_be_bytes_trimmed_vec());
                }
                // the mapping key doesn't change here so no need to update the list
                MappingUpdate::Update(_, _, _) => {}
            }
        }

        contract
            .apply_update(ctx, &UpdateSimpleStorage::Mapping(mapping_updates.clone()))
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
            contract,
        )
    }

    pub async fn generate_extraction_proof(
        &self,
        ctx: &mut TestContext,
        contract: &Contract,
        proof_key: ProofKey,
    ) -> Result<ValueExtractionOutput> {
        let chain_id = ctx.rpc.get_chain_id().await?;
        let mapping_root_proof = match ctx.storage.get_proof_exact(&proof_key) {
            Ok(p) => p,
            Err(_) => {
                let mapping_values_proof = ctx
                    .prove_mapping_values_extraction(
                        &contract.address,
                        self.slot,
                        self.mapping_keys.clone(),
                    )
                    .await;

                ctx.storage
                    .store_proof(proof_key, mapping_values_proof.clone())?;
                info!("Generated Values Extraction (C.1) proof for mapping slots");
                {
                    let pproof = ProofWithVK::deserialize(&mapping_values_proof).unwrap();
                    let pi =
                        mp2_v1::values_extraction::PublicInputs::new(&pproof.proof().public_inputs);
                    debug!("[--] FINAL MPT DIGEST VALUE --> {:?} ", pi.values_digest());
                }
                mapping_values_proof
            }
        };
        let slot_input = SlotInputs::Mapping(self.slot);
        let metadata_hash = metadata_hash(slot_input, &contract.address, chain_id, vec![]);
        // it's a compoound value type of proof since we're not using the length
        Ok(ValueExtractionOutput {
            value_proof: mapping_root_proof,
            table_dimension: TableDimension::Compound,
            length_proof: None,
            metadata_hash,
        })
    }
    pub fn mapping_to_table_update(
        &self,
        block_number: BlockPrimaryIndex,
        updates: Vec<MappingUpdate>,
        index: MappingIndex,
        slot: u8,
        contract: &Contract,
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
                            &contract.address,
                            contract.chain_id,
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

use lazy_static::lazy_static;
lazy_static! {
    pub(crate) static ref BASE_VALUE: U256 = U256::from(10);
    pub static ref DEFAULT_ADDRESS: Address =
        Address::from_str("0xBA401cdAc1A3B6AEede21c9C4A483bE6c29F88C4").unwrap();
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
