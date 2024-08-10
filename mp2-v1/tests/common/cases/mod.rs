//! Define test cases

use alloy::primitives::{Address, U256};
use indexing::TableRowValues;
use log::debug;
use mp2_common::{
    eth::StorageSlot,
    utils::{pack_and_compute_poseidon_value, Endianness},
};
use mp2_test::utils::random_vector;
use mp2_v1::{
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
use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::{
    rowtree::SecondaryIndexCell,
    table::{CellsUpdate, Table},
};

pub mod indexing;
pub mod query;

/// The key,value such that the combination is unique. This can be turned into a RowTreeKey.
/// to store in the row tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UniqueMappingEntry {
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
        previous_row_key: Option<RowTreeKey>,
    ) -> (CellsUpdate<BlockPrimaryIndex>, SecondaryIndexCell) {
        let row_value = self.to_table_row_value(block_number, mapping_index, slot, contract);
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
    ) -> TableRowValues<BlockPrimaryIndex> {
        // we construct the two associated cells in the table. One of them will become
        // a SecondaryIndexCell depending on the secondary index type we have chosen
        // for this mapping.
        let extract_key = MappingIndex::Key(deterministic_identifier_for_mapping_key_column(
            slot, contract,
        ));
        let key_cell = self.to_cell(extract_key);
        let extract_key = MappingIndex::Value(deterministic_identifier_for_mapping_value_column(
            slot, contract,
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
    fn to_cell(&self, index: MappingIndex) -> Cell {
        match index {
            MappingIndex::Key(id) => Cell::new(id, self.key),
            MappingIndex::Value(id) => Cell::new(id, self.value),
        }
    }

    fn to_row_key(&self, index: &MappingIndex) -> RowTreeKey {
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

#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub(crate) enum TableSourceSlot {
    /// Test arguments for single values extraction (C.1)
    SingleValues(SingleValuesExtractionArgs),
    /// Test arguments for mapping values extraction (C.1)
    /// We can test with and without the length
    Mapping((MappingValuesExtractionArgs, Option<LengthExtractionArgs>)),
}

impl TableSourceSlot {
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
        }
    }
}

/// Test case definition
pub(crate) struct TestCase {
    pub(crate) table: Table,
    pub(crate) contract_address: Address,
    pub(crate) contract_extraction: ContractExtractionArgs,
    pub(crate) source: TableSourceSlot,
}

/// Single values extraction arguments (C.1)
#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub(crate) struct SingleValuesExtractionArgs {
    /// Simple slots
    pub(crate) slots: Vec<u8>,
}

/// Mapping values extraction arguments (C.1)
#[derive(Debug, Hash, Eq, PartialEq, Clone)]
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

/// Length extraction arguments (C.2)
#[derive(Debug, Hash, Eq, PartialEq, Clone)]
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

pub fn deterministic_identifier_single_var_column(slot: u8, contract_address: &Address) -> u64 {
    let mut rng = ChaCha8Rng::seed_from_u64(slot as u64);
    let deterministic = Address::from_slice(&rng.gen::<[u8; 20]>());
    identifier_single_var_column(slot, &deterministic)
}

pub fn deterministic_identifier_for_mapping_key_column(
    slot: u8,
    contract_address: &Address,
) -> u64 {
    let mut rng = ChaCha8Rng::seed_from_u64(slot as u64);
    let deterministic = Address::from_slice(&rng.gen::<[u8; 20]>());
    identifier_for_mapping_key_column(slot, &deterministic)
}

/// Calculate `value_id = Poseidon(VAL || slot || contract_address)[0]` for mapping variable leaf.
pub fn deterministic_identifier_for_mapping_value_column(
    slot: u8,
    contract_address: &Address,
) -> u64 {
    let mut rng = ChaCha8Rng::seed_from_u64(slot as u64);
    let deterministic = Address::from_slice(&rng.gen::<[u8; 20]>());
    deterministic_identifier_for_mapping_value_column(slot, &deterministic)
}
