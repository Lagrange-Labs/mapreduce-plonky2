//! Define test cases

use alloy::primitives::{Address, U256};
use local_simple::TableRowValues;
use mp2_common::eth::StorageSlot;
use mp2_test::utils::random_vector;
use mp2_v1::values_extraction::{
    identifier_for_mapping_key_column, identifier_for_mapping_value_column,
};
use rand::{thread_rng, Rng};

use super::{
    celltree::Cell,
    rowtree::{RowTreeKey, SecondaryIndexCell, ToNonce},
    table::{CellsUpdate, Table},
};

pub(crate) mod local_simple;

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
enum MappingIndex {
    Key(u64),
    Value(u64),
}

impl UniqueMappingEntry {
    pub fn to_update(
        &self,
        index: &MappingIndex,
        slot: u8,
        contract: &Address,
    ) -> (CellsUpdate, SecondaryIndexCell) {
        let row_value = self.to_table_row_value(&index, slot, &contract);
        let cells_update = CellsUpdate {
            previous_row_key: Default::default(),
            new_row_key: self.to_row_key(index),
            updated_cells: row_value.current_cells,
        };
        let index_cell = row_value.current_secondary;
        (cells_update, index_cell)
    }

    /// Return a row given this mapping entry, depending on the chosen index
    pub fn to_table_row_value(
        &self,
        index: &MappingIndex,
        slot: u8,
        contract: &Address,
    ) -> TableRowValues {
        // we construct the two associated cells in the table. One of them will become
        // a SecondaryIndexCell depending on the secondary index type we have chosen
        // for this mapping.
        let extract_key = MappingIndex::Key(identifier_for_mapping_key_column(slot, &contract));
        let key_cell = self.to_cell(extract_key);
        let extract_key = MappingIndex::Key(identifier_for_mapping_value_column(slot, &contract));
        let value_cell = self.to_cell(extract_key);
        // then we look at which one is must be the secondary cell
        let (secondary, rest) = match index {
            // by definition, mapping key is unique, so there is no need for a specific
            // nonce for the tree in that case
            MappingIndex::Key(_) => (
                SecondaryIndexCell::new_from(key_cell, U256::from(0)),
                value_cell,
            ),
            // Here we take the tuple (value,key) as uniquely identifying a row in the
            // table
            MappingIndex::Value(_) => {
                (SecondaryIndexCell::new_from(value_cell, self.key), key_cell)
            }
        };
        TableRowValues {
            current_cells: vec![rest],
            current_secondary: secondary,
        }
    }

    // using MappingIndex is a misleading name but it allows us to choose which part of the mapping
    // we want to extract
    fn to_cell(&self, index: MappingIndex) -> Cell {
        match index {
            MappingIndex::Value(id) => Cell {
                id,
                value: self.value,
            },
            MappingIndex::Key(id) => Cell {
                id,
                value: self.key,
            },
        }
    }

    fn to_row_key(&self, index: &MappingIndex) -> RowTreeKey {
        match index {
            MappingIndex::Key(_) => RowTreeKey {
                value: self.key.into(),
                rest: self.value.to_nonce(),
            },
            MappingIndex::Value(_) => RowTreeKey {
                value: self.value.into(),
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
    /// * doing some controlled changes on the smart contract, since if we want to do an update we
    /// need to know an existing key
    /// * doing the MPT proofs over, since this test doesn't implement the copy on write for MPT
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

fn random_u256() -> U256 {
    let limbs = thread_rng().gen::<[u64; 4]>();
    U256::from_limbs(limbs)
}

fn random_address() -> Address {
    Address::from_slice(&random_vector(20))
}
