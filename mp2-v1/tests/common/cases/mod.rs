//! Define test cases

use std::collections::HashMap;

use alloy::primitives::Address;
use mp2_common::{eth::StorageSlot, F};

use super::{
    proof_storage::ProofStorage,
    table::{Table, TableID},
};

pub(crate) mod local_simple;
////pub(crate) mod pudgy_penguins;

/// Storage mapping key
type MappingKey = Vec<u8>;

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
            Self::Mapping(_) => unimplemented!("mappings are coming"),
        }
    }
}

/// Test case definition
pub(crate) struct TestCase {
    pub(crate) table: Table,
    pub(crate) slots_to_id: HashMap<u8, u64>,
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
    /// Mapping keys
    pub(crate) mapping_keys: Vec<MappingKey>,
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
