//! Define test cases

use alloy::primitives::Address;
use mp2_common::eth::StorageSlot;

use super::{proof_storage::ProofStorage, table::TableID};

pub(crate) mod local_simple;
pub(crate) mod pudgy_penguins;

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

/// Test case definition
#[derive(Debug)]
pub(crate) struct TestCase {
    pub(crate) contract_address: Address,
    pub(crate) contract_extraction: ContractExtractionArgs,
    pub(crate) source: TableSourceSlot,
}

impl TestCase {
    pub fn table_id(&self) -> TableID {
        let slots = match self.source {
            TableSourceSlot::SingleValues(ref s) => s.slots.clone(),
            TableSourceSlot::Mapping((ref map, ref length)) => {
                let mut slots = vec![map.slot];
                if let Some(l) = length {
                    slots.push(l.slot);
                }
                slots
            }
        };
        TableID::new(&self.contract_address, &slots)
    }
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
