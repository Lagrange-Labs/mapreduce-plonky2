//! Define test cases

use mp2_common::eth::StorageSlot;

pub(crate) mod local_simple;
pub(crate) mod pudgy_penguins;

/// Storage mapping key
type MappingKey = Vec<u8>;

/// Test case definition
#[derive(Debug)]
pub(crate) struct TestCase {
    /// Test contract address
    pub(crate) contract_address: String,
    /// Test arguments for single values extraction (C.1)
    pub(crate) values_extraction_single: SingleValuesExtractionArgs,
    /// Test arguments for mapping values extraction (C.1)
    pub(crate) values_extraction_mapping: MappingValuesExtractionArgs,
    /// Test arguments for length extraction (C.2)
    pub(crate) length_extraction: LengthExtractionArgs,
    /// Test arguments for contract extraction (C.3)
    pub(crate) contract_extraction: ContractExtractionArgs,
}

/// Single values extraction arguments (C.1)
#[derive(Debug)]
pub(crate) struct SingleValuesExtractionArgs {
    /// Simple slots
    pub(crate) slots: Vec<u8>,
}

/// Mapping values extraction arguments (C.1)
#[derive(Debug)]
pub(crate) struct MappingValuesExtractionArgs {
    /// Mapping slot number
    pub(crate) slot: u8,
    /// Mapping keys
    pub(crate) mapping_keys: Vec<MappingKey>,
}

/// Length extraction arguments (C.2)
#[derive(Debug)]
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
