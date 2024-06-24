//! Test case for local Simple contract
//! Reference `test-contracts/src/Simple.sol` for the details of Simple contract.

use super::{
    ContractExtractionArgs, LengthExtractionArgs, MappingKey, MappingValuesExtractionArgs,
    SingleValuesExtractionArgs, TestCase,
};
use ethers::prelude::Address;
use mp2_common::eth::{left_pad32, StorageSlot};
use mp2_test::eth::get_local_rpc_url;
use std::str::FromStr;

/// Local Simple contract address
/// Must fix when updating and deploying the new Simple contract.
const LOCAL_SIMPLE_ADDRESS: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

/// Test slots for single values extraction
const SINGLE_SLOTS: [u8; 4] = [0, 1, 2, 3];

/// Test slot for mapping values extraction
const MAPPING_SLOT: u8 = 4;

/// Test mapping addresses (keys) for mapping values extraction
const MAPPING_ADDRESSES: [&str; 2] = [
    "0x3bf5733f695b2527acc7bd4c5350e57acfd9fbb5",
    "0x6cac7190535f4908d0524e7d55b3750376ea1ef7",
];

/// Test slot for length extraction
const LENGTH_SLOT: u8 = 5;

/// Test length value for length extraction
const LENGTH_VALUE: u8 = 4;

/// Test slot for contract extraction
const CONTRACT_SLOT: usize = 1;

impl TestCase {
    /// Create a test case for local Simple contract.
    pub(crate) fn local_simple_test_case() -> Self {
        Self {
            rpc_url: get_local_rpc_url(),
            contract_address: LOCAL_SIMPLE_ADDRESS.to_string(),
            values_extraction_single: SingleValuesExtractionArgs {
                slots: SINGLE_SLOTS.to_vec(),
            },
            values_extraction_mapping: MappingValuesExtractionArgs {
                slot: MAPPING_SLOT,
                mapping_keys: test_mapping_keys(),
            },
            length_extraction: LengthExtractionArgs {
                slot: LENGTH_SLOT,
                value: LENGTH_VALUE,
            },
            contract_extraction: ContractExtractionArgs {
                slot: StorageSlot::Simple(CONTRACT_SLOT),
            },
        }
    }
}

/// Convert the test mapping addresses to mapping keys.
fn test_mapping_keys() -> Vec<MappingKey> {
    MAPPING_ADDRESSES
        .iter()
        .map(|address| {
            let address = Address::from_str(address).unwrap();
            left_pad32(&address.to_fixed_bytes()).to_vec()
        })
        .collect()
}
