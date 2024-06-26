//! Test case for local Simple contract
//! Reference `test-contracts/src/Simple.sol` for the details of Simple contract.

use super::{
    super::bindings::simple::Simple::SimpleInstance, ContractExtractionArgs, LengthExtractionArgs,
    MappingKey, MappingValuesExtractionArgs, SingleValuesExtractionArgs, TestCase,
};
use alloy::{
    contract::private::{Network, Provider, Transport},
    primitives::{Address, U256},
};
use ethers::prelude::Address as EthAddress;
use mp2_common::eth::{left_pad32, StorageSlot};
use rand::{thread_rng, Rng};
use std::str::FromStr;

/// Test slots for single values extraction
const SINGLE_SLOTS: [u8; 4] = [0, 1, 2, 3];

/// Test slot for mapping values extraction
const MAPPING_SLOT: u8 = 4;

/// Test mapping addresses (keys) for mapping values extraction
const MAPPING_ADDRESSES: [&str; LENGTH_VALUE as usize] = [
    "0x3bf5733f695b2527acc7bd4c5350e57acfd9fbb5",
    "0x6cac7190535f4908d0524e7d55b3750376ea1ef7",
];

/// Test slot for length extraction
const LENGTH_SLOT: u8 = 1;

/// Test length value for length extraction
const LENGTH_VALUE: u8 = 2;

/// Test slot for contract extraction
const CONTRACT_SLOT: usize = 1;

impl TestCase {
    /// Create a test case for local Simple contract.
    pub(crate) async fn local_simple_test_case<
        T: Transport + Clone,
        P: Provider<T, N>,
        N: Network,
    >(
        contract: SimpleInstance<T, P, N>,
    ) -> Self {
        let contract_address = contract.address().to_string();

        // Call the contract function to set the test data.
        set_contract_data(contract).await;

        Self {
            contract_address,
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

/// Call the contract function to set the test data.
async fn set_contract_data<T: Transport + Clone, P: Provider<T, N>, N: Network>(
    contract: SimpleInstance<T, P, N>,
) {
    // setSimples(bool newS1, uint256 newS2, string memory newS3, address newS4)
    let b = contract.setSimples(
        true,
        U256::from(LENGTH_VALUE), // use this variable as the length slot for the mapping
        "test".to_string(),
        Address::from_str("0xb90ed61bffed1df72f2ceebd965198ad57adfcbd").unwrap(),
    );
    b.send().await.unwrap().watch().await.unwrap();

    // setMapping(address key, uint256 value)
    let mut rng = thread_rng();
    for addr in MAPPING_ADDRESSES {
        let b = contract.setMapping(
            Address::from_str(addr).unwrap(),
            U256::from(rng.gen::<u64>()),
        );
        b.send().await.unwrap().watch().await.unwrap();
    }

    // addToArray(uint256 value)
    for _ in 0..=LENGTH_VALUE {
        let b = contract.addToArray(U256::from(rng.gen::<u64>()));
        b.send().await.unwrap().watch().await.unwrap();
    }
}

/// Convert the test mapping addresses to mapping keys.
fn test_mapping_keys() -> Vec<MappingKey> {
    MAPPING_ADDRESSES
        .iter()
        .map(|address| {
            let address = EthAddress::from_str(address).unwrap();
            left_pad32(&address.to_fixed_bytes()).to_vec()
        })
        .collect()
}
