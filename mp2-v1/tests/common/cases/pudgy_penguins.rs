//! Pudgy Penguins mainnet test case

use super::{
    ContractExtractionArgs, LengthExtractionArgs, MappingKey, MappingValuesExtractionArgs,
    SingleValuesExtractionArgs, TestCase,
};
use mp2_common::eth::{left_pad32, StorageSlot};

/// Pudgy Penguins contract address
const PUDGY_PENGUINS_ADDRESS: &str = "0xbd3531da5cf5857e7cfaa92426877b022e612cf8";

/// Test slots for single values extraction:
/// slot-0: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L23>
/// slot-1: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L26>
/// slot-8: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/extensions/ERC721Enumerable.sol#L21>
/// slot-10: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol#L21>
const SINGLE_SLOTS: [u8; 4] = [0, 1, 8, 10];

/// Test slot for mapping values extraction:
/// Extract from
/// <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol>.
/// Assume it's using ERC731Enumerable that inherits ERC721.
const MAPPING_SLOT: u8 = 2;

/// Test NFT IDs for mapping values extraction:
/// Pudgy Penguins holders <https://dune.com/queries/2450476/4027653>
/// 0x188b264aa1456b869c3a92eeed32117ebb835f47: <https://opensea.io/assets/ethereum/0xbd3531da5cf5857e7cfaa92426877b022e612cf8/1116>
/// 0x29469395eaf6f95920e59f858042f0e28d98a20b: <https://opensea.io/assets/ethereum/0xbd3531da5cf5857e7cfaa92426877b022e612cf8/1191>
/// 0x3f22fc93143790a1bd11c37c65a0a0f7e7875ea2: <https://opensea.io/assets/ethereum/0xbd3531da5cf5857e7cfaa92426877b022e612cf8/4291>
/// 0x9020974187aaccc6bd94fb3c952f029215b4fa9f: <https://opensea.io/assets/ethereum/0xbd3531da5cf5857e7cfaa92426877b022e612cf8/6960>
/// 0x4182a46c61c3ee40e61304f8b419f813eeced3b4: <https://opensea.io/assets/ethereum/0xbd3531da5cf5857e7cfaa92426877b022e612cf8/7655>
/// 0xfdd6cc8f6849e82f5e0102057fa74941024d11b6: <https://opensea.io/assets/ethereum/0xbd3531da5cf5857e7cfaa92426877b022e612cf8/8562>
const MAPPING_NFT_IDS: [u32; 6] = [1116, 1191, 4291, 6960, 7655, 8562];

/// Test slot for length extraction:
/// slot-8: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/extensions/ERC721Enumerable.sol#L21>
const LENGTH_SLOT: u8 = 8;

/// Test length value for length extraction
const LENGTH_VALUE: u8 = 0xfa;

/// Test slot for contract extraction:
/// slot-0: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L23>
const CONTRACT_SLOT: usize = 0;

impl TestCase {
    /// Create a test case for Pudgy Penguins contract.
    pub(crate) fn pudgy_penguins_test_case() -> Self {
        Self {
            contract_address: PUDGY_PENGUINS_ADDRESS.to_string(),
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

/// Convert the test NFT IDs to mapping keys.
fn test_mapping_keys() -> Vec<MappingKey> {
    MAPPING_NFT_IDS
        .iter()
        .map(|id| left_pad32(&id.to_be_bytes()).to_vec())
        .collect()
}
