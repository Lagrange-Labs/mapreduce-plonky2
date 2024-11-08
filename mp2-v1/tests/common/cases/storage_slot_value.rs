//! Value types and related functions saved in the storage slot

use crate::common::bindings::simple::Simple::{simpleStructReturn, structMappingReturn};
use alloy::primitives::{Address, U256};
use itertools::Itertools;
use mp2_common::{
    eth::{StorageSlot, StorageSlotNode},
    types::MAPPING_LEAF_VALUE_LEN,
};
use mp2_v1::api::SlotInput;
use rand::{thread_rng, Rng};
use std::array;

/// Abstract for the value saved in the storage slot.
/// It could be a single value as Uint256 or a Struct.
pub trait StorageSlotValue: Clone {
    /// Generate a random value for testing.
    fn sample() -> Self;

    /// Convert from an Uint256 vector.
    fn from_u256_slice(u: &[U256]) -> Self;

    /// Convert into an Uint256 vector.
    fn to_u256_vec(&self) -> Vec<U256>;

    /// Construct a storage slot for a mapping entry.
    fn mapping_storage_slot(slot: u8, evm_word: u32, mapping_key: Vec<u8>) -> StorageSlot;
}

impl StorageSlotValue for Address {
    fn sample() -> Self {
        Address::random()
    }
    fn from_u256_slice(u: &[U256]) -> Self {
        assert_eq!(u.len(), 1, "Must convert from one U256");

        Address::from_slice(&u[0].to_be_bytes_trimmed_vec())
    }
    fn to_u256_vec(&self) -> Vec<U256> {
        vec![U256::from_be_slice(self.as_ref())]
    }
    fn mapping_storage_slot(slot: u8, evm_word: u32, mapping_key: Vec<u8>) -> StorageSlot {
        // It should be a mapping single value slot if the value is an Uint256.
        assert_eq!(evm_word, 0);

        StorageSlot::Mapping(mapping_key, slot as usize)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct LargeStruct {
    pub(crate) field1: U256,
    pub(crate) field2: u128,
    pub(crate) field3: u128,
}

impl StorageSlotValue for LargeStruct {
    fn sample() -> Self {
        let rng = &mut thread_rng();
        let field1 = U256::from_limbs(rng.gen());
        let [field2, field3] = array::from_fn(|_| rng.gen());

        Self {
            field1,
            field2,
            field3,
        }
    }
    fn from_u256_slice(u: &[U256]) -> Self {
        assert_eq!(u.len(), 3, "Must convert from three U256 for LargeStruct");

        let field1 = u[0];
        let field2 = u[1].to();
        let field3 = u[2].to();

        Self {
            field1,
            field2,
            field3,
        }
    }
    fn to_u256_vec(&self) -> Vec<U256> {
        let [field2, field3] = [self.field2, self.field3].map(U256::from);
        vec![self.field1, field2, field3]
    }
    fn mapping_storage_slot(slot: u8, evm_word: u32, mapping_key: Vec<u8>) -> StorageSlot {
        // Check if the EVM word must be included.
        assert!(Self::slot_inputs(slot)
            .iter()
            .any(|slot_input| slot_input.evm_word() == evm_word));

        let parent_slot = StorageSlot::Mapping(mapping_key, slot as usize);
        StorageSlot::Node(StorageSlotNode::new_struct(parent_slot, evm_word))
    }
}

impl LargeStruct {
    pub const FIELD_NUM: usize = 3;

    pub fn new(field1: U256, field2: u128, field3: u128) -> Self {
        Self {
            field1,
            field2,
            field3,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.field1
            .to_be_bytes::<{ U256::BYTES }>()
            .into_iter()
            .chain(self.field2.to_be_bytes())
            .chain(self.field3.to_be_bytes())
            .collect()
    }

    pub fn slot_inputs(slot: u8) -> Vec<SlotInput> {
        vec![
            SlotInput::new(slot, 0, 256, 0),
            // Big-endian layout
            SlotInput::new(slot, 16, 128, 1),
            SlotInput::new(slot, 0, 128, 1),
        ]
    }
}

impl From<simpleStructReturn> for LargeStruct {
    fn from(res: simpleStructReturn) -> Self {
        Self {
            field1: res.field1,
            field2: res.field2,
            field3: res.field3,
        }
    }
}

impl From<structMappingReturn> for LargeStruct {
    fn from(res: structMappingReturn) -> Self {
        Self {
            field1: res.field1,
            field2: res.field2,
            field3: res.field3,
        }
    }
}

impl From<&[[u8; MAPPING_LEAF_VALUE_LEN]]> for LargeStruct {
    fn from(fields: &[[u8; MAPPING_LEAF_VALUE_LEN]]) -> Self {
        assert_eq!(fields.len(), Self::FIELD_NUM);

        let fields = fields
            .iter()
            .cloned()
            .map(U256::from_be_bytes)
            .collect_vec();

        let field1 = fields[0];
        let field2 = fields[1].to();
        let field3 = fields[2].to();
        Self {
            field1,
            field2,
            field3,
        }
    }
}
