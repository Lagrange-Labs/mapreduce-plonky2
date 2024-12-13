//! Mapping key, storage value types and related functions for the storage slot

use crate::common::bindings::simple::Simple::{
    mappingOfStructMappingsReturn, simpleStructReturn, structMappingReturn,
};
use alloy::primitives::{Address, U256};
use derive_more::Constructor;
use itertools::Itertools;
use log::warn;
use mp2_common::{
    eth::{StorageSlot, StorageSlotNode},
    types::MAPPING_LEAF_VALUE_LEN,
};
use mp2_v1::api::{SlotInput, SlotInputs};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::{array, fmt::Debug};

/// Abstract for the mapping key of the storage slot.
/// It could be a normal mapping key, or a pair of keys which identifies the
/// mapping of mapppings key.
pub(crate) trait StorageSlotMappingKey: Clone + Debug + PartialOrd + Ord {
    /// Generate a random key for testing.
    fn sample_key() -> Self;

    /// Construct an SlotInputs enum.
    fn slot_inputs(slot_inputs: Vec<SlotInput>) -> SlotInputs;

    /// Convert into an Uint256 vector.
    fn to_u256_vec(&self) -> Vec<U256>;

    /// Construct a storage slot for a mapping entry.
    fn storage_slot(&self, slot: u8, evm_word: u32) -> StorageSlot;
}

pub(crate) type MappingKey = U256;

impl StorageSlotMappingKey for MappingKey {
    fn sample_key() -> Self {
        sample_u256()
    }
    fn slot_inputs(slot_inputs: Vec<SlotInput>) -> SlotInputs {
        SlotInputs::Mapping(slot_inputs)
    }
    fn to_u256_vec(&self) -> Vec<U256> {
        vec![*self]
    }
    fn storage_slot(&self, slot: u8, evm_word: u32) -> StorageSlot {
        let storage_slot = StorageSlot::Mapping(self.to_be_bytes_vec(), slot as usize);
        if evm_word == 0 {
            // We could construct the mapping slot for the EVM word of 0 directly even if the
            // mapping value is a Struct, since the returned storage slot is only used to compute
            // the slot location, and it's same with the Struct mapping and the EVM word of 0.
            return storage_slot;
        }

        // It's definitely a Struct if the EVM word is non zero.
        StorageSlot::Node(StorageSlotNode::new_struct(storage_slot, evm_word))
    }
}

#[derive(
    Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Constructor,
)]
pub(crate) struct MappingOfMappingsKey {
    pub(crate) outer_key: U256,
    pub(crate) inner_key: U256,
}

impl StorageSlotMappingKey for MappingOfMappingsKey {
    fn sample_key() -> Self {
        let rng = &mut thread_rng();
        let [outer_key, inner_key] = array::from_fn(|_| U256::from_limbs(rng.gen()));
        Self::new(outer_key, inner_key)
    }
    fn slot_inputs(slot_inputs: Vec<SlotInput>) -> SlotInputs {
        SlotInputs::MappingOfMappings(slot_inputs)
    }
    fn to_u256_vec(&self) -> Vec<U256> {
        vec![self.outer_key, self.inner_key]
    }
    fn storage_slot(&self, slot: u8, evm_word: u32) -> StorageSlot {
        let storage_slot = {
            let parent_slot = StorageSlot::Mapping(self.outer_key.to_be_bytes_vec(), slot as usize);
            StorageSlot::Node(
                StorageSlotNode::new_mapping(parent_slot, self.inner_key.to_be_bytes_vec())
                    .unwrap(),
            )
        };
        if evm_word == 0 {
            // We could construct the mapping slot for the EVM word of 0 directly even if the
            // mapping value is a Struct, since the returned storage slot is only used to compute
            // the slot location, and it's same with the Struct mapping and the EVM word of 0.
            return storage_slot;
        }

        // It's definitely a Struct if the EVM word is non zero.
        StorageSlot::Node(StorageSlotNode::new_struct(storage_slot, evm_word))
    }
}

/// Abstract for the value saved in the storage slot.
/// It could be a single value as Uint256 or a Struct.
pub trait StorageSlotValue: Clone {
    /// Generate a random value for testing.
    fn sample_value() -> Self;

    /// Update the slot input specified field to a random value.
    fn random_update(&mut self, slot_input_to_update: &SlotInput);

    /// Convert from an Uint256 vector.
    fn from_u256_slice(u: &[U256]) -> Self;

    /// Convert into an Uint256 vector.
    fn to_u256_vec(&self) -> Vec<U256>;
}

impl StorageSlotValue for Address {
    fn sample_value() -> Self {
        Address::random()
    }
    fn random_update(&mut self, _: &SlotInput) {
        loop {
            let new_addr = Self::sample_value();
            if &new_addr != self {
                *self = new_addr;
                break;
            }
            warn!("Generated the same address");
        }
    }
    fn from_u256_slice(u: &[U256]) -> Self {
        assert_eq!(u.len(), 1, "Must convert from one U256");

        Address::from_slice(&u[0].to_be_bytes_trimmed_vec())
    }
    fn to_u256_vec(&self) -> Vec<U256> {
        vec![U256::from_be_slice(self.as_ref())]
    }
}

impl StorageSlotValue for U256 {
    fn sample_value() -> Self {
        sample_u256()
    }
    fn random_update(&mut self, _: &SlotInput) {
        loop {
            let new_value = Self::sample_value();
            if &new_value != self {
                *self = new_value;
                break;
            }
            warn!("Generated the same Uint256");
        }
    }
    fn from_u256_slice(u: &[U256]) -> Self {
        assert_eq!(u.len(), 1, "Should be one U256");

        u[0]
    }
    fn to_u256_vec(&self) -> Vec<U256> {
        vec![*self]
    }
}

fn sample_u256() -> U256 {
    let rng = &mut thread_rng();
    U256::from_limbs(rng.gen())
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct LargeStruct {
    pub(crate) field1: U256,
    pub(crate) field2: u128,
    pub(crate) field3: u128,
}

impl StorageSlotValue for LargeStruct {
    fn sample_value() -> Self {
        let rng = &mut thread_rng();
        let field1 = U256::from_limbs(rng.gen());
        let [field2, field3] = array::from_fn(|_| rng.gen());

        Self {
            field1,
            field2,
            field3,
        }
    }
    fn random_update(&mut self, slot_input_to_update: &SlotInput) {
        let field_index = LargeStruct::slot_inputs(slot_input_to_update.slot())
            .iter()
            .position(|slot_input| slot_input == slot_input_to_update)
            .unwrap();
        let rng = &mut thread_rng();
        let diff = rng.gen_range(1..100);
        if field_index == 0 {
            self.field1 += U256::from(diff);
        } else if field_index == 1 {
            self.field2 += diff;
        } else if field_index == 2 {
            self.field3 += diff;
        } else {
            panic!("Wrong Struct field index");
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

impl From<mappingOfStructMappingsReturn> for LargeStruct {
    fn from(res: mappingOfStructMappingsReturn) -> Self {
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
