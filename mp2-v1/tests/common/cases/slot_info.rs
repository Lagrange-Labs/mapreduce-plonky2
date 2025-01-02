//! Mapping key, storage value types and related functions for the storage slot

use crate::common::{
    bindings::simple::{
        self,
        Simple::{
            mappingOfStructMappingsReturn, simpleStructReturn, structMappingReturn, MappingChange,
            MappingOfSingleValueMappingsChange, MappingOfStructMappingsChange, MappingOperation,
            MappingStructChange, SimpleInstance,
        },
    },
    Deserialize, Serialize,
};
use alloy::{
    network::Network,
    primitives::{Address, U256},
    providers::Provider,
    transports::Transport,
};
use derive_more::Constructor;
use itertools::Itertools;
use log::warn;
use mp2_common::{
    eth::{StorageSlot, StorageSlotNode},
    types::MAPPING_LEAF_VALUE_LEN,
};
use mp2_v1::api::{SlotInput, SlotInputs};
use rand::{thread_rng, Rng};

use std::{array, fmt::Debug, future::Future, hash::Hash};

use super::contract::MappingUpdate;

pub(crate) trait MappingInfo: StorageSlotMappingKey {
    type Value: StorageSlotValue;
    type Call;
    fn to_call(update: &MappingUpdate<Self, Self::Value>) -> Self::Call;

    fn call_contract<T: Transport + Clone, P: Provider<T, N>, N: Network>(
        contract: &SimpleInstance<T, P, N>,
        changes: Vec<Self::Call>,
    ) -> impl Future<Output = ()> + Send;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct SimpleMapping {
    inner: U256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct StructMapping {
    inner: U256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct SimpleNestedMapping {
    outer: U256,
    inner: U256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct StructNestedMapping {
    outer: U256,
    inner: U256,
}

impl StorageSlotMappingKey for StructNestedMapping {
    type Key = U256;

    const NO_KEYS: usize = 2;

    fn sample_key() -> Self {
        let rng = &mut thread_rng();
        StructNestedMapping {
            outer: U256::from_limbs(rng.gen()),
            inner: U256::from_limbs(rng.gen()),
        }
    }

    fn slot_inputs(slot_inputs: Vec<SlotInput>, length: Option<u8>) -> SlotInputs {
        if let Some(length_slot) = length {
            SlotInputs::MappingWithLength(slot_inputs, length_slot)
        } else {
            SlotInputs::MappingOfMappings(slot_inputs)
        }
    }
    fn to_u256_vec(&self) -> Vec<U256> {
        vec![self.outer, self.inner]
    }
    fn storage_slot(&self, slot: u8, evm_word: u32) -> StorageSlot {
        let storage_slot = {
            let parent_slot = StorageSlot::Mapping(self.outer.to_be_bytes_vec(), slot as usize);
            StorageSlot::Node(
                StorageSlotNode::new_mapping(parent_slot, self.inner.to_be_bytes_vec()).unwrap(),
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

impl MappingInfo for StructNestedMapping {
    type Value = LargeStruct;
    type Call = MappingOfStructMappingsChange;
    fn to_call(update: &MappingUpdate<Self, Self::Value>) -> MappingOfStructMappingsChange {
        let op: MappingOperation = update.into();

        let (key, value) = update.to_tuple();

        MappingOfStructMappingsChange {
            outerKey: key.outer,
            innerKey: key.inner,
            field1: value.field1,
            field2: value.field2,
            field3: value.field3,
            operation: op.into(),
        }
    }

    async fn call_contract<T: Transport + Clone, P: Provider<T, N>, N: Network>(
        contract: &SimpleInstance<T, P, N>,
        changes: Vec<Self::Call>,
    ) {
        let call = contract.changeMapping_0(changes);
        call.send().await.unwrap().watch().await.unwrap();
    }
}

impl StorageSlotMappingKey for SimpleNestedMapping {
    type Key = U256;

    const NO_KEYS: usize = 2;

    fn sample_key() -> Self {
        let rng = &mut thread_rng();
        SimpleNestedMapping {
            outer: U256::from_limbs(rng.gen()),
            inner: U256::from_limbs(rng.gen()),
        }
    }

    fn slot_inputs(slot_inputs: Vec<SlotInput>, length: Option<u8>) -> SlotInputs {
        if let Some(length_slot) = length {
            SlotInputs::MappingWithLength(slot_inputs, length_slot)
        } else {
            SlotInputs::MappingOfMappings(slot_inputs)
        }
    }
    fn to_u256_vec(&self) -> Vec<U256> {
        vec![self.outer, self.inner]
    }
    fn storage_slot(&self, slot: u8, evm_word: u32) -> StorageSlot {
        let storage_slot = {
            let parent_slot = StorageSlot::Mapping(self.outer.to_be_bytes_vec(), slot as usize);
            StorageSlot::Node(
                StorageSlotNode::new_mapping(parent_slot, self.inner.to_be_bytes_vec()).unwrap(),
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

impl MappingInfo for SimpleNestedMapping {
    type Value = U256;
    type Call = MappingOfSingleValueMappingsChange;
    fn to_call(update: &MappingUpdate<Self, Self::Value>) -> MappingOfSingleValueMappingsChange {
        let op: MappingOperation = update.into();

        let (key, value) = update.to_tuple();

        MappingOfSingleValueMappingsChange {
            outerKey: key.outer,
            innerKey: key.inner,
            value,
            operation: op.into(),
        }
    }

    async fn call_contract<T: Transport + Clone, P: Provider<T, N>, N: Network>(
        contract: &SimpleInstance<T, P, N>,
        changes: Vec<Self::Call>,
    ) {
        let call = contract.changeMapping_2(changes);
        call.send().await.unwrap().watch().await.unwrap();
    }
}

impl StorageSlotMappingKey for SimpleMapping {
    type Key = U256;

    const NO_KEYS: usize = 1;

    fn sample_key() -> Self {
        SimpleMapping {
            inner: sample_u256(),
        }
    }
    fn slot_inputs(slot_inputs: Vec<SlotInput>, length: Option<u8>) -> SlotInputs {
        if let Some(length_slot) = length {
            SlotInputs::MappingWithLength(slot_inputs, length_slot)
        } else {
            SlotInputs::Mapping(slot_inputs)
        }
    }
    fn to_u256_vec(&self) -> Vec<U256> {
        vec![self.inner]
    }
    fn storage_slot(&self, slot: u8, evm_word: u32) -> StorageSlot {
        let storage_slot = StorageSlot::Mapping(self.inner.to_be_bytes_vec(), slot as usize);
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

impl MappingInfo for SimpleMapping {
    type Value = Address;
    type Call = MappingChange;

    fn to_call(update: &MappingUpdate<Self, Self::Value>) -> Self::Call {
        let op: MappingOperation = update.into();

        let (key, value) = update.to_tuple();

        MappingChange {
            key: key.inner,
            value,
            operation: op.into(),
        }
    }

    async fn call_contract<T: Transport + Clone, P: Provider<T, N>, N: Network>(
        contract: &SimpleInstance<T, P, N>,
        changes: Vec<Self::Call>,
    ) {
        let call = contract.changeMapping_1(changes);
        call.send().await.unwrap().watch().await.unwrap();
    }
}

impl StorageSlotMappingKey for StructMapping {
    type Key = U256;

    const NO_KEYS: usize = 1;

    fn sample_key() -> Self {
        StructMapping {
            inner: sample_u256(),
        }
    }
    fn slot_inputs(slot_inputs: Vec<SlotInput>, length: Option<u8>) -> SlotInputs {
        if let Some(length_slot) = length {
            SlotInputs::MappingWithLength(slot_inputs, length_slot)
        } else {
            SlotInputs::Mapping(slot_inputs)
        }
    }
    fn to_u256_vec(&self) -> Vec<U256> {
        vec![self.inner]
    }
    fn storage_slot(&self, slot: u8, evm_word: u32) -> StorageSlot {
        let storage_slot = StorageSlot::Mapping(self.inner.to_be_bytes_vec(), slot as usize);
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

impl MappingInfo for StructMapping {
    type Value = LargeStruct;
    type Call = MappingStructChange;

    fn to_call(update: &MappingUpdate<Self, Self::Value>) -> MappingStructChange {
        let op: MappingOperation = update.into();

        let (key, value) = update.to_tuple();

        MappingStructChange {
            key: key.inner,
            field1: value.field1,
            field2: value.field2,
            field3: value.field3,
            operation: op.into(),
        }
    }

    async fn call_contract<T: Transport + Clone, P: Provider<T, N>, N: Network>(
        contract: &SimpleInstance<T, P, N>,
        changes: Vec<Self::Call>,
    ) {
        let call = contract.changeMapping_3(changes);
        call.send().await.unwrap().watch().await.unwrap();
    }
}

/// Abstract for the mapping key of the storage slot.
/// It could be a normal mapping key, or a pair of keys which identifies the
/// mapping of mapppings key.
pub trait StorageSlotMappingKey: Clone + Debug + PartialOrd + Ord + Send + Sync {
    /// This is what the keys actually look like.
    type Key;

    /// How many keys there are
    const NO_KEYS: usize;

    /// Generate a random key for testing.
    fn sample_key() -> Self;

    /// Construct an SlotInputs enum.
    fn slot_inputs(slot_inputs: Vec<SlotInput>, length: Option<u8>) -> SlotInputs;

    /// Convert into an Uint256 vector.
    fn to_u256_vec(&self) -> Vec<U256>;

    /// Construct a storage slot for a mapping entry.
    fn storage_slot(&self, slot: u8, evm_word: u32) -> StorageSlot;
}

pub(crate) type MappingKey = U256;

impl StorageSlotMappingKey for MappingKey {
    type Key = U256;

    const NO_KEYS: usize = 1;

    fn sample_key() -> Self {
        sample_u256()
    }
    fn slot_inputs(slot_inputs: Vec<SlotInput>, length: Option<u8>) -> SlotInputs {
        if let Some(length_slot) = length {
            SlotInputs::MappingWithLength(slot_inputs, length_slot)
        } else {
            SlotInputs::Mapping(slot_inputs)
        }
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
    type Key = U256;

    const NO_KEYS: usize = 2;

    fn sample_key() -> Self {
        let [outer_key, inner_key] = array::from_fn(|_| MappingKey::sample_key());
        Self::new(outer_key, inner_key)
    }
    fn slot_inputs(slot_inputs: Vec<SlotInput>, length: Option<u8>) -> SlotInputs {
        if let Some(length_slot) = length {
            SlotInputs::MappingWithLength(slot_inputs, length_slot)
        } else {
            SlotInputs::MappingOfMappings(slot_inputs)
        }
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
pub trait StorageSlotValue: Clone + Send + Sync {
    /// The number of fields this value has.
    const NUM_FIELDS: usize;

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
    const NUM_FIELDS: usize = 1;

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
    const NUM_FIELDS: usize = 1;

    fn sample_value() -> Self {
        U256::from(sample_u128()) // sample as u128 to be safe for overflow in queries
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

fn sample_u128() -> u128 {
    let rng = &mut thread_rng();
    rng.gen()
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize, Copy)]
pub struct LargeStruct {
    pub(crate) field1: U256,
    pub(crate) field2: u128,
    pub(crate) field3: u128,
}

impl StorageSlotValue for LargeStruct {
    const NUM_FIELDS: usize = 3;

    fn sample_value() -> Self {
        let field1 = U256::from(sample_u128()); // sample as u128 to be safe for overflow in queries
        let [field2, field3] = array::from_fn(|_| sample_u128());

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
        assert_eq!(fields.len(), Self::NUM_FIELDS);

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

impl From<LargeStruct> for simple::Simple::LargeStruct {
    fn from(value: LargeStruct) -> Self {
        Self {
            field1: value.field1,
            field2: value.field2,
            field3: value.field3,
        }
    }
}
