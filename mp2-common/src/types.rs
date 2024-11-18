//! Custom types

use crate::{array::Array, D, F};
use anyhow::ensure;
use derive_more::Deref;
use plonky2::{
    field::extension::quintic::QuinticExtension,
    hash::hash_types::HashOut,
    iop::target::Target,
    plonk::{circuit_builder::CircuitBuilder, config::GenericHashOut},
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use serde::{Deserialize, Serialize};

/// Default field
pub type GFp = F;

/// Quintic extension field
pub type GFp5 = QuinticExtension<F>;

/// Default circuit builder
pub type CBuilder = CircuitBuilder<F, D>;

/// Length of an U64
pub const U64_LEN: usize = 8;
/// Length of an U64 in U32
pub const PACKED_U64_LEN: usize = U64_LEN / 4;
/// Length of a curve target (2x quintic + bool)
pub const CURVE_TARGET_LEN: usize = 11;
/// Byte representation of an U64
pub type U64Target = Array<Target, U64_LEN>;
/// U32 representation of an U64
pub type PackedU64Target = Array<U32Target, PACKED_U64_LEN>;

/// Length of an address (H160 = [u8; 20])
pub const ADDRESS_LEN: usize = 20;
/// Length of an address in U32
pub const PACKED_ADDRESS_LEN: usize = ADDRESS_LEN / 4;
/// Byte representation of an address
pub type AddressTarget = Array<Target, ADDRESS_LEN>;
/// U32 representation of an address
pub type PackedAddressTarget = Array<U32Target, PACKED_ADDRESS_LEN>;

/// The length of a mapping key in bytes
pub const MAPPING_KEY_LEN: usize = 32;
/// Length of a mapping key when packed in u32
pub const PACKED_MAPPING_KEY_LEN: usize = MAPPING_KEY_LEN / 4;
/// A value is never more than 32 bytes in EVM
pub const VALUE_LEN: usize = 32;
/// A compact representation of a value in U32
pub const PACKED_VALUE_LEN: usize = VALUE_LEN / 4;
/// The target for a packed value in U32
pub type PackedValueTarget = Array<U32Target, PACKED_VALUE_LEN>;
/// The target for a mapping key, 32 bytes
pub type MappingKeyTarget = Array<Target, MAPPING_KEY_LEN>;
/// The target for representing a mapping key, in packed format in u32
pub type PackedMappingKeyTarget = Array<U32Target, PACKED_MAPPING_KEY_LEN>;

/// Regular hash output function - it can be generated from field elements using
/// poseidon with the output serialized or via regular hash functions.
#[derive(Clone, Hash, Default, Debug, Serialize, Deserialize, Deref, PartialEq, Eq)]
pub struct HashOutput(pub [u8; 32]);
impl AsRef<[u8]> for &HashOutput {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Max observed is 622 but better be safe by default, it doesn't cost "more" for keccak
/// since it still has to do 5 rounds in 622 or 650.
pub const MAX_BLOCK_LEN: usize = 650;

/// This constant represents the maximum size a value can be inside the storage trie.
///
/// It is different than the `MAX_LEAF_VALUE_LEN` constant because it represents the
/// value **not** RLP encoded,i.e. without the 1-byte RLP header.
pub const MAPPING_LEAF_VALUE_LEN: usize = 32;

/// The length of an EVM word
pub const EVM_WORD_LEN: usize = 32;

impl From<[u8; 32]> for HashOutput {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl TryFrom<Vec<u8>> for HashOutput {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        ensure!(value.len() == 32, "invalid length of the vector");
        Ok(Self(value.try_into().unwrap()))
    }
}

impl<'a> From<&'a HashOutput> for &'a [u8] {
    fn from(value: &'a HashOutput) -> Self {
        value.0.as_slice()
    }
}

impl<'a> From<&'a HashOutput> for Vec<u8> {
    fn from(value: &'a HashOutput) -> Self {
        value.0.to_vec()
    }
}

impl From<HashOut<F>> for HashOutput {
    fn from(value: HashOut<F>) -> Self {
        value.to_bytes().try_into().unwrap()
    }
}

impl From<&HashOut<F>> for HashOutput {
    fn from(value: &HashOut<F>) -> Self {
        value.to_bytes().try_into().unwrap()
    }
}

impl From<HashOutput> for HashOut<F> {
    fn from(value: HashOutput) -> Self {
        Self::from_bytes(&value.0)
    }
}

impl From<&HashOutput> for HashOut<F> {
    fn from(value: &HashOutput) -> Self {
        Self::from_bytes(&value.0)
    }
}
