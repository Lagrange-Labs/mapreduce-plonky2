//! Custom types

use crate::array::Array;
use plonky2::{
    iop::target::Target,
    plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

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
pub type HashOutput = [u8; 32];
