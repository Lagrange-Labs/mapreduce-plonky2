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

/// Regular hash output function - it can be generated from field elements using
/// poseidon with the output serialized or via regular hash functions.
pub type HashOutput = [u8; 32];
