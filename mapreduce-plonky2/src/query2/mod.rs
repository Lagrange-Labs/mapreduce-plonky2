//! The module implementing the required mechanisms for ‶Query 2″
//! https://www.notion.so/lagrangelabs/Cryptographic-Documentation-85adb821f18647b2a3dc65efbe144981?pvs=4#fa3f5d23a7724d0699a04f72bbec2a16

use plonky2::{field::goldilocks_field::GoldilocksField, iop::target::Target};
use plonky2_crypto::u32::arithmetic_u32::U32Target;

use crate::{array::Array, types::PACKED_ADDRESS_LEN as PACKED_SC_ADDRESS_LEN};

pub(crate) mod aggregation;
mod provenance;
mod revelation;
mod storage;
#[cfg(test)]
mod tests;

/// Length of an address (H256 = [u8; 32])
pub(crate) const ADDRESS_LEN: usize = 32;

pub(crate) const PACKED_ADDRESS_LEN: usize = ADDRESS_LEN / 4;

// TODO: use 32B for address for now, see later if we prefer 20B
pub(crate) type AddressTarget = Array<Target, ADDRESS_LEN>;

pub(crate) type PackedAddressTarget = Array<U32Target, PACKED_ADDRESS_LEN>;

// TODO: use 32B for address for now, see later if we prefer 20B
pub(crate) type Address<F> = Array<F, ADDRESS_LEN>;

pub(crate) type PackedSCAddress<F> = Array<F, PACKED_SC_ADDRESS_LEN>;

// An EWord (EVM Word) is a 256-bits/8×32B integer
pub const EWORD_LEN: usize = 8;
// Targets for an EVM word
type EWordTarget = [Target; EWORD_LEN];
// 8 Goldilocks encoding an EVM words
type EWord = [GoldilocksField; EWORD_LEN];
