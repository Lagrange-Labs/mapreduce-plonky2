//! The module implementing the required mechanisms for ‶Query 2″
//! https://www.notion.so/lagrangelabs/Cryptographic-Documentation-85adb821f18647b2a3dc65efbe144981?pvs=4#fa3f5d23a7724d0699a04f72bbec2a16

use plonky2::iop::target::Target;

use crate::array::Array;

mod epilogue;
mod provenance;
mod storage;

/// Length of an address (H256 = [u8; 32])
pub(crate) const ADDRESS_LEN: usize = 32;

// TODO: use 32B for address for now, see later if we prefer 20B
pub(crate) type AddressTarget = Array<Target, ADDRESS_LEN>;

// TODO: use 32B for address for now, see later if we prefer 20B
pub(crate) type Address<F> = Array<F, ADDRESS_LEN>;
