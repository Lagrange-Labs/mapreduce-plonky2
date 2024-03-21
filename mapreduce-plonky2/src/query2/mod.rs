use plonky2::iop::target::Target;

use crate::array::Array;

mod provenance;
mod storage;

/// Length of an address (H256 = [u8; 32])
pub(crate) const ADDRESS_LEN: usize = 32;

// TODO: use 32B for address for now, see later if we prefer 20B
pub(crate) type AddressTarget = Array<Target, ADDRESS_LEN>;

// TODO: use 32B for address for now, see later if we prefer 20B
pub(crate) type Address<F> = Array<F, ADDRESS_LEN>;
