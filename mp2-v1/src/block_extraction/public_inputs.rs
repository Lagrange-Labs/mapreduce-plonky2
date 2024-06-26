use core::iter;
use std::array;

use mp2_common::{
    array::Array,
    keccak::{OutputHash, PACKED_HASH_LEN},
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::CBuilder,
    u256::{self, U256PubInputs, UInt256Target},
    utils::FromTargets,
};
use plonky2::iop::target::Target;
use plonky2_crypto::u32::arithmetic_u32::U32Target;

// Block extraction public inputs:
// - `BH : [8]F` packed Keccak hash of the block
// - `PREV_BH : [8]F` packed Keccak hash of the block
// - `BN : F` Proven block number
// - `SH : [8]F` Packed state root hash
const BH_RANGE: PublicInputRange = 0..PACKED_HASH_LEN;
const PREV_BH_RANGE: PublicInputRange = BH_RANGE.end..BH_RANGE.end + PACKED_HASH_LEN;
const BN_RANGE: PublicInputRange = PREV_BH_RANGE.end..PREV_BH_RANGE.end + u256::NUM_LIMBS;
const SH_RANGE: PublicInputRange = BN_RANGE.end..BN_RANGE.end + PACKED_HASH_LEN;

/// Public inputs for the dynamic-length variable extraction.
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T> {
    /// Block hash
    pub(crate) bh: &'a [T],
    /// Previous block hash
    pub(crate) prev_bh: &'a [T],
    /// Block number
    pub(crate) bn: &'a [T],
    /// Packed state root
    pub(crate) sh: &'a [T],
}

impl<'a> PublicInputCommon for PublicInputs<'a, Target> {
    const RANGES: &'static [PublicInputRange] = &[BH_RANGE, PREV_BH_RANGE, BN_RANGE, SH_RANGE];

    fn register_args(&self, cb: &mut CBuilder) {
        cb.register_public_inputs(self.bh);
        cb.register_public_inputs(self.prev_bh);
        cb.register_public_inputs(self.bn);
        cb.register_public_inputs(self.sh);
    }
}

impl<'a> PublicInputs<'a, Target> {
    /// Creates a new instance of the public inputs from its logical components.
    pub const fn new(
        bh: &'a [Target],
        prev_bh: &'a [Target],
        bn: &'a [Target],
        sh: &'a [Target],
    ) -> Self {
        assert!(bh.len() == PACKED_HASH_LEN);
        assert!(prev_bh.len() == PACKED_HASH_LEN);
        assert!(sh.len() == PACKED_HASH_LEN);
        assert!(bn.len() == u256::NUM_LIMBS);
        Self {
            bh,
            prev_bh,
            bn,
            sh,
        }
    }

    pub fn block_number(&self) -> UInt256Target {
        UInt256Target::from_targets(self.bn)
    }

    pub fn block_hash(&self) -> OutputHash {
        OutputHash::from_targets(&self.bh)
    }

    pub fn state_root(&self) -> OutputHash {
        OutputHash::from_targets(&self.sh)
    }
}

impl<'a, T: Clone> PublicInputs<'a, T> {
    /// Creates a vector from the parts of the public inputs
    pub fn to_vec(&self) -> Vec<T> {
        self.bh
            .iter()
            .chain(self.prev_bh.iter())
            .chain(self.bn.iter())
            .chain(self.sh.iter())
            .cloned()
            .collect()
    }
}

impl<'a, T> PublicInputs<'a, T> {
    /// Total length of the public inputs.
    pub const TOTAL_LEN: usize = SH_RANGE.end;

    /// Creates a new instance from its internal parts.
    pub fn from_parts(bh: &'a [T], prev_bh: &'a [T], bn: &'a [T], sh: &'a [T]) -> Self {
        assert_eq!(bh.len(), BH_RANGE.len());
        assert_eq!(prev_bh.len(), PREV_BH_RANGE.len());
        assert_eq!(sh.len(), SH_RANGE.len());

        Self {
            bh,
            prev_bh,
            bn,
            sh,
        }
    }

    /// Creates a new instance of the public inputs from a contiguous slice.
    pub fn from_slice(pi: &'a [T]) -> Self {
        Self {
            bh: &pi[BH_RANGE],
            prev_bh: &pi[PREV_BH_RANGE],
            bn: &pi[BN_RANGE],
            sh: &pi[SH_RANGE],
        }
    }

    /// Returns the block hash.
    pub const fn block_hash_raw(&self) -> &[T] {
        self.bh
    }

    /// Returns the previous block hash.
    pub const fn prev_block_hash_raw(&self) -> &[T] {
        self.prev_bh
    }

    /// Returns the block number.
    pub const fn block_number_raw(&self) -> &[T] {
        &self.bn
    }

    /// Returns the packed state root hash.
    pub const fn state_root_raw(&self) -> &[T] {
        self.sh
    }
}
