use mp2_common::{
    keccak::PACKED_HASH_LEN,
    public_inputs::{PublicInputCommon, PublicInputRange},
    rlp::MAX_KEY_NIBBLE_LEN,
    types::{CBuilder, CURVE_TARGET_LEN},
};
use plonky2::iop::target::Target;

// Length extraction public inputs:
// - `H : [8]F` packed Keccak hash of the block
// - `DM : Digest[F]` : Metadata digest to extract
// - `K : [64]F` MPT key corresponding to the slot holding the length
// - `T : F` pointer in the MPT key
// - `N : F` length of the dynamic length variable
const H_RANGE: PublicInputRange = 0..PACKED_HASH_LEN;
const DM_RANGE: PublicInputRange = H_RANGE.end..H_RANGE.end + CURVE_TARGET_LEN;
const K_RANGE: PublicInputRange = DM_RANGE.end..DM_RANGE.end + MAX_KEY_NIBBLE_LEN;
const T_RANGE: PublicInputRange = K_RANGE.end..K_RANGE.end + 1;
const N_RANGE: PublicInputRange = T_RANGE.end..T_RANGE.end + 1;

/// Public inputs for the dynamic-length variable extraction.
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T> {
    h: &'a [T],
    dm: (&'a [T], &'a [T], &'a T),
    k: &'a [T],
    t: &'a T,
    n: &'a T,
}

impl<'a> PublicInputCommon for PublicInputs<'a, Target> {
    const RANGES: &'static [PublicInputRange] = &[H_RANGE, DM_RANGE, K_RANGE, T_RANGE, N_RANGE];

    fn register_args(&self, cb: &mut CBuilder) {
        cb.register_public_inputs(self.h);
        cb.register_public_inputs(self.dm.0);
        cb.register_public_inputs(self.dm.1);
        cb.register_public_input(*self.dm.2);
        cb.register_public_inputs(self.k);
        cb.register_public_input(*self.t);
        cb.register_public_input(*self.n);
    }
}

impl<'a, T> PublicInputs<'a, T> {
    /// Creates a new instance of the public inputs from its logical components.
    pub const fn new(
        h: &'a [T],
        dm: (&'a [T], &'a [T], &'a T),
        k: &'a [T],
        t: &'a T,
        n: &'a T,
    ) -> Self {
        Self { h, dm, k, t, n }
    }

    /// Returns the packed block hash.
    pub const fn root_hash(&self) -> &[T] {
        self.h
    }

    /// Returns the metadata digest to extract.
    ///
    /// It holds the length slot, along with other pertinent details such as whether or not the
    /// value is RLP encoded.
    pub const fn metadata(&self) -> (&'a [T], &'a [T], &'a T) {
        self.dm
    }

    /// MPT key corresponding to the slot holding the length.
    pub const fn mpt_key(&self) -> &[T] {
        self.k
    }

    /// Pointer in the MPT key.
    pub const fn mpt_key_pointer(&self) -> &T {
        &self.t
    }

    /// Length of the dynamic length variable.
    pub const fn length(&self) -> &T {
        &self.n
    }
}
