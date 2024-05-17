use mp2_common::{
    keccak::PACKED_HASH_LEN,
    public_inputs::{PublicInputCommon, PublicInputRange},
    rlp::MAX_KEY_NIBBLE_LEN,
    types::{CBuilder, CURVE_TARGET_LEN},
};
use plonky2::iop::target::Target;
use plonky2_ecgfp5::gadgets::curve::CurveTarget;

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

impl<'a> PublicInputs<'a, Target> {
    /// Creates a new instance of the public inputs from its logical components.
    pub fn new(
        h: &'a [Target],
        dm: &'a CurveTarget,
        k: &'a [Target],
        t: &'a Target,
        n: &'a Target,
    ) -> Self {
        let dm_x = &dm.0 .0[0].0[..];
        let dm_y = &dm.0 .0[1].0[..];
        let dm_is_inf = &dm.0 .1.target;

        Self {
            h,
            dm: (dm_x, dm_y, dm_is_inf),
            k,
            t,
            n,
        }
    }
}

impl<'a, T> PublicInputs<'a, T> {
    /// Creates a new instance of the public inputs from a contiguous slice.
    pub fn from_slice(pi: &'a [T]) -> Self {
        Self {
            h: &pi[H_RANGE],
            dm: (
                &pi[DM_RANGE.start..DM_RANGE.start + CURVE_TARGET_LEN / 2],
                &pi[DM_RANGE.start + CURVE_TARGET_LEN / 2..DM_RANGE.end - 1],
                &pi[DM_RANGE.end - 1],
            ),
            k: &pi[K_RANGE],
            t: &pi[T_RANGE.start],
            n: &pi[N_RANGE.start],
        }
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
