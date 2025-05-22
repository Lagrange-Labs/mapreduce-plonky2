use core::{array, iter};

use crate::{CBuilder, OutputHash, F as GFp};
use mp2_common::{
    array::Array,
    keccak::PACKED_HASH_LEN,
    mpt_sequential::MPTKeyWire,
    public_inputs::{PublicInputCommon, PublicInputRange},
    rlp::MAX_KEY_NIBBLE_LEN,
    types::CURVE_TARGET_LEN,
    utils::{FromFields, FromTargets},
};
use plonky2::iop::target::Target;
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::{curve::curve::WeierstrassPoint, gadgets::curve::CurveTarget};

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
    pub(crate) h: &'a [T],
    pub(crate) dm: &'a [T],
    pub(crate) k: &'a [T],
    pub(crate) t: &'a T,
    pub(crate) n: &'a T,
}

impl PublicInputCommon for PublicInputs<'_, Target> {
    const RANGES: &'static [PublicInputRange] = &[H_RANGE, DM_RANGE, K_RANGE, T_RANGE, N_RANGE];

    fn register_args(&self, cb: &mut CBuilder) {
        cb.register_public_inputs(self.h);
        cb.register_public_inputs(self.dm);
        cb.register_public_inputs(self.k);
        cb.register_public_input(*self.t);
        cb.register_public_input(*self.n);
    }
}

impl<'a> PublicInputs<'a, Target> {
    /// Creates a new instance of the public inputs from its logical components.
    pub fn new(
        h: &'a [Target],
        dm: &'a [Target],
        k: &'a [Target],
        t: &'a Target,
        n: &'a Target,
    ) -> Self {
        Self { h, dm, k, t, n }
    }

    /// MPT key wires corresponding to the slot holding the length.
    pub fn mpt_key_wire(&self) -> MPTKeyWire {
        let key = self.mpt_key();
        let pointer = *self.mpt_key_pointer();

        MPTKeyWire {
            key: Array {
                arr: array::from_fn(|i| key[i]),
            },
            pointer,
        }
    }

    pub fn root_hash(&self) -> Array<U32Target, PACKED_HASH_LEN> {
        OutputHash::from_targets(self.root_hash_raw())
    }

    /// value is RLP encoded.
    pub fn metadata_digest(&self) -> CurveTarget {
        CurveTarget::from_targets(self.dm)
    }
}

impl<T: Clone> PublicInputs<'_, T> {
    /// Creates a vector from the parts of the public inputs
    pub fn to_vec(&self) -> Vec<T> {
        self.h
            .iter()
            .chain(self.dm.iter())
            .chain(self.k.iter())
            .chain(iter::once(self.t))
            .chain(iter::once(self.n))
            .cloned()
            .collect()
    }
}

impl<'a, T> PublicInputs<'a, T> {
    /// Total length of the public inputs.
    pub const TOTAL_LEN: usize = N_RANGE.end;

    /// Creates a new instance from its internal parts.
    pub fn from_parts(h: &'a [T], dm: &'a [T], k: &'a [T], t: &'a T, n: &'a T) -> Self {
        assert_eq!(h.len(), H_RANGE.len());
        assert_eq!(dm.len(), DM_RANGE.len());
        assert_eq!(k.len(), K_RANGE.len());

        Self { h, dm, k, t, n }
    }

    /// Creates a new instance of the public inputs from a contiguous slice.
    pub fn from_slice(pi: &'a [T]) -> Self {
        Self {
            h: &pi[H_RANGE],
            dm: &pi[DM_RANGE],
            k: &pi[K_RANGE],
            t: &pi[T_RANGE.start],
            n: &pi[N_RANGE.start],
        }
    }

    /// Returns the packed block hash.
    pub const fn root_hash_raw(&self) -> &[T] {
        self.h
    }

    /// Returns the metadata digest to extract.
    ///
    /// It holds the length slot, along with other pertinent details such as whether or not the
    /// value is RLP encoded.
    pub const fn metadata(&self) -> &'a [T] {
        self.dm
    }

    /// MPT key corresponding to the slot holding the length.
    pub const fn mpt_key(&self) -> &[T] {
        self.k
    }

    /// Pointer in the MPT key.
    pub const fn mpt_key_pointer(&self) -> &T {
        self.t
    }

    /// Length of the dynamic length variable.
    pub const fn length(&self) -> &T {
        self.n
    }
}

impl PublicInputs<'_, GFp> {
    /// Creates a [WeierstrassPoint] from the metadata.
    pub fn metadata_point(&self) -> WeierstrassPoint {
        WeierstrassPoint::from_fields(self.dm)
    }
}
