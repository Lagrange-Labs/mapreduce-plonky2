//! Public inputs for Extraction Leaf/Extension/Branch circuits

use mp2_common::{
    array::Array,
    keccak::{OutputHash, PACKED_HASH_LEN},
    mpt_sequential::MPTKeyWire,
    public_inputs::{PublicInputRange, PublicInputTargets},
    rlp::MAX_KEY_NIBBLE_LEN,
    types::{CBuilder, GFp, GFp5, CURVE_TARGET_LEN},
    utils::{convert_point_to_curve_target, convert_slice_to_curve_point},
};
use plonky2::{
    field::{extension::FieldExtension, types::Field},
    iop::target::Target,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::{
    curve::curve::WeierstrassPoint,
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget},
};
use std::array::from_fn;

// Leaf/Extension/Branch node Public Inputs:
// - `H : [8]F` packed Keccak hash of the extension node
// - `K : [64]F` MPT key in nibbles (of *one* leaf under this subtree)
// - `T : F` pointer in the MPT indicating portion of the key already traversed (from 64 → 0)
// - `DV : Digest[F]` : Digest of the values accumulated in this subtree
//     - It can be an accumulation of *cell* digest or *rows* digest. The distinction is made in subsequent circuits.
// - `DM : Digest[F]` : Metadata digest (e.g. simple variable `D(identifier || slot)`)
// - `N : F` - Number of leaves extracted from this subtree
const H_RANGE: PublicInputRange = 0..PACKED_HASH_LEN;
const K_RANGE: PublicInputRange = H_RANGE.end..H_RANGE.end + MAX_KEY_NIBBLE_LEN;
const T_RANGE: PublicInputRange = K_RANGE.end..K_RANGE.end + 1;
const DV_RANGE: PublicInputRange = T_RANGE.end..T_RANGE.end + CURVE_TARGET_LEN;
const DM_RANGE: PublicInputRange = DV_RANGE.end..DV_RANGE.end + CURVE_TARGET_LEN;
const N_RANGE: PublicInputRange = DM_RANGE.end..DM_RANGE.end + 1;

/// Public inputs wrapper of any proof generated in this module
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T> {
    pub(crate) proof_inputs: &'a [T],
}

impl<'a> PublicInputTargets for PublicInputs<'a, Target> {
    const RANGES: &'static [PublicInputRange] =
        &[H_RANGE, K_RANGE, T_RANGE, DV_RANGE, DM_RANGE, N_RANGE];
}

impl<'a> PublicInputs<'a, Target> {
    pub fn register(
        cb: &mut CBuilder,
        h: &OutputHash,
        k: &MPTKeyWire,
        dv: CurveTarget,
        dm: CurveTarget,
        n: Target,
    ) {
        Self::register_with_check(
            cb,
            &[
                &|cb| h.register_as_public_input(cb),
                &|cb| k.key.register_as_public_input(cb),
                &|cb| cb.register_public_input(k.pointer),
                &|cb| cb.register_curve_public_input(dv),
                &|cb| cb.register_curve_public_input(dm),
                &|cb| cb.register_public_input(n),
            ],
        );
    }

    /// Return the merkle hash of the subtree this proof has processed.
    pub fn root_hash(&self) -> OutputHash {
        let hash = self.root_hash_info();
        Array::<U32Target, PACKED_HASH_LEN>::from_array(from_fn(|i| U32Target(hash[i])))
    }

    /// Return the MPT key defined over the public inputs.
    pub fn mpt_key(&self) -> MPTKeyWire {
        let (key, ptr) = self.mpt_key_info();
        MPTKeyWire {
            key: Array {
                arr: from_fn(|i| key[i]),
            },
            pointer: ptr,
        }
    }

    /// Return the accumulator digest defined over the public inputs.
    pub fn accumulator(&self) -> CurveTarget {
        convert_point_to_curve_target(self.accumulator_info())
    }

    /// Return the metadata digest defined over the public inputs.
    pub fn metadata(&self) -> CurveTarget {
        convert_point_to_curve_target(self.metadata_info())
    }
}

impl<'a> PublicInputs<'a, GFp> {
    /// Return the accumulator digest defined over the public inputs.
    pub fn accumulator(&self) -> WeierstrassPoint {
        let (x, y, is_inf) = self.accumulator_info();
        WeierstrassPoint {
            x: GFp5::from_basefield_array(from_fn::<GFp, 5, _>(|i| x[i])),
            y: GFp5::from_basefield_array(from_fn::<GFp, 5, _>(|i| y[i])),
            is_inf: is_inf.is_nonzero(),
        }
    }

    /// Return the merkle hash of the subtree this proof has processed.
    pub fn root_hash(&self) -> Vec<u32> {
        let hash = self.root_hash_info();
        hash.iter().map(|t| t.0 as u32).collect()
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    pub(crate) const H_RANGE: PublicInputRange = H_RANGE;
    pub(crate) const K_RANGE: PublicInputRange = K_RANGE;
    pub(crate) const T_RANGE: PublicInputRange = T_RANGE;
    pub(crate) const DV_RANGE: PublicInputRange = DV_RANGE;
    pub(crate) const DM_RANGE: PublicInputRange = DM_RANGE;
    pub(crate) const N_RANGE: PublicInputRange = N_RANGE;

    pub fn from(proof_inputs: &'a [T]) -> Self {
        Self { proof_inputs }
    }

    fn root_hash_info(&self) -> &[T] {
        &self.proof_inputs[H_RANGE]
    }

    fn accumulator_info(&self) -> ([T; 5], [T; 5], T) {
        convert_slice_to_curve_point(&self.proof_inputs[Self::DV_RANGE])
    }

    fn metadata_info(&self) -> ([T; 5], [T; 5], T) {
        convert_slice_to_curve_point(&self.proof_inputs[Self::DM_RANGE])
    }

    fn mpt_key_info(&self) -> (&[T], T) {
        let key = &self.proof_inputs[K_RANGE];
        let ptr = self.proof_inputs[T_RANGE.start];

        (key, ptr)
    }

    /// Return the number of leaves extracted from this subtree.
    pub fn n(&self) -> T {
        self.proof_inputs[Self::N_RANGE][0]
    }
}
