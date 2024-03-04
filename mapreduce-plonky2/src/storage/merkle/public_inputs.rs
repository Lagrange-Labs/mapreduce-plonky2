use crate::{
    group_hashing::N,
    keccak::OutputHash,
    utils::{convert_point_to_curve_target, transform_to_curve_point},
};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::hash_types::NUM_HASH_OUT_ELTS,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::gadgets::{
    base_field::QuinticExtensionTarget,
    curve::{CircuitBuilderEcGFp5, CurveTarget},
};
use std::array;

/// This is a wrapper around an array of targets set as public inputs of any
/// proof generated in this module. They all share the same structure.
/// `D` Digest value up to this node
/// `R` Merkle root up to this node
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T: Clone> {
    pub(crate) proof_inputs: &'a [T],
}

impl<'a> PublicInputs<'a, Target> {
    pub fn register(
        cb: &mut CircuitBuilder<GoldilocksField, 2>,
        digest: &CurveTarget,
        root_hash: &OutputHash,
    ) {
        cb.register_curve_public_input(*digest);
        root_hash.register_as_input(cb);
    }

    /// Return the curve point target of digest defined over the public inputs.
    pub fn digest(&self) -> CurveTarget {
        convert_point_to_curve_target(self.digest_data())
    }

    pub fn root_hash(&self) -> OutputHash {
        let data = self.root_hash_data();
        array::from_fn(|i| U32Target(data[i])).into()
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    pub(crate) const D_IDX: usize = 0;
    pub(crate) const R_IDX: usize = Self::D_IDX + 2 * N + 1; // 2*N+1 for curve target
    pub(crate) const TOTAL_LEN: usize = Self::R_IDX + NUM_HASH_OUT_ELTS;

    pub fn from(arr: &'a [T]) -> Self {
        Self { proof_inputs: arr }
    }

    /// Transform a list of elements to a curve point.
    pub fn digest_data(&self) -> ([T; 5], [T; 5], T) {
        transform_to_curve_point(&self.proof_inputs[Self::D_IDX..])
    }

    pub fn root_hash_data(&self) -> &[T] {
        &self.proof_inputs[Self::R_IDX..]
    }
}
