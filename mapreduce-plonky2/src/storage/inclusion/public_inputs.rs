use plonky2::{
    field::goldilocks_field::GoldilocksField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::CurveTarget;

use crate::keccak::OutputHash;

/// Stores the public input used to prove the inclusion of a value in a *binary* merkle tree.
///
///  * R - the hash born by the current node
///  * D – the digest of the values encoutered up until R
pub struct PublicInputs<'input, FieldElt: Clone> {
    pub inputs: &'input [FieldElt],
}

impl<'a, FieldElt: Clone + Copy> PublicInputs<'a, FieldElt> {
    const EXTENSION: usize = 5;

    const ROOT_OFFSET: usize = 0;
    const ROOT_LEN: usize = 64; // 4×GL(8B) = 64B
    const DIGEST_OFFSET: usize = 4;
    const DIGEST_LEN: usize = 1;

    pub fn register(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        // TODO: Poseidon hash I assume?
        root: &OutputHash,
        digest: &CurveTarget,
    ) {
    }

    pub fn current_root() {}

    // TODO: merge with storage/mapping implementationproof_proof_ & generalize
    pub fn digest(&self) -> ([FieldElt; 5], [FieldElt; 5], FieldElt) {
        // 5 F for each coordinates + 1 bool flag
        let raw = &self.inputs[Self::DIGEST_OFFSET..Self::DIGEST_OFFSET + Self::DIGEST_LEN];
        assert!(raw.len() >= 5 * 2 + 1);
        let x = raw[0..Self::EXTENSION].try_into().unwrap();
        let y = raw[Self::EXTENSION..2 * Self::EXTENSION]
            .try_into()
            .unwrap();
        let flag = raw[2 * Self::EXTENSION];
        (x, y, flag)
    }

    pub fn root(&self) -> &[FieldElt] {
        &self.inputs[Self::ROOT_OFFSET..Self::ROOT_OFFSET + Self::ROOT_LEN]
    }
}
