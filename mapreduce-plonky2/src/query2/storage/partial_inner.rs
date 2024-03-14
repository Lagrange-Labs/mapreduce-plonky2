//! Mechanism for partially-recomputed inner node, i.e. only one child proof needs to be recomputed

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::hash_types::HashOutTarget,
    iop::{
        target::{BoolTarget, Target},
        witness::PartialWitness,
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::poseidon::hash_maybe_swap;

use super::public_inputs::PublicInputs;
pub struct PartialInnerNodeWires {}

/// This circuit prove the root of the subtree made of:
///   - a child whose hash has not changes on the side defined by unproved_is_left
///   - another child whose hash has been updated.
#[derive(Clone)]
pub struct PartialInnerNodeCircuit {}

impl PartialInnerNodeCircuit {
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        proved: &PublicInputs<Target>,
        unproved_hash: HashOutTarget,
        proved_is_right: BoolTarget,
    ) -> PartialInnerNodeWires {
        let root = hash_maybe_swap(
            b,
            &[proved.root().elements, unproved_hash.elements],
            proved_is_right,
        );
        PublicInputs::<Target>::register(b, &root, &proved.digest(), &proved.owner());
        PartialInnerNodeWires {}
    }

    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &PartialInnerNodeWires) {}
}
