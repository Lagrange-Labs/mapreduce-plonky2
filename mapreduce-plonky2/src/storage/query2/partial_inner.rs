//! Mechanism for partially-recomputed inner node, i.e. only one child proof needs to be recomputed

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::{BoolTarget, Target},
        witness::PartialWitness,
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{circuit::UserCircuit, storage::NODE_MARKER};

use super::public_inputs::PublicInputs;
pub struct PartialInnerNodeWires {}

#[derive(Clone)]
pub struct PartialInnerNodeCircuit {}

impl PartialInnerNodeCircuit {
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        proved_child: &PublicInputs<Target>,
        unproved_child_hash: HashOutTarget,
        unproved_child_position: BoolTarget,
    ) -> PartialInnerNodeWires {
        let leaf_str = b.constant(NODE_MARKER());
        let one = b.one();

        let unproved_is_left = unproved_child_position.target;
        let unproved_is_right = b.sub(one, unproved_is_left);

        // Left-hand case
        let unproved_is_left_hash = b.hash_n_to_hash_no_pad::<PoseidonHash>(
            std::iter::once(leaf_str)
                .chain(unproved_child_hash.elements.iter().copied())
                .chain(proved_child.root().elements.iter().copied())
                .collect::<Vec<_>>(),
        );

        // Right-hand case
        let unproved_is_right_hash = b.hash_n_to_hash_no_pad::<PoseidonHash>(
            std::iter::once(leaf_str)
                .chain(proved_child.root().elements.iter().copied())
                .chain(unproved_child_hash.elements.iter().copied())
                .collect::<Vec<_>>(),
        );

        let root = HashOutTarget::from_vec(
            unproved_is_left_hash
                .elements
                .iter()
                .zip(unproved_is_right_hash.elements.iter())
                .map(|(l, r)| {
                    let right = b.mul(unproved_is_right, *r);
                    b.mul_add(unproved_is_left, *l, right)
                })
                .collect::<Vec<_>>(),
        );

        PublicInputs::<GoldilocksField>::register(
            b,
            &root,
            &proved_child.digest(),
            &proved_child.owner(),
        );
        PartialInnerNodeWires {}
    }

    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &PartialInnerNodeWires) {}
}

impl UserCircuit<GoldilocksField, 2> for PartialInnerNodeCircuit {
    type Wires = PartialInnerNodeWires;

    fn build(
        c: &mut plonky2::plonk::circuit_builder::CircuitBuilder<GoldilocksField, 2>,
    ) -> Self::Wires {
        todo!()
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        self.assign(pw, wires);
    }
}
