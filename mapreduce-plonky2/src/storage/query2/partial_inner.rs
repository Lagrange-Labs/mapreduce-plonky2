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

use crate::{circuit::UserCircuit, storage::LEAF_MARKER};

use super::public_inputs::PublicInputs;
pub struct PartialInnerNodeWires {}

#[derive(Clone)]
pub struct PartialInnerNodeCircuit {}

impl PartialInnerNodeCircuit {
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        leaf_child: &PublicInputs<Target>,
        inner_child_hash: &HashOutTarget,
        inner_child_position: BoolTarget,
    ) -> PartialInnerNodeWires {
        let leaf_str = b.constant(LEAF_MARKER());
        let one = b.one();

        let do_left = inner_child_position.target;
        let do_right = b.sub(one, do_left);

        // Left-hand case
        let to_hash_left = std::iter::once(leaf_str)
            .chain(inner_child_hash.elements.iter().copied())
            .chain(leaf_child.root().elements.iter().copied())
            .collect::<Vec<_>>();
        let left_hash = b.hash_n_to_hash_no_pad::<PoseidonHash>(to_hash_left);
        // Right-hand case
        let to_hash_right = std::iter::once(leaf_str)
            .chain(leaf_child.root().elements.iter().copied())
            .chain(inner_child_hash.elements.iter().copied())
            .collect::<Vec<_>>();
        let right_hash = b.hash_n_to_hash_no_pad::<PoseidonHash>(to_hash_right);

        let root = HashOutTarget::from_vec(
            left_hash
                .elements
                .iter()
                .zip(right_hash.elements.iter())
                .map(|(l, r)| {
                    let right = b.mul(do_right, *r);
                    b.mul_add(do_left, *l, right)
                })
                .collect::<Vec<_>>(),
        );

        PublicInputs::<GoldilocksField>::register(
            b,
            &root,
            &leaf_child.digest(),
            &leaf_child.owner(),
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
