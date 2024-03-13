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

/// This circuit prove the root of the subtree made of:
///   - an child whose hash has not changes on the side defined by unproved_is_left
///   - another child whose hash has been updated.
#[derive(Clone)]
pub struct PartialInnerNodeCircuit {}

impl PartialInnerNodeCircuit {
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        proved: &PublicInputs<Target>,
        unproved_hash: HashOutTarget,
        unproved_is_left: BoolTarget,
    ) -> PartialInnerNodeWires {
        let one = b.one();

        let unproved_is_left = unproved_is_left.target;
        let unproved_is_right = b.sub(one, unproved_is_left);

        // Left-hand case
        let unproved_is_left_hash = b.hash_n_to_hash_no_pad::<PoseidonHash>(
            unproved_hash
                .elements
                .iter()
                .copied()
                .chain(proved.root().elements.iter().copied())
                .collect::<Vec<_>>(),
        );

        // Right-hand case
        // b.verify_merkle_proof(leaf_data, leaf_index_bits, merkle_root, proof)
        let unproved_is_right_hash = b.hash_n_to_hash_no_pad::<PoseidonHash>(
            proved
                .root()
                .elements
                .iter()
                .copied()
                .chain(unproved_hash.elements.iter().copied())
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

        PublicInputs::<GoldilocksField>::register(b, &root, &proved.digest(), &proved.owner());
        PartialInnerNodeWires {}
    }

    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &PartialInnerNodeWires) {}
}
