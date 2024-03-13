use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::NUM_HASH_OUT_ELTS, poseidon::PoseidonHash},
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{array::Array, group_hashing::CircuitBuilderGroupHashing};

use super::{PublicInputs, STORAGE_NODE_DST};

pub struct NodeWires {}

#[derive(Clone)]
pub struct NodeCircuit {}

impl NodeCircuit {
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        inputs: [PublicInputs<Target>; 2],
    ) -> NodeWires {
        let (left_child, right_child) = (&inputs[0], &inputs[1]);
        let dst = b.constant(GoldilocksField::from_canonical_u8(STORAGE_NODE_DST));

        let digest = b.add_curve_point(&[left_child.digest(), right_child.digest()]);
        let to_hash = Array::<Target, { 1 + 2 * NUM_HASH_OUT_ELTS }>::try_from(
            std::iter::once(dst)
                .chain(left_child.root_raw().iter().copied())
                .chain(right_child.root_raw().iter().copied())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(Vec::from(to_hash.arr));

        PublicInputs::<GoldilocksField>::register(b, &root, &digest);

        NodeWires {}
    }

    pub fn assign(&self, _: &mut PartialWitness<GoldilocksField>, _: &NodeWires) {}
}
