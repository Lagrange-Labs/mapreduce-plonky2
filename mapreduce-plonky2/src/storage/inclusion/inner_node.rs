use std::sync::OnceLock;

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::CurveTarget;

use crate::{array::Array, group_hashing::CircuitBuilderGroupHashing};

use super::PublicInputs;

pub const NUM_HASH_OUT_ELTS: usize = 4;

// One u32 encoding the bytes for b"NODE"
static NODE_STR: OnceLock<GoldilocksField> = OnceLock::new();

pub struct NodeWires {
    // in
    // children: [Vec<Target>; 2],
    // out
    root: HashOutTarget,
    digest: CurveTarget,
}

pub struct NodeCircuit {}

impl NodeCircuit {
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        inputs: [Vec<Target>; 2],
    ) -> NodeWires {
        let (left_child, right_child) = (
            PublicInputs::from(inputs[0].as_slice()),
            PublicInputs::from(inputs[1].as_slice()),
        );
        let node_str = b.constant(
            *NODE_STR
                .get_or_init(|| GoldilocksField::from_canonical_u32(u32::from_be_bytes(*b"NODE"))),
        );

        let digest = b.add_curve_point(&[left_child.digest(), right_child.digest()]);
        let to_hash = Array::<Target, { 1 + 2 * NUM_HASH_OUT_ELTS }>::try_from(
            std::iter::once(node_str)
                .chain(left_child.root().arr.iter().copied())
                .chain(right_child.root().arr.iter().copied()),
        )
        .unwrap();
        let root = b.hash_or_noop::<PoseidonHash>(Vec::from(to_hash.arr));

        PublicInputs::<GoldilocksField>::register(b, &root, &digest);

        NodeWires { root, digest }
    }
}
