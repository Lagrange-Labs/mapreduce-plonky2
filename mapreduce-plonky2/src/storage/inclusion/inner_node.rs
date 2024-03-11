use std::sync::OnceLock;

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{HashOutTarget, NUM_HASH_OUT_ELTS},
        poseidon::PoseidonHash,
    },
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::CurveTarget;

use crate::{array::Array, group_hashing::CircuitBuilderGroupHashing};

use super::PublicInputs;

// One u32 encoding the bytes for b"NODE"
static NODE_STR: OnceLock<GoldilocksField> = OnceLock::new();
// ['N', 'O', 'D', 'E'] -> 4B -> 1GL
const LEAF_MARKER_GL_SIZE: usize = 1;

pub struct NodeWires {
    //
    // IN
    //
    // the children proof of this inner node
    // children: [&[Target]; 2],

    //
    // OUT
    //
    // the root of the subtree up to this level, i.e. Poseidon("NODE" ++ child[0].root ++ child[1].root)
    root: HashOutTarget,
    // the digest " " " " " " ", i.e. child[0].digest + child[1].digest
    digest: CurveTarget,
}

pub struct NodeCircuit {}

impl NodeCircuit {
    pub fn build(b: &mut CircuitBuilder<GoldilocksField, 2>, inputs: [&[Target]; 2]) -> NodeWires {
        let (left_child, right_child) =
            (PublicInputs::from(inputs[0]), PublicInputs::from(inputs[1]));
        let node_str = b.constant(
            *NODE_STR
                .get_or_init(|| GoldilocksField::from_canonical_u32(u32::from_be_bytes(*b"NODE"))),
        );

        let digest = b.add_curve_point(&[left_child.digest(), right_child.digest()]);
        let to_hash = Array::<Target, { LEAF_MARKER_GL_SIZE + 2 * NUM_HASH_OUT_ELTS }>::try_from(
            std::iter::once(node_str)
                .chain(left_child.root().elements.iter().copied())
                .chain(right_child.root().elements.iter().copied())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(Vec::from(to_hash.arr));

        PublicInputs::<GoldilocksField>::register(b, &root, &digest);

        NodeWires { root, digest }
    }
}
