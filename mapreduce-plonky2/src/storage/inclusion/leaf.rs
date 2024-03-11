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

// A key is 32B-long
// TODO: upgrade from 1B/GL to 4B/GL
const KEY_GL_SIZE: usize = 32;
// A value in a leaf node is 32B wide
// TODO: upgrade from 1B/GL to 4B/GL
const LEAF_GL_SIZE: usize = 32;
// One u32 encoding the bytes for b"LEAF"
static LEAF_STR: OnceLock<GoldilocksField> = OnceLock::new();
// ['L', 'E', 'A', 'F'] -> 4B -> 1GL
const LEAF_MARKER_GL_SIZE: usize = 1;

pub struct LeafCircuit {
    key: [u8; KEY_GL_SIZE],
    value: [u8; LEAF_GL_SIZE],
}

pub struct LeafWires {
    //
    // IN
    //
    // The key leading to this leaf
    key: Array<Target, KEY_GL_SIZE>,
    // The value encoded in this leaf
    value: Array<Target, LEAF_GL_SIZE>,

    //
    // OUT
    //
    // the root of the degenerated sub-tree only containing this leaf, i.e. Poseidon("LEAF" ++ value)
    root: HashOutTarget,
    // the digest of " " " " " " " ", i.e. ProjectionOnCurve(value)
    digest: CurveTarget,
}

impl LeafCircuit {
    pub fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> LeafWires {
        let leaf_str = b.constant(
            *LEAF_STR
                .get_or_init(|| GoldilocksField::from_canonical_u32(u32::from_be_bytes(*b"LEAF"))),
        );
        let key = Array::<Target, KEY_GL_SIZE>::new(b);
        let value = Array::<Target, LEAF_GL_SIZE>::new(b);
        let kv = Array::<Target, { KEY_GL_SIZE + LEAF_GL_SIZE }>::try_from(
            key.arr
                .iter()
                .chain(value.arr.iter())
                .copied()
                .collect::<Vec<_>>(),
        )
        .unwrap();

        let to_hash =
            Array::<Target, { LEAF_MARKER_GL_SIZE + KEY_GL_SIZE + LEAF_GL_SIZE }>::try_from(
                std::iter::once(leaf_str)
                    .chain(kv.arr.iter().copied())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let digest = b.map_to_curve_point(&kv.arr);
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(Vec::from(to_hash.arr));

        PublicInputs::<GoldilocksField>::register(b, &root, &digest);

        LeafWires {
            key,
            value,
            root,
            digest,
        }
    }
}
