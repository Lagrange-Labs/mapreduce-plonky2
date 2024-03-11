use std::sync::OnceLock;

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::CurveTarget;

use crate::{array::Array, circuit::UserCircuit, group_hashing::CircuitBuilderGroupHashing};

use super::{PublicInputs, LEAF_MARKER};

// A key is 32B-long
const KEY_GL_SIZE: usize = 32;
// A value in a leaf node is 32B wide
const LEAF_GL_SIZE: usize = 32;
// ['L', 'E', 'A', 'F'] -> 4B -> 1GL
const LEAF_MARKER_GL_SIZE: usize = 1;

#[derive(Clone, Debug)]
pub struct LeafCircuit {
    pub key: [u8; KEY_GL_SIZE],
    pub value: [u8; LEAF_GL_SIZE],
}

pub fn str_to_gl(s: &str) -> GoldilocksField {
    assert!(s.as_bytes().len() <= 4);
    let mut x = 0u32;
    for b in s.bytes() {
        x <<= 8;
        x |= b as u32;
    }
    GoldilocksField::from_canonical_u32(x)
}

pub struct LeafWires {
    //
    // IN
    //
    // The key leading to this leaf
    pub key: Array<Target, KEY_GL_SIZE>,
    // The value encoded in this leaf
    pub value: Array<Target, LEAF_GL_SIZE>,

    //
    // OUT
    //
    // the root of the degenerated sub-tree only containing this leaf, i.e. Poseidon("LEAF" ++ value)
    pub root: HashOutTarget,
    // the digest of " " " " " " " ", i.e. ProjectionOnCurve(value)
    pub digest: CurveTarget,
}

impl LeafCircuit {
    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &LeafWires) {
        wires.key.assign_from_data(pw, &self.key);
        wires.value.assign_from_data(pw, &self.value);
    }
}

impl UserCircuit<GoldilocksField, 2> for LeafCircuit {
    type Wires = LeafWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> LeafWires {
        let leaf_str = b.constant(LEAF_MARKER());
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
        let digest = b.map_to_curve_point(&value.arr);
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(Vec::from(to_hash.arr));

        PublicInputs::<GoldilocksField>::register(b, &root, &digest);

        LeafWires {
            key,
            value,
            root,
            digest,
        }
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        self.assign(pw, wires);
    }
}
