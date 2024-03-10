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

// One u32 encoding the bytes for b"LEAF"
static LEAF_STR: OnceLock<GoldilocksField> = OnceLock::new();

pub struct LeafCircuit {
    key: [u8; 32],
    value: [u8; 32],
}

pub struct LeafWires {
    // in
    key: Array<Target, 32>,
    value: Array<Target, 32>,
    // out
    root: HashOutTarget,
    digest: CurveTarget,
}

impl LeafCircuit {
    pub fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> LeafWires {
        let leaf_str = b.constant(
            *LEAF_STR
                .get_or_init(|| GoldilocksField::from_canonical_u32(u32::from_be_bytes(*b"LEAF"))),
        );
        let key = Array::<Target, 32>::new(b);
        let value = Array::<Target, 32>::new(b);
        let kv = Array::<Target, 32>::try_from(
            key.arr
                .iter()
                .chain(value.arr.iter())
                .copied()
                .collect::<Vec<_>>(),
        )
        .unwrap();

        let to_hash = Array::<Target, 65>::try_from(
            std::iter::once(leaf_str)
                .chain(kv.arr.iter().copied())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let digest = b.map_to_curve_point(&kv.arr);
        let root = b.hash_or_noop::<PoseidonHash>(Vec::from(to_hash.arr));

        PublicInputs::<GoldilocksField>::register(b, &root, &digest);

        LeafWires {
            key,
            value,
            root,
            digest,
        }
    }
}
