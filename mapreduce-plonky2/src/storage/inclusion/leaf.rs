use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::CurveTarget;

use crate::{array::Array, group_hashing::CircuitBuilderGroupHashing};

use super::PublicInputs;

pub struct LeafCircuit {
    value: [u8; 32],
}

pub struct LeafWires {
    // in
    value: Array<Target, 32>,
    // out
    root: HashOutTarget,
    digest: CurveTarget,
}

impl LeafCircuit {
    pub fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> LeafWires {
        let zero = b.zero();
        let leaf_str = GoldilocksField::from_canonical_u32(u32::from_be_bytes(*b"LEAF"));
        let value = Array::<Target, 32>::new(b);
        let leaf_str = b.constant(leaf_str);

        let to_hash = Array::<Target, 33>::try_from(
            std::iter::once(leaf_str)
                .chain(value.arr.iter().copied())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let digest = b.map_to_curve_point(&value.arr);
        let root = b.hash_or_noop::<PoseidonHash>(Vec::from(to_hash.arr));

        PublicInputs::<GoldilocksField>::register(b, &root, &digest);

        LeafWires {
            value,
            root,
            digest,
        }
    }
}
