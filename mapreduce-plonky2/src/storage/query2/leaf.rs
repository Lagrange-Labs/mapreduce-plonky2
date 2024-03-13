// Contain the mechanisms required to prove the inclusion of a Key, Value pair in the storage database.

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::poseidon::PoseidonHash,
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    array::Array,
    circuit::UserCircuit,
    group_hashing::CircuitBuilderGroupHashing,
    storage::{KEY_GL_SIZE, LEAF_GL_SIZE, LEAF_MARKER, LEAF_MARKER_GL_SIZE},
};

use super::{public_inputs::PublicInputs, AddressTarget};

pub struct InclusionWires {
    pub key: Array<Target, KEY_GL_SIZE>,
    pub value: Array<Target, LEAF_GL_SIZE>,
    pub owner: AddressTarget,
}

#[derive(Clone)]
pub struct InclusionCircuit {
    pub key: [u8; KEY_GL_SIZE],
    pub value: [u8; LEAF_GL_SIZE],
    pub owner: [u8; AddressTarget::LEN],
}

impl InclusionCircuit {
    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &InclusionWires) {
        wires.key.assign_from_data(pw, &self.key);
        wires.value.assign_from_data(pw, &self.value);
        wires.owner.assign_from_data(pw, &self.owner);
    }
}

impl UserCircuit<GoldilocksField, 2> for InclusionCircuit {
    type Wires = InclusionWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let leaf_str = b.constant(LEAF_MARKER());
        let owner = AddressTarget::new(b);
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

        let to_hash = Array::<
            Target,
            { LEAF_MARKER_GL_SIZE + KEY_GL_SIZE + LEAF_GL_SIZE + AddressTarget::LEN },
        >::try_from(
            std::iter::once(leaf_str)
                .chain(kv.arr.iter().copied())
                .chain(owner.arr.iter().copied())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let digest = b.map_to_curve_point(&kv.arr);
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(Vec::from(to_hash.arr));

        PublicInputs::<GoldilocksField>::register(b, &root, &digest, &owner);
        InclusionWires { key, value, owner }
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        self.assign(pw, wires);
    }
}
