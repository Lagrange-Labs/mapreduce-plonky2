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
    storage::{KEY_GL_SIZE, LEAF_GL_SIZE},
};

use super::{public_inputs::PublicInputs, AddressTarget};

pub struct InclusionWires {
    pub key: Array<Target, KEY_GL_SIZE>,
    pub value: Array<Target, LEAF_GL_SIZE>,
}

/// This circuit prove the new root hash of a leaf containing the requested data
#[derive(Clone)]
pub struct LeafCircuit {
    pub key: [u8; KEY_GL_SIZE],
    pub value: [u8; AddressTarget::LEN],
}

impl LeafCircuit {
    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &InclusionWires) {
        wires.key.assign_from_data(pw, &self.key);
        wires.value.assign_from_data(pw, &self.value);
    }
}

impl UserCircuit<GoldilocksField, 2> for LeafCircuit {
    type Wires = InclusionWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let key = Array::<Target, KEY_GL_SIZE>::new(b);
        let key_u32 = key.convert_u8_to_u32(b);
        let value = Array::<Target, { AddressTarget::LEN }>::new(b);
        let value_u32 = value.convert_u8_to_u32(b);
        let kv = key_u32.concat(&value_u32).to_targets();

        let digest = b.map_to_curve_point(&kv.arr);
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(Vec::from(kv.arr));

        PublicInputs::<GoldilocksField>::register(b, &root, &digest, &value);
        InclusionWires { key, value }
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        self.assign(pw, wires);
    }
}
