use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::poseidon::PoseidonHash,
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{array::Array, circuit::UserCircuit, group_hashing::CircuitBuilderGroupHashing};

use super::{PublicInputs, KEY_SIZE, LEAF_SIZE};

#[derive(Clone, Debug)]
pub struct LeafCircuit {
    pub key: [u8; KEY_SIZE],
    pub value: [u8; LEAF_SIZE],
}

pub struct LeafWires {
    //
    // IN
    //
    // The mapping key associated to this leaf, expected in byte format
    pub key: Array<Target, KEY_SIZE>,
    // The value encoded in this leaf, expected in byte format
    pub value: Array<Target, LEAF_SIZE>,
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
        let key = Array::<Target, KEY_SIZE>::new(b);
        let key_u32 = key.convert_u8_to_u32(b);
        let value = Array::<Target, LEAF_SIZE>::new(b);
        let value_u32 = value.convert_u8_to_u32(b);
        let kv = key_u32.concat(&value_u32).to_targets();
        let digest = b.map_to_curve_point(&kv.arr);
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(Vec::from(kv.arr));

        PublicInputs::<GoldilocksField>::register(b, &root, &digest);

        LeafWires { key, value }
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        self.assign(pw, wires);
    }
}
