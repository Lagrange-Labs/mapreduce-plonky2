// Contain the mechanisms required to prove the inclusion of a Key, Value pair in the storage database.

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::poseidon::PoseidonHash,
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;

use crate::{
    array::Array,
    circuit::UserCircuit,
    group_hashing::CircuitBuilderGroupHashing,
    query2::{storage::public_inputs::PublicInputs, AddressTarget, PackedAddressTarget},
    storage::{KEY_SIZE, LEAF_SIZE}, utils::convert_u8_to_u32_slice,
};

const PACKED_KEY_SIZE: usize = KEY_SIZE/4;

pub struct InclusionWires {
    pub key: Array<U32Target, PACKED_KEY_SIZE>,
    pub value: PackedAddressTarget,
}

/// This circuit prove the new root hash of a leaf containing the requested data
#[derive(Clone)]
pub struct LeafCircuit {
    pub key: [u8; KEY_SIZE],
    pub value: [u8; AddressTarget::LEN],
}

impl LeafCircuit {
    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &InclusionWires) {
        let key_u32 = convert_u8_to_u32_slice(&self.key);
        wires.key.assign_from_data(pw, &key_u32.try_into().unwrap());
        let value_u32 = convert_u8_to_u32_slice(&self.value);
        wires.value.assign_from_data(pw, &value_u32.try_into().unwrap());
    }
}

impl UserCircuit<GoldilocksField, 2> for LeafCircuit {
    type Wires = InclusionWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let key = Array::<U32Target, PACKED_KEY_SIZE>::new(b);
        let value = PackedAddressTarget::new(b);
        let kv = key.concat(&value).to_targets();

        let digest = b.map_to_curve_point(&kv.arr);
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(Vec::from(kv.arr));

        PublicInputs::<GoldilocksField>::register(b, &root, &digest, &value);
        InclusionWires { key, value }
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        self.assign(pw, wires);
    }
}
