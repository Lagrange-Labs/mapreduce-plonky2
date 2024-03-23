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
    types::{MAPPING_KEY_LEN, VALUE_LEN},
    utils::convert_u8_to_u32_slice,
};

const PACKED_KEY_SIZE: usize = MAPPING_KEY_LEN / 4;

pub struct InclusionWires {
    pub mapping_key: Array<Target, MAPPING_KEY_LEN>,
    pub mapping_value: Array<Target, VALUE_LEN>,
}

/// This circuit prove the new root hash of a leaf containing the requested data
#[derive(Clone, Debug)]
pub struct LeafCircuit {
    pub mapping_key: [u8; MAPPING_KEY_LEN],
    pub mapping_value: [u8; VALUE_LEN],
}

impl LeafCircuit {
    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &InclusionWires) {
        wires.mapping_key.assign_from_data(pw, &self.mapping_key);
        wires
            .mapping_value
            .assign_from_data(pw, &self.mapping_value);
    }
}

impl UserCircuit<GoldilocksField, 2> for LeafCircuit {
    type Wires = InclusionWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let key = Array::<Target, MAPPING_KEY_LEN>::new(b);
        let key_u32 = key.convert_u8_to_u32(b);
        let value = Array::<Target, VALUE_LEN>::new(b);
        let value_u32 = value.convert_u8_to_u32(b);
        let kv = key_u32.concat(&value_u32).to_targets();

        // the digest is done on the key only, in compact form, because our goal is
        // to reval all the keys at the last step of the computation graph
        let digest = b.map_to_curve_point(&key_u32.to_targets().arr);
        // the root is done on both as this is what proves the inclusion in the storage db
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(Vec::from(kv.arr));

        // we expose the value, in compact form to the public inputs, it gets propagated
        // up the computation tree
        PublicInputs::<GoldilocksField>::register(b, &root, &digest, &value_u32);
        InclusionWires {
            mapping_key: key,
            mapping_value: value,
        }
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        self.assign(pw, wires);
    }
}
