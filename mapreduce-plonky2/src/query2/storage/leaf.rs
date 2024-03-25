// Contain the mechanisms required to prove the inclusion of a Key, Value pair in the storage database.

use plonky2::{
    field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonHash,
    iop::witness::PartialWitness, plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use crate::{
    array::Array,
    circuit::UserCircuit,
    group_hashing::CircuitBuilderGroupHashing,
    query2::storage::public_inputs::PublicInputs,
    types::{PackedMappingKeyTarget, MAPPING_KEY_LEN, PACKED_MAPPING_KEY_LEN, PACKED_VALUE_LEN},
};

const PACKED_KEY_SIZE: usize = MAPPING_KEY_LEN / 4;

#[derive(Serialize, Deserialize)]
pub struct LeafWires {
    pub packed_mapping_key: Array<U32Target, PACKED_MAPPING_KEY_LEN>,
    pub packed_mapping_value: Array<U32Target, PACKED_VALUE_LEN>,
}

/// This circuit prove the new root hash of a leaf containing the requested data
#[derive(Clone, Debug)]
pub struct LeafCircuit {
    pub mapping_key: [u32; PACKED_MAPPING_KEY_LEN],
    pub mapping_value: [u32; PACKED_VALUE_LEN],
}

impl LeafCircuit {
    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &LeafWires) {
        wires
            .packed_mapping_key
            .assign_from_data(pw, &self.mapping_key);
        wires
            .packed_mapping_value
            .assign_from_data(pw, &self.mapping_value);
    }
}

impl UserCircuit<GoldilocksField, 2> for LeafCircuit {
    type Wires = LeafWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let key_u32 = PackedMappingKeyTarget::new(b);
        let value_u32 = Array::<U32Target, PACKED_VALUE_LEN>::new(b);
        let kv = key_u32.concat(&value_u32).to_targets();

        // the digest is done on the key only, in compact form, because our goal is
        // to reval all the keys at the last step of the computation graph
        let digest = b.map_to_curve_point(&key_u32.to_targets().arr);
        // the root is done on both as this is what proves the inclusion in the storage db
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(Vec::from(kv.arr));

        // we expose the value, in compact form to the public inputs, it gets propagated
        // up the computation tree
        PublicInputs::<GoldilocksField>::register(b, &root, &digest, &value_u32);
        LeafWires {
            packed_mapping_key: key_u32,
            packed_mapping_value: value_u32,
        }
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        self.assign(pw, wires);
    }
}

impl CircuitLogicWires<GoldilocksField, 2, 0> for LeafWires {
    type CircuitBuilderParams = ();
    type Inputs = LeafCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GoldilocksField>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<GoldilocksField, 2>,
        _verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<2>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        LeafCircuit::build(builder)
    }

    fn assign_input(
        &self,
        inputs: Self::Inputs,
        pw: &mut PartialWitness<GoldilocksField>,
    ) -> anyhow::Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}
