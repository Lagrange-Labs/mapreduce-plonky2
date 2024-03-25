use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::poseidon::PoseidonHash,
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use crate::{
    api::mapping::leaf::VALUE_LEN, array::Array, circuit::UserCircuit,
    group_hashing::CircuitBuilderGroupHashing, types::MAPPING_KEY_LEN,
};

use super::{PublicInputs, KEY_SIZE, LEAF_SIZE};

/// Circuit that handles the proving of the leaf of the storage database for a mapping variable
#[derive(Clone, Debug)]
pub struct LeafCircuit {
    /// The mapping key we want to insert in our db. Left-padded with zeroes if necessary
    pub mapping_key: [u8; MAPPING_KEY_LEN],
    /// The mapping value associated to this mapping key. Left-padded with zeroes if necessary
    pub mapping_value: [u8; VALUE_LEN],
}

#[derive(Serialize, Deserialize)]
pub struct LeafWires {
    //
    // IN
    //
    // The mapping key associated to this leaf, expected in byte format
    pub key: Array<Target, MAPPING_KEY_LEN>,
    // The value encoded in this leaf, expected in byte format
    pub value: Array<Target, VALUE_LEN>,
}

impl LeafCircuit {
    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &LeafWires) {
        wires.key.assign_from_data(pw, &self.mapping_key);
        wires.value.assign_from_data(pw, &self.mapping_value);
    }
}

impl UserCircuit<GoldilocksField, 2> for LeafCircuit {
    type Wires = LeafWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> LeafWires {
        let key = Array::<Target, MAPPING_KEY_LEN>::new(b);
        let value = Array::<Target, VALUE_LEN>::new(b);
        let kv = key.concat(&value).to_targets();
        let kv_u32 = kv.convert_u8_to_u32(b).to_targets();

        let digest = b.map_to_curve_point(&kv_u32.arr);
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(Vec::from(kv_u32.arr));

        PublicInputs::<GoldilocksField>::register(b, &root, &digest);

        LeafWires { key, value }
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
