use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    serialization::{deserialize, serialize},
};
use serde::{Deserialize, Serialize};

use crate::{api::ProofWithVK, poseidon::hash_maybe_swap};

use super::BlockPublicInputs;
#[derive(Serialize, Deserialize)]
pub struct PartialNodeWires {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    unproved: HashOutTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    proved_is_right: BoolTarget,
}

#[derive(Clone, Debug)]
pub struct PartialNodeCircuit {
    sibling_hash: HashOut<F>,
    sibling_is_left: bool,
}

impl PartialNodeCircuit {
    pub(crate) fn new(sibling_hash: HashOut<F>, sibling_is_left: bool) -> Self {
        Self {
            sibling_hash,
            sibling_is_left,
        }
    }
}

impl PartialNodeCircuit {
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        proved: &BlockPublicInputs<Target>,
    ) -> PartialNodeWires {
        let unproved = b.add_virtual_hash();
        let proved_is_right = b.add_virtual_bool_target_safe();
        let root = hash_maybe_swap(
            b,
            &[proved.root().elements, unproved.elements],
            proved_is_right,
        );

        BlockPublicInputs::<Target>::register(
            b,
            proved.block_number(),
            proved.range(),
            &root,
            &proved.smart_contract_address(),
            &proved.user_address(),
            proved.mapping_slot(),
            proved.mapping_slot_length(),
            proved.digest(),
        );

        PartialNodeWires {
            unproved,
            proved_is_right,
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &PartialNodeWires) {
        pw.set_hash_target(wires.unproved, self.sibling_hash);
        pw.set_bool_target(wires.proved_is_right, self.sibling_is_left);
    }
}

type F = crate::api::F;
const D: usize = crate::api::D;
const NUM_IO: usize = BlockPublicInputs::<Target>::total_len();

impl CircuitLogicWires<F, D, 1> for PartialNodeWires {
    type CircuitBuilderParams = ();

    type Inputs = PartialNodeCircuit;

    const NUM_PUBLIC_INPUTS: usize = NUM_IO;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<D>; 1],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let children_pi = BlockPublicInputs::from(Self::public_input_targets(verified_proofs[0]));
        PartialNodeCircuit::build(builder, &children_pi)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

pub struct PartialNodeCircuitInputs {
    inputs: PartialNodeCircuit,
    child_proof: ProofWithVK,
}

impl PartialNodeCircuitInputs {
    pub(crate) fn new(
        child_proof: ProofWithVK,
        sibling_hash: HashOut<F>,
        sibling_is_left: bool,
    ) -> Self {
        Self {
            inputs: PartialNodeCircuit::new(sibling_hash, sibling_is_left),
            child_proof,
        }
    }
}

impl From<PartialNodeCircuitInputs> for (PartialNodeCircuit, ProofWithVK) {
    fn from(val: PartialNodeCircuitInputs) -> Self {
        (val.inputs, val.child_proof)
    }
}
