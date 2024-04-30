//! Module handling the extension node inside a storage trie

use super::{public_inputs::PublicInputs, MAX_EXTENSION_NODE_LEN};
use anyhow::Result;
use mp2_common::{
    array::{Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires, HASH_LEN},
    mpt_sequential::{MPTNodeWires, PAD_LEN},
    types::{CBuilder, GFp},
};
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::proof::ProofWithPublicInputsTarget,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

const PADDED_LEN: usize = PAD_LEN(MAX_EXTENSION_NODE_LEN);

/// Circuit to prove the extension node
#[derive(Clone, Debug)]
pub struct ExtensionNodeCircuit {
    node: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExtensionWires {
    node: VectorWire<Target, PADDED_LEN>,
    root: KeccakWires<PADDED_LEN>,
}

impl ExtensionNodeCircuit {
    pub fn build(b: &mut CBuilder, child_proof: PublicInputs<Target>) -> ExtensionWires {
        let tru = b._true();

        // Build the node wires.
        let wires = MPTNodeWires::<MAX_EXTENSION_NODE_LEN, HASH_LEN>::build_and_advance_key(
            b,
            &child_proof.mpt_key(),
        );
        let node = wires.node;
        let root = wires.root;

        // Constrain the extracted hash is the one exposed by the proof.
        let packed_child_hash = wires.value.convert_u8_to_u32(b);
        let given_child_hash = child_proof.root_hash();
        let equals = packed_child_hash.equals(b, &given_child_hash);
        b.connect(tru.target, equals.target);

        // Expose the public inputs.
        PublicInputs::register(
            b,
            &root.output_array,
            &wires.key,
            child_proof.values_digest(),
            child_proof.metadata_digest(),
            child_proof.n(),
        );

        ExtensionWires { node, root }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &ExtensionWires) {
        let node = Vector::<u8, PADDED_LEN>::from_vec(&self.node).unwrap();
        wires.node.assign(pw, &node);

        KeccakCircuit::<PADDED_LEN>::assign(pw, &wires.root, &InputData::Assigned(&node));
    }
}

/// D = 2,
/// Num of children = 1
impl CircuitLogicWires<GFp, 2, 1> for ExtensionWires {
    type CircuitBuilderParams = ();

    type Inputs = ExtensionNodeCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GFp>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<2>; 1],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let inputs = PublicInputs::from(&verified_proofs[0].public_inputs);
        ExtensionNodeCircuit::build(builder, inputs)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<GFp>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}
