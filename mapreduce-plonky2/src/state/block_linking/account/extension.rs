use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::{circuit_builder::CircuitBuilder, proof::ProofWithPublicInputsTarget},
};
use recursion_framework::circuit_builder::{public_input_targets, CircuitLogicWires};
use serde::{Deserialize, Serialize};

use crate::{
    api::mapping::{
        ExtensionNodeCircuit as StorageExtensionCircuit, ExtensionWires as StorageExtensionWires,
    },
    array::VectorWire,
    keccak::{KeccakCircuit, HASH_LEN},
    mpt_sequential::{Circuit as MPTCircuit, PAD_LEN},
    rlp::decode_fixed_list,
    storage::MAX_EXTENSION_NODE_LEN,
};

use super::public_inputs::PublicInputs;
use anyhow::Result;

#[derive(Serialize, Deserialize)]
pub(crate) struct ExtensionWires(StorageExtensionWires);

pub(crate) struct ExtensionCircuit(StorageExtensionCircuit);

type F = super::F;
const D: usize = super::D;
const PADDED_LEN: usize = PAD_LEN(MAX_EXTENSION_NODE_LEN);

impl ExtensionCircuit {
    pub(crate) fn new(node: Vec<u8>) -> Self {
        Self(StorageExtensionCircuit { node })
    }

    pub(crate) fn build(cb: &mut CircuitBuilder<F, D>, child_pi: &[Target]) -> ExtensionWires {
        //ToDo: refactor to extract common code with `StorageExtensionCircuit::build`
        let zero = cb.zero();
        let tru = cb._true();
        let node = VectorWire::<Target, PADDED_LEN>::new(cb);
        // first check node is bytes and then hash the nodes
        node.assert_bytes(cb);
        let root = KeccakCircuit::<PADDED_LEN>::hash_vector(cb, &node);

        // only 2 elements in an extension node
        let rlp_headers = decode_fixed_list::<_, _, 2>(cb, &node.arr.arr, zero);

        // look at the key from the children proof and move its pointer according to this node
        let child_pi = PublicInputs::from(&child_pi);
        let child_mpt_key = child_pi.mpt_key();
        // TODO: refactor these methods - gets too complex when attached with MPTCircuit
        let (new_key, child_hash, valid) =
            MPTCircuit::<1, MAX_EXTENSION_NODE_LEN>::advance_key_leaf_or_extension::<
                _,
                _,
                2,
                HASH_LEN,
            >(cb, &node.arr, &child_mpt_key, &rlp_headers);
        cb.connect(tru.target, valid.target);
        // make sure the extracted hash is the one exposed by the proof
        let packed_child_hash = child_hash.convert_u8_to_u32(cb);
        let given_child_hash = child_pi.root_hash();
        packed_child_hash.enforce_equal(cb, &given_child_hash);

        PublicInputs::register(
            cb,
            &new_key,
            &child_pi.contract_address(),
            child_pi.mapping_slot(),
            child_pi.length_slot(),
            &root.output_array,
            &child_pi.digest(),
            &child_pi.lpn_root(),
        );

        ExtensionWires(StorageExtensionWires { node, keccak: root })
    }

    pub(crate) fn assign(&self, pw: &mut PartialWitness<F>, wires: &ExtensionWires) -> Result<()> {
        Ok(self.0.assign(pw, &wires.0))
    }
}

const NUM_IO: usize = PublicInputs::<Target>::TOTAL_LEN;

// Extension circuit needs to verify the proof for the child node, so the number of verifiers for
// `CircuitLogicWires` is 1
impl CircuitLogicWires<F, D, 1> for ExtensionWires {
    type CircuitBuilderParams = ();

    type Inputs = ExtensionCircuit;

    const NUM_PUBLIC_INPUTS: usize = NUM_IO;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; 1],
        _: Self::CircuitBuilderParams,
    ) -> Self {
        ExtensionCircuit::build(
            builder,
            public_input_targets::<F, D, NUM_IO>(verified_proofs[0]),
        )
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.assign(pw, &self)
    }
}
