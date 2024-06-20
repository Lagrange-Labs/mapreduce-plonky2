//! Module handling the extension node inside a state trie

use super::public_inputs::PublicInputs;
use crate::MAX_EXTENSION_NODE_LEN;
use anyhow::Result;
use mp2_common::{
    array::{Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires, HASH_LEN},
    mpt_sequential::{MPTLeafOrExtensionNode, PAD_LEN},
    public_inputs::PublicInputCommon,
    types::CBuilder,
    D, F,
};
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::proof::ProofWithPublicInputsTarget,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

const PADDED_LEN: usize = PAD_LEN(MAX_EXTENSION_NODE_LEN);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExtensionWires {
    node: VectorWire<Target, PADDED_LEN>,
    root: KeccakWires<PADDED_LEN>,
}

/// Circuit to proving the processing of an extension node
#[derive(Clone, Debug)]
pub struct ExtensionCircuit {
    pub(crate) node: Vec<u8>,
}

impl ExtensionCircuit {
    pub fn build(b: &mut CBuilder, child_proof: PublicInputs<Target>) -> ExtensionWires {
        // Build the node wires.
        let wires = MPTLeafOrExtensionNode::build_and_advance_key::<
            _,
            D,
            MAX_EXTENSION_NODE_LEN,
            HASH_LEN,
        >(b, &child_proof.mpt_key());
        let node = wires.node;
        let root = wires.root;
        let new_mpt_key = wires.key;

        // Constrain the extracted hash is the one exposed by the proof.
        let packed_hash = wires.value.convert_u8_to_u32(b);
        let given_hash = child_proof.root_hash();
        packed_hash.enforce_equal(b, &given_hash);

        // Register the public inputs.
        let PublicInputs { dm, s, .. } = child_proof;
        let h = &root.output_array.to_targets().arr;
        let k = &new_mpt_key.key.arr;
        let t = &new_mpt_key.pointer;
        PublicInputs { h, dm, k, t, s }.register(b);

        ExtensionWires { node, root }
    }

    pub fn assign(&self, pw: &mut PartialWitness<F>, wires: &ExtensionWires) {
        let node = Vector::<u8, PADDED_LEN>::from_vec(&self.node).unwrap();
        wires.node.assign(pw, &node);

        KeccakCircuit::<PADDED_LEN>::assign(pw, &wires.root, &InputData::Assigned(&node));
    }
}

/// Num of children = 1
impl CircuitLogicWires<F, D, 1> for ExtensionWires {
    type CircuitBuilderParams = ();

    type Inputs = ExtensionCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; 1],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let inputs = PublicInputs::from_slice(&verified_proofs[0].public_inputs);
        ExtensionCircuit::build(builder, inputs)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth_trie::{EthTrie, MemoryDB, Nibbles, Trie};
    use mp2_common::{
        group_hashing::map_to_curve_point,
        keccak::PACKED_HASH_LEN,
        rlp::MAX_KEY_NIBBLE_LEN,
        types::PACKED_ADDRESS_LEN,
        utils::{convert_u8_to_u32_slice, keccak256, Fieldable, ToFields},
        C,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{field::types::Field, iop::witness::WitnessWrite};
    use rand::{thread_rng, Rng};
    use std::sync::Arc;

    #[derive(Clone, Debug)]
    struct TestExtensionCircuit<'a> {
        c: ExtensionCircuit,
        child_pi: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestExtensionCircuit<'a> {
        // Extension node wires + child public inputs
        type Wires = (ExtensionWires, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let child_pi = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            let ext_wires = ExtensionCircuit::build(b, PublicInputs::from_slice(&child_pi));

            (ext_wires, child_pi)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);

            assert_eq!(wires.1.len(), PublicInputs::<Target>::TOTAL_LEN);
            pw.set_target_arr(&wires.1, self.child_pi);
        }
    }

    #[test]
    fn test_contract_extraction_extension_circuit() {
        // We need to create a trie that for sure contains an extension node:
        // We insert two values under two keys which only differ by their last nibble/byte
        // Normally, the trie should look like:
        // root = extension node
        // branch = point of different between the two keys
        // two leaves
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));
        let key1 = random_vector::<u8>(32);
        let mut key2 = key1.clone();
        key2[31] = key2[31]
            .checked_add(thread_rng().gen_range(1..10))
            .unwrap_or_default();
        assert!(key1 != key2);
        let value1 = random_vector(32);
        let value2 = random_vector(32);
        trie.insert(&key1, &value1).unwrap();
        trie.insert(&key2, &value2).unwrap();
        trie.root_hash().unwrap();
        let proof = trie.get_proof(&key1).unwrap();
        let node = proof.first().unwrap().clone();
        let root_rlp: Vec<Vec<u8>> = rlp::decode_list(&node);
        assert_eq!(root_rlp.len(), 2);

        // Prepare the public inputs for the extension node circuit.
        let h = &convert_u8_to_u32_slice(&keccak256(&proof[1])).to_fields();
        let dm = &map_to_curve_point(&random_vector::<u32>(PACKED_ADDRESS_LEN).to_fields())
            .to_weierstrass()
            .to_fields();
        let k = &random_vector::<u32>(MAX_KEY_NIBBLE_LEN).to_fields();
        let t = &63_u8.to_field();
        let s = &random_vector::<u32>(PACKED_HASH_LEN).to_fields();
        let child_pi = PublicInputs { h, dm, k, t, s };

        let test_circuit = TestExtensionCircuit {
            c: ExtensionCircuit { node: node.clone() },
            child_pi: &child_pi.to_vec(),
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);

        // Check packed block hash
        {
            let hash = convert_u8_to_u32_slice(&keccak256(&node)).to_fields();
            assert_eq!(pi.h, hash);
        }
        // Check metadata digest
        assert_eq!(pi.dm, child_pi.dm);
        // Check MPT key and pointer
        {
            assert_eq!(pi.k, child_pi.k);

            // child pointer - partial key length
            let keys: Vec<Vec<u8>> = rlp::decode_list(&node);
            let nibbles = Nibbles::from_compact(&keys[0]);
            let exp_ptr = *child_pi.t - F::from_canonical_usize(nibbles.nibbles().len());
            assert_eq!(*pi.t, exp_ptr);
        }
        // Check packed storage root hash
        assert_eq!(pi.s, child_pi.s);
    }
}
