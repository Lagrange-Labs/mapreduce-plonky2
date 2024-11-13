//! Module handling the extension node inside a storage trie

use crate::MAX_EXTENSION_NODE_LEN;

use super::public_inputs::{PublicInputs, PublicInputsArgs};
use anyhow::Result;
use mp2_common::{
    array::{Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires, HASH_LEN},
    mpt_sequential::{MPTLeafOrExtensionNode, PAD_LEN},
    public_inputs::PublicInputCommon,
    types::{CBuilder, GFp},
    utils::Endianness,
    D,
};
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::proof::ProofWithPublicInputsTarget,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

const PADDED_LEN: usize = PAD_LEN(MAX_EXTENSION_NODE_LEN);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExtensionNodeWires {
    node: VectorWire<Target, PADDED_LEN>,
    root: KeccakWires<PADDED_LEN>,
}

/// Circuit to proving the processing of an extension node
#[derive(Clone, Debug)]
pub struct ExtensionNodeCircuit {
    pub(crate) node: Vec<u8>,
}

impl ExtensionNodeCircuit {
    pub fn build(b: &mut CBuilder, child_proof: PublicInputs<Target>) -> ExtensionNodeWires {
        // Build the node wires.
        let wires = MPTLeafOrExtensionNode::build_and_advance_key::<
            _,
            D,
            MAX_EXTENSION_NODE_LEN,
            HASH_LEN,
        >(b, &child_proof.mpt_key());
        let node = wires.node;
        let root = wires.root;

        // Constrain the extracted hash is the one exposed by the proof.
        let packed_child_hash = wires.value.pack(b, Endianness::Little);
        let given_child_hash = child_proof.root_hash_target();
        packed_child_hash.enforce_equal(b, &given_child_hash);

        // Expose the public inputs.
        PublicInputsArgs {
            h: &root.output_array,
            k: &wires.key,
            dv: child_proof.values_digest_target(),
            dm: child_proof.metadata_digest_target(),
            n: child_proof.n(),
        }
        .register(b);

        ExtensionNodeWires { node, root }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &ExtensionNodeWires) {
        let node = Vector::<u8, PADDED_LEN>::from_vec(&self.node).unwrap();
        wires.node.assign(pw, &node);

        KeccakCircuit::<PADDED_LEN>::assign(pw, &wires.root, &InputData::Assigned(&node));
    }
}

/// Num of children = 1
impl CircuitLogicWires<GFp, D, 1> for ExtensionNodeWires {
    type CircuitBuilderParams = ();

    type Inputs = ExtensionNodeCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GFp>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; 1],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let inputs = PublicInputs::new(&verified_proofs[0].public_inputs);
        ExtensionNodeCircuit::build(builder, inputs)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<GFp>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{super::public_inputs::tests::new_extraction_public_inputs, *};
    use eth_trie::{EthTrie, MemoryDB, Nibbles, Trie};
    use mp2_common::{
        group_hashing::map_to_curve_point,
        rlp::MAX_KEY_NIBBLE_LEN,
        utils::{keccak256, Endianness, Packer},
        C, D, F,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::types::Field,
        iop::{target::Target, witness::WitnessWrite},
        plonk::circuit_builder::CircuitBuilder,
    };
    use rand::{thread_rng, Rng};
    use std::sync::Arc;

    #[derive(Clone, Debug)]
    struct TestExtensionNodeCircuit<'a> {
        c: ExtensionNodeCircuit,
        exp_pi: PublicInputs<'a, F>,
    }

    impl UserCircuit<F, D> for TestExtensionNodeCircuit<'_> {
        // Extension node wires + child public inputs
        type Wires = (ExtensionNodeWires, Vec<Target>);

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let exp_pi = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            let ext_wires = ExtensionNodeCircuit::build(b, PublicInputs::new(&exp_pi));

            (ext_wires, exp_pi)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);

            assert_eq!(wires.1.len(), PublicInputs::<Target>::TOTAL_LEN);
            assert_eq!(
                self.exp_pi.proof_inputs.len(),
                PublicInputs::<Target>::TOTAL_LEN
            );
            pw.set_target_arr(&wires.1, self.exp_pi.proof_inputs)
        }
    }

    #[test]
    fn test_values_extraction_extension_node_circuit() {
        // We need to create a trie that for sure contains an extension node:
        // We insert two values under two keys which only differ by their last nibble/byte
        // Normally, the trie should look like:
        // root = extension node
        // branch = point of different between the two keys
        // two leaves
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));
        let key1 = random_vector(32);
        let mut key2 = key1.clone();
        key2[31] = thread_rng().gen();
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
        let [values_digest, metadata_digest] = [random_vector(10), random_vector(20)].map(|arr| {
            map_to_curve_point(
                &arr.into_iter()
                    .map(F::from_canonical_u8)
                    .collect::<Vec<_>>(),
            )
            .to_weierstrass()
        });
        let key = random_vector(64);
        let ptr = 63;
        // Hash the child of the extension node in packed mode.
        let child_hash = keccak256(&proof[1]).pack(Endianness::Little);
        let n = 15;
        let exp_pi = new_extraction_public_inputs(
            &child_hash,
            &key,
            ptr,
            &values_digest,
            &metadata_digest,
            n,
        );
        let exp_pi = PublicInputs::new(&exp_pi);

        // Quick test to see if we can convert back to public inputs.
        assert_eq!(child_hash, exp_pi.root_hash());
        let (exp_key, _exp_ptr) = exp_pi.mpt_key_info();
        assert_eq!(
            key.iter()
                .cloned()
                .map(F::from_canonical_u8)
                .collect::<Vec<_>>(),
            exp_key,
        );
        assert_eq!(values_digest, exp_pi.values_digest());
        assert_eq!(metadata_digest, exp_pi.metadata_digest());
        assert_eq!(F::from_canonical_usize(n), exp_pi.n());

        let circuit = TestExtensionNodeCircuit {
            c: ExtensionNodeCircuit { node: node.clone() },
            exp_pi: exp_pi.clone(),
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        let pi = PublicInputs::new(&proof.public_inputs);

        {
            let exp_hash = keccak256(&node).pack(Endianness::Little);
            assert_eq!(pi.root_hash(), exp_hash);
        }
        {
            let (key, ptr) = pi.mpt_key_info();
            assert_eq!(key, exp_key);

            let ext_key: Vec<Vec<u8>> = rlp::decode_list(&node);
            let nib = Nibbles::from_compact(&ext_key[0]);
            let exp_ptr = F::from_canonical_usize(MAX_KEY_NIBBLE_LEN - 1 - nib.nibbles().len());
            assert_eq!(ptr, exp_ptr);
        }
        assert_eq!(pi.values_digest(), exp_pi.values_digest());
        assert_eq!(pi.metadata_digest(), exp_pi.metadata_digest());
        assert_eq!(pi.n(), exp_pi.n());
    }
}
