use mp2_common::{types::GFp, C, D, F};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{RecursiveCircuitInfo, RecursiveCircuits},
};
use serde::{Deserialize, Serialize};

use crate::{
    api::{default_config, InputNode, ProofInputSerialized, ProofWithVK},
    length_extraction::{BranchLengthCircuit, ExtensionLengthCircuit},
};

use super::{
    BranchLengthWires, ExtensionLengthWires, LeafLengthCircuit, LeafLengthWires, PublicInputs,
};

type LeafWire = LeafLengthWires;
type ExtensionInput = ProofInputSerialized<InputNode>;
type BranchInput = ProofInputSerialized<InputNode>;

/// CircuitInput is a wrapper around the different specialized circuits that can
/// be used to prove a MPT node recursively.
#[derive(Serialize, Deserialize)]
pub enum LengthCircuitInput {
    Branch(BranchInput),
    Extension(ExtensionInput),
    Leaf(LeafLengthCircuit),
}

impl LengthCircuitInput {
    /// Creates a new circuit input instance for proving the length extraction of a branch MPT node.
    pub fn new_branch(node: Vec<u8>, child_proof: Vec<u8>) -> Self {
        Self::Branch(ExtensionInput {
            input: InputNode { node },
            serialized_child_proofs: vec![child_proof],
        })
    }

    /// Creates a new circuit input instance for proving the length extraction of an extension MPT node.
    pub fn new_extension(node: Vec<u8>, child_proof: Vec<u8>) -> Self {
        Self::Extension(ExtensionInput {
            input: InputNode { node },
            serialized_child_proofs: vec![child_proof],
        })
    }

    /// Creates a new circuit input instance for proving the length extraction of a leaf MPT node.
    pub fn new_leaf(length_slot: u8, length_node: Vec<u8>, variable_slot: u8) -> Self {
        Self::Leaf(LeafLengthCircuit::new(
            length_slot,
            length_node,
            variable_slot,
        ))
    }
}

/// Length extraction MPT circuits.
///
/// Unlocks the usage with the recursion framwork.
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicParameters {
    branch: CircuitWithUniversalVerifier<F, C, D, 1, BranchLengthWires>,
    extension: CircuitWithUniversalVerifier<F, C, D, 1, ExtensionLengthWires>,
    leaf: CircuitWithUniversalVerifier<F, C, D, 0, LeafWire>,
    set: RecursiveCircuits<F, C, D>,
}

impl PublicParameters {
    /// Number of public inputs used in the circuits.
    pub const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GFp>::TOTAL_LEN;

    /// Number of circuit variants.
    pub const CIRCUIT_SET_SIZE: usize = 3;

    /// Generates the circuit parameters for the MPT circuits.
    pub fn build() -> Self {
        let config = default_config();
        let circuit_builder = CircuitWithUniversalVerifierBuilder::<
            F,
            D,
            { Self::NUM_PUBLIC_INPUTS },
        >::new::<C>(config, Self::CIRCUIT_SET_SIZE);

        log::debug!("Building MPT length extraction leaf circuit...");

        let leaf = circuit_builder.build_circuit(());

        log::debug!("Building MPT length extraction extension circuit...");

        let extension = circuit_builder.build_circuit(());

        log::debug!("Building MPT length extraction branch circuit...");

        let branch = circuit_builder.build_circuit(());

        log::debug!("Building MPT length extraction recursive circuit set...");

        let set = RecursiveCircuits::new_from_circuit_digests(vec![
            leaf.get_verifier_data().circuit_digest,
            extension.get_verifier_data().circuit_digest,
            branch.get_verifier_data().circuit_digest,
        ]);

        log::debug!("Build of MPT length extraction circuits completed.");

        Self {
            branch,
            extension,
            leaf,
            set,
        }
    }

    /// Generates a serialized proof via [ProofWithVK::serialize].
    pub fn generate_proof(&self, circuit: LengthCircuitInput) -> anyhow::Result<Vec<u8>> {
        let set = &self.set;

        let proof_and_vk = match circuit {
            LengthCircuitInput::Branch(c) => {
                log::debug!("Generating a MPT length extraction branch proof...");

                let (child_proof, child_vk) = c
                    .get_child_proofs()?
                    .pop()
                    .ok_or_else(|| anyhow::Error::msg("No proof found for the branch node."))?
                    .into();

                let proof = set.generate_proof(
                    &self.branch,
                    [child_proof],
                    [&child_vk],
                    BranchLengthCircuit::new(c.input.node),
                )?;

                (proof, self.branch.get_verifier_data().clone())
            }
            LengthCircuitInput::Extension(c) => {
                log::debug!("Generating a MPT length extraction extension proof...");

                let (child_proof, child_vk) = c
                    .get_child_proofs()?
                    .pop()
                    .ok_or_else(|| anyhow::Error::msg("No proof found for the extension node."))?
                    .into();

                let proof = set.generate_proof(
                    &self.extension,
                    [child_proof],
                    [&child_vk],
                    ExtensionLengthCircuit::new(c.input.node),
                )?;

                (proof, self.extension.get_verifier_data().clone())
            }
            LengthCircuitInput::Leaf(c) => {
                log::debug!("Generating a MPT length extraction leaf proof...");

                let proof = set.generate_proof(&self.leaf, [], [], c)?;

                (proof, self.extension.get_verifier_data().clone())
            }
        };

        log::debug!("MPT length extraction proof generated, serializing...");

        // TODO we might not need the VK serialized with the proof as it might live elsewhere as
        // static data.
        let proof = ProofWithVK::from(proof_and_vk).serialize()?;

        log::debug!("MPT length extraction proof serialized.");

        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use std::{array, iter, sync::Arc};

    use eth_trie::{EthTrie, MemoryDB, Nibbles, Trie};
    use mp2_common::{
        eth::StorageSlot,
        group_hashing::{map_to_curve_point, EXTENSION_DEGREE},
        rlp::MAX_KEY_NIBBLE_LEN,
        types::{GFp, GFp5},
        utils::{convert_u8_to_u32_slice, keccak256},
    };
    use plonky2::field::{extension::FieldExtension, types::Field};
    use plonky2_ecgfp5::curve::curve::WeierstrassPoint;
    use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

    use crate::{api::ProofWithVK, length_extraction::PublicInputs};

    use super::{LengthCircuitInput, PublicParameters};

    #[test]
    fn length_extraction_api_works() {
        let seed = 0xbeef;
        let rng = &mut StdRng::seed_from_u64(seed);

        let params = PublicParameters::build();
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb);

        let depth = 4;
        let length = rng.next_u32();
        let (length_slot, mpt_key, variable_slot) = loop {
            let length_slot = rng.gen::<u8>();
            let variable_slot = rng.gen::<u8>();
            let storage_slot = StorageSlot::Simple(length_slot as usize);

            let mpt_key = storage_slot.mpt_key_vec();
            let value = rng.next_u32();
            let encoded = rlp::encode(&value).to_vec();

            trie.insert(&mpt_key, &encoded).unwrap();
            trie.root_hash().unwrap();

            let proof = trie.get_proof(&mpt_key).unwrap();
            if proof.len() == depth {
                let value = length;
                let encoded = rlp::encode(&value).to_vec();

                trie.insert(&mpt_key, &encoded).unwrap();
                trie.root_hash().unwrap();

                break (length_slot, mpt_key, variable_slot);
            }
        };

        // Leaf extraction

        let mut proof = trie.get_proof(&mpt_key).unwrap();

        let node = proof.pop().unwrap();
        let leaf_circuit = LengthCircuitInput::new_leaf(length_slot, node.clone(), variable_slot);
        let leaf_proof = params.generate_proof(leaf_circuit).unwrap();

        let rlp_headers: Vec<Vec<u8>> = rlp::decode_list(&node);
        let rlp_nibbles = Nibbles::from_compact(&rlp_headers[0]);
        let mut pointer = GFp::from_canonical_usize(MAX_KEY_NIBBLE_LEN - 1)
            - GFp::from_canonical_usize(rlp_nibbles.nibbles().len());

        let lp = ProofWithVK::deserialize(&leaf_proof).unwrap();
        let pis = lp.proof.public_inputs;
        let pi = PublicInputs::from_slice(&pis[..PublicInputs::<GFp>::TOTAL_LEN]);

        let root: Vec<_> = convert_u8_to_u32_slice(&keccak256(&node))
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        let mut key = Vec::with_capacity(64);
        for k in mpt_key {
            key.push(GFp::from_canonical_u8(k >> 4));
            key.push(GFp::from_canonical_u8(k & 0x0f));
        }

        let dm = map_to_curve_point(&[
            GFp::from_canonical_u8(length_slot),
            GFp::from_canonical_u8(variable_slot),
        ])
        .to_weierstrass();

        let y = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| pi.metadata().1[i]);
        let x = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| pi.metadata().0[i]);
        let is_inf = pi.metadata().2 == &GFp::ONE;
        let dm_p = WeierstrassPoint {
            x: GFp5::from_basefield_array(x),
            y: GFp5::from_basefield_array(y),
            is_inf,
        };

        assert_eq!(pi.length(), &GFp::from_canonical_u32(length));
        assert_eq!(pi.root_hash(), &root);
        assert_eq!(pi.mpt_key(), &key);
        assert_eq!(dm, dm_p);
        assert_eq!(pi.mpt_key_pointer(), &pointer);

        // Branch extraction

        /*
        let mut child_proof = leaf_proof;

        while let Some(node) = proof.pop() {
            pointer -= GFp::ONE;

            let branch_circuit = LengthCircuitInput::new_branch(node, child_proof.clone());
            let branch_proof = params.generate_proof(branch_circuit).unwrap();

            let lp = ProofWithVK::deserialize(&branch_proof).unwrap();
            let pis = lp.proof.public_inputs;
            let pi = PublicInputs::from_slice(&pis);
            assert_eq!(pi.mpt_key_pointer(), &pointer,);

            child_proof = branch_proof;
        }
        */
    }

    #[test]
    fn length_extraction_extension_api_works() {
        let seed = 0xbeef;
        let rng = &mut StdRng::seed_from_u64(seed);

        let params = PublicParameters::build();
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb);

        let length_slot = rng.gen::<u8>();
        let variable_slot = rng.gen::<u8>();
        let storage_slot = StorageSlot::Simple(length_slot as usize);

        let key1 = storage_slot.mpt_key_vec();
        let key2: Vec<u8> = key1
            .iter()
            .enumerate()
            .map(|(i, k)| if i == 31 { rng.gen() } else { *k })
            .collect();

        let value1 = rng.next_u32();
        let value2 = rng.next_u32();

        let bytes1: Vec<u8> = value1
            .to_be_bytes()
            .into_iter()
            .chain(iter::repeat(0).take(28))
            .collect();

        let bytes2: Vec<u8> = value2
            .to_be_bytes()
            .into_iter()
            .chain(iter::repeat(0).take(28))
            .collect();

        trie.insert(&key1, &bytes1).unwrap();
        trie.insert(&key2, &bytes2).unwrap();
        trie.root_hash().unwrap();

        let mut proof = trie.get_proof(&key1).unwrap();
        let node = proof.first().unwrap().clone();
        let root_rlp: Vec<Vec<u8>> = rlp::decode_list(&node);
        assert_eq!(root_rlp.len(), 2);

        // Leaf extraction

        let node = proof.pop().unwrap();
        let leaf_circuit = LengthCircuitInput::new_leaf(length_slot, node.clone(), variable_slot);
        let leaf_proof = params.generate_proof(leaf_circuit).unwrap();

        let rlp_headers: Vec<Vec<u8>> = rlp::decode_list(&node);
        let rlp_nibbles = Nibbles::from_compact(&rlp_headers[0]);
        let mut pointer = GFp::from_canonical_usize(MAX_KEY_NIBBLE_LEN - 1)
            - GFp::from_canonical_usize(rlp_nibbles.nibbles().len());

        let lp = ProofWithVK::deserialize(&leaf_proof).unwrap();
        let pis = lp.proof.public_inputs;
        let pi = PublicInputs::from_slice(&pis[..PublicInputs::<GFp>::TOTAL_LEN]);
        assert_eq!(pi.mpt_key_pointer(), &pointer);

        // Extension extraction

        /*
        let node = proof.pop().unwrap();
        let ext_circuit = LengthCircuitInput::new_extension(node, leaf_proof);
        let ext_proof = params.generate_proof(ext_circuit).unwrap();
        */
    }
}
