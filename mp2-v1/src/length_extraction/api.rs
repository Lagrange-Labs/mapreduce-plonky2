use mp2_common::{group_hashing::map_to_curve_point, types::GFp, C, D, F};
use plonky2::field::types::Field;
use plonky2_ecgfp5::curve::curve::Point as Digest;
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

/// Compute metadata digest D(length_slot || variable_slot)
pub fn compute_metadata_digest(length_slot: u8, variable_slot: u8) -> Digest {
    map_to_curve_point(&[
        GFp::from_canonical_u8(length_slot),
        GFp::from_canonical_u8(variable_slot),
    ])
}

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
    pub fn new_leaf(length_slot: u8, node: Vec<u8>, variable_slot: u8) -> Self {
        Self::Leaf(LeafLengthCircuit::new(length_slot, node, variable_slot))
    }
}

/// Length extraction MPT circuits.
///
/// Unlocks the usage with the recursion framwork.
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicParameters {
    branch: CircuitWithUniversalVerifier<F, C, D, 1, BranchLengthWires>,
    extension: CircuitWithUniversalVerifier<F, C, D, 1, ExtensionLengthWires>,
    leaf: CircuitWithUniversalVerifier<F, C, D, 0, LeafLengthWires>,
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

                let mut proofs = c.get_child_proofs()?;

                anyhow::ensure!(proofs.len() == 1, "the proof arity is 1");

                let (child_proof, child_vk) = proofs.remove(0).into();
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

                let mut proofs = c.get_child_proofs()?;

                anyhow::ensure!(proofs.len() == 1, "the proof arity is 1");

                let (child_proof, child_vk) = proofs.remove(0).into();
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

                (proof, self.leaf.get_verifier_data().clone())
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
    use std::sync::Arc;

    use eth_trie::{EthTrie, MemoryDB, Nibbles, Trie};
    use mp2_common::{
        eth::StorageSlot,
        rlp::MAX_KEY_NIBBLE_LEN,
        types::GFp,
        utils::{keccak256, Endianness, Packer, ToFields},
    };
    use plonky2::field::types::Field;
    use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

    use crate::{
        api::ProofWithVK,
        length_extraction::{api::compute_metadata_digest, tests::PudgyState, PublicInputs},
    };

    use super::{LengthCircuitInput, PublicParameters};

    #[test]
    fn length_extraction_api_pudgy_works() {
        let PudgyState {
            slot,
            length,
            variable_slot,
            dm,
            key,
            mut pointer,
            mut proof,
            ..
        } = PudgyState::new();
        let params = PublicParameters::build();

        // Leaf extraction

        let node = proof.pop().unwrap();
        let leaf_circuit = LengthCircuitInput::new_leaf(slot, node.clone(), variable_slot);
        let mut child_proof = params.generate_proof(leaf_circuit).unwrap();

        let lp = ProofWithVK::deserialize(&child_proof).unwrap();
        let pis = lp.proof.public_inputs;
        let pi = PublicInputs::from_slice(&pis[..PublicInputs::<GFp>::TOTAL_LEN]);

        let root: Vec<_> = keccak256(&node).pack(Endianness::Little).to_fields();

        assert_eq!(pi.length(), &GFp::from_canonical_u32(length));
        assert_eq!(pi.root_hash(), &root);
        assert_eq!(pi.mpt_key(), &key);
        assert_eq!(pi.metadata_point(), dm);
        assert_eq!(pi.mpt_key_pointer(), &pointer);

        // Branch extraction

        while let Some(node) = proof.pop() {
            pointer -= GFp::ONE;

            let root: Vec<_> = keccak256(&node).pack(Endianness::Little).to_fields();

            let branch_circuit = LengthCircuitInput::new_branch(node, child_proof);

            child_proof = params.generate_proof(branch_circuit).unwrap();

            let lp = ProofWithVK::deserialize(&child_proof).unwrap();
            let pis = lp.proof.public_inputs;
            let pi = PublicInputs::from_slice(&pis[..PublicInputs::<GFp>::TOTAL_LEN]);

            assert_eq!(pi.length(), &GFp::from_canonical_u32(length));
            assert_eq!(pi.root_hash(), &root);
            assert_eq!(pi.mpt_key(), &key);
            assert_eq!(pi.metadata_point(), dm);
            assert_eq!(pi.mpt_key_pointer(), &pointer);
        }
    }

    #[test]
    fn length_extraction_api_extension_works() {
        let rng = &mut StdRng::seed_from_u64(0xffff);
        let params = PublicParameters::build();
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));

        let length_slot = rng.gen::<u8>();
        let variable_slot = rng.gen::<u8>();
        let storage_slot = StorageSlot::Simple(length_slot as usize);

        let key1 = storage_slot.mpt_key_vec();
        let mut key2 = storage_slot.mpt_key_vec();

        while key2[31] == key1[31] {
            key2[31] = rng.gen();
        }

        let value1 = rng.next_u32();
        let value2 = rng.next_u32();

        let mut bytes1 = rlp::encode(&value1);
        let mut bytes2 = rlp::encode(&value2);

        // padding is required for a consistent EthTrie path
        // check https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/212
        bytes1.resize(32, 0);
        bytes2.resize(32, 0);

        trie.insert(&key1, &bytes1).unwrap();
        trie.insert(&key2, &bytes2).unwrap();
        trie.root_hash().unwrap();

        let mut proof = trie.get_proof(&key1).unwrap();

        let node = proof.first().unwrap().clone();
        let root_rlp: Vec<Vec<u8>> = rlp::decode_list(&node);
        assert_eq!(root_rlp.len(), 2);

        let mut key = Vec::with_capacity(64);
        for k in key1 {
            key.push(GFp::from_canonical_u8(k >> 4));
            key.push(GFp::from_canonical_u8(k & 0b00001111));
        }

        let length = GFp::from_canonical_u32(value1);
        let dm = compute_metadata_digest(length_slot, variable_slot).to_weierstrass();

        // Leaf extraction

        let node = proof.pop().unwrap();
        let leaf_circuit = LengthCircuitInput::new_leaf(length_slot, node.clone(), variable_slot);
        let child_proof = params.generate_proof(leaf_circuit).unwrap();

        let lp = ProofWithVK::deserialize(&child_proof).unwrap();
        let pis = lp.proof.public_inputs;
        let pi = PublicInputs::from_slice(&pis[..PublicInputs::<GFp>::TOTAL_LEN]);

        let rlp_headers: Vec<Vec<u8>> = rlp::decode_list(&node);
        let rlp_nibbles = Nibbles::from_compact(&rlp_headers[0]);
        let pointer = GFp::from_canonical_usize(MAX_KEY_NIBBLE_LEN - 1)
            - GFp::from_canonical_usize(rlp_nibbles.nibbles().len());

        let root: Vec<_> = keccak256(&node).pack(Endianness::Little).to_fields();

        assert_eq!(pi.length(), &length);
        assert_eq!(pi.root_hash(), &root);
        assert_eq!(pi.mpt_key(), &key);
        assert_eq!(pi.metadata_point(), dm);
        assert_eq!(pi.mpt_key_pointer(), &pointer);

        // Branch extraction

        let pointer = pointer - GFp::ONE;
        let node = proof.pop().unwrap();

        let root: Vec<_> = keccak256(&node).pack(Endianness::Little).to_fields();

        let branch_circuit = LengthCircuitInput::new_branch(node, child_proof);
        let child_proof = params.generate_proof(branch_circuit).unwrap();

        let lp = ProofWithVK::deserialize(&child_proof).unwrap();
        let pis = lp.proof.public_inputs;
        let pi = PublicInputs::from_slice(&pis[..PublicInputs::<GFp>::TOTAL_LEN]);

        assert_eq!(pi.length(), &length);
        assert_eq!(pi.root_hash(), &root);
        assert_eq!(pi.mpt_key(), &key);
        assert_eq!(pi.metadata_point(), dm);
        assert_eq!(pi.mpt_key_pointer(), &pointer);

        // Extension extraction

        let pointer = GFp::ZERO - GFp::ONE;
        let node = proof.pop().unwrap();

        let root: Vec<_> = keccak256(&node).pack(Endianness::Little).to_fields();
        let ext_circuit = LengthCircuitInput::new_extension(node, child_proof);
        let child_proof = params.generate_proof(ext_circuit).unwrap();

        let lp = ProofWithVK::deserialize(&child_proof).unwrap();
        let pis = lp.proof.public_inputs;
        let pi = PublicInputs::from_slice(&pis[..PublicInputs::<GFp>::TOTAL_LEN]);

        assert_eq!(pi.length(), &length);
        assert_eq!(pi.root_hash(), &root);
        assert_eq!(pi.mpt_key(), &key);
        assert_eq!(pi.metadata_point(), dm);
        assert_eq!(pi.mpt_key_pointer(), &pointer);
    }
}
