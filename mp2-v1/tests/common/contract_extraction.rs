//! Test utilities for Contract Extraction (C.3)

use super::TestContext;
use ethers::prelude::Address;
use log::info;
use mp2_common::{
    eth::{ProofQuery, StorageSlot},
    group_hashing::map_to_curve_point,
    mpt_sequential::{
        mpt_key_ptr, utils::bytes_to_nibbles, MPT_BRANCH_RLP_SIZE, MPT_EXTENSION_RLP_SIZE,
    },
    utils::{convert_u8_to_u32_slice, keccak256, ToFields},
    F,
};
use mp2_v1::{
    api::{generate_proof, CircuitInput, ProofWithVK, PublicParameters},
    contract_extraction,
    contract_extraction::PublicInputs,
};
use plonky2::field::types::Field;
use rlp::{Prototype, Rlp};
use std::str::FromStr;

impl TestContext {
    /// Generate the Contract Extraction (C.3) proof.
    pub(crate) async fn prove_contract_extraction(
        &self,
        contract_address: &str,
        slot: StorageSlot,
    ) -> ProofWithVK {
        // Query the MPT proof from RPC.
        let contract_address = Address::from_str(contract_address).unwrap();
        let query = match slot {
            StorageSlot::Simple(slot) => ProofQuery::new_simple_slot(contract_address, slot),
            StorageSlot::Mapping(mapping_key, slot) => {
                ProofQuery::new_mapping_slot(contract_address, slot, mapping_key)
            }
        };
        let res = self.query_mpt_proof(&query).await;

        // Get the storage root hash, and check it with `keccak(storage_root)`,
        let storage_root = res.storage_proof[0].proof[0].to_vec();
        let storage_root = keccak256(&storage_root);
        assert_eq!(storage_root, res.storage_hash.0);

        // Get the state nodes, and reverse to get the sequence from leaf to root.
        let mut nodes = res.account_proof;
        nodes.reverse();

        // Generate the leaf proof.
        let leaf = nodes[0].to_vec();
        let mut proof = prove_leaf(self.params(), leaf, &storage_root, contract_address);

        // Prove the all nodes till to the root.
        for node in &nodes[1..] {
            let rlp = Rlp::new(node);
            match rlp.prototype().unwrap() {
                Prototype::List(MPT_EXTENSION_RLP_SIZE) => {
                    proof = prove_extension(self.params(), node.to_vec(), proof);
                }
                Prototype::List(MPT_BRANCH_RLP_SIZE) => {
                    proof = prove_branch(self.params(), node.to_vec(), proof);
                }
                _ => panic!("Invalid RLP size for the state proof"),
            }
        }

        ProofWithVK::deserialize(&proof).unwrap()
    }
}

/// Generate the leaf proof.
fn prove_leaf(
    params: &PublicParameters,
    node: Vec<u8>,
    storage_root: &[u8],
    contract_address: Address,
) -> Vec<u8> {
    // Generate the proof.
    let input =
        contract_extraction::CircuitInput::new_leaf(node.clone(), &storage_root, contract_address);
    let input = CircuitInput::ContractExtraction(input);
    let proof = generate_proof(params, input).unwrap();

    // Check the leaf public inputs.
    let proof_with_vk = ProofWithVK::deserialize(&proof).unwrap();
    let pi = PublicInputs::from_slice(&proof_with_vk.proof().public_inputs);
    // Check packed block hash
    {
        let exp_block_hash = keccak256(&node);
        let exp_block_hash = convert_u8_to_u32_slice(&keccak256(&node)).to_fields();
        assert_eq!(pi.h, exp_block_hash);
    }
    // Check metadata digest
    {
        let packed_contract_address = convert_u8_to_u32_slice(&contract_address.0).to_fields();
        let exp_digest = map_to_curve_point(&packed_contract_address);
        assert_eq!(pi.metadata_point(), exp_digest.to_weierstrass());
    }
    // Check MPT key and pointer
    {
        let key = pi.k;
        let ptr = pi.t;

        let mpt_key = keccak256(&contract_address.0);
        let exp_key: Vec<_> = bytes_to_nibbles(&mpt_key)
            .into_iter()
            .map(F::from_canonical_u8)
            .collect();
        assert_eq!(key, exp_key);

        let leaf_key: Vec<Vec<u8>> = rlp::decode_list(&node);
        let exp_ptr = F::from_canonical_usize(mpt_key_ptr(&leaf_key[0]));
        assert_eq!(exp_ptr, *ptr);
    }
    // Check packed storage root hash
    {
        let exp_storage_root_hash: Vec<_> = convert_u8_to_u32_slice(&storage_root).to_fields();
        assert_eq!(pi.s, exp_storage_root_hash);
    }

    proof
}

/// Generate the extension proof.
fn prove_extension(params: &PublicParameters, node: Vec<u8>, child_proof: Vec<u8>) -> Vec<u8> {
    // Generate the proof.
    let input = contract_extraction::CircuitInput::new_extension(node.clone(), child_proof.clone());
    let input = CircuitInput::ContractExtraction(input);
    let proof = generate_proof(params, input).unwrap();

    // Check the extension public inputs.
    let proof_with_vk = ProofWithVK::deserialize(&proof).unwrap();
    let pi = PublicInputs::from_slice(&proof_with_vk.proof().public_inputs);
    let child_proof_with_vk = ProofWithVK::deserialize(&child_proof).unwrap();
    let child_pi = PublicInputs::from_slice(&child_proof_with_vk.proof().public_inputs);
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

        let leaf_key: Vec<Vec<u8>> = rlp::decode_list(&node);
        let exp_ptr = F::from_canonical_usize(mpt_key_ptr(&leaf_key[0]));
        assert_eq!(pi.t, &exp_ptr);
    }
    // Check packed storage root hash
    assert_eq!(pi.s, child_pi.s);

    proof
}

/// Generate the branch proof.
fn prove_branch(params: &PublicParameters, node: Vec<u8>, child_proof: Vec<u8>) -> Vec<u8> {
    // Generate the proof.
    let input = contract_extraction::CircuitInput::new_branch(node.clone(), child_proof.clone());
    let input = CircuitInput::ContractExtraction(input);
    let proof = generate_proof(params, input).unwrap();

    // Check the branch public inputs.
    let proof_with_vk = ProofWithVK::deserialize(&proof).unwrap();
    let pi = PublicInputs::from_slice(&proof_with_vk.proof().public_inputs);
    let child_proof_with_vk = ProofWithVK::deserialize(&child_proof).unwrap();
    let child_pi = PublicInputs::from_slice(&child_proof_with_vk.proof().public_inputs);
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

        // -1 because branch circuit exposes the new pointer.
        assert_eq!(*pi.t, *child_pi.t - F::ONE);
    }
    // Check packed storage root hash
    assert_eq!(pi.s, child_pi.s);

    proof
}
