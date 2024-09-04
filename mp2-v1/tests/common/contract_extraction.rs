//! Test utilities for Contract Extraction (C.3)

use super::TestContext;
use alloy::{eips::BlockNumberOrTag, primitives::Address};
use eth_trie::Nibbles;
use mp2_common::{
    eth::{ProofQuery, StorageSlot},
    mpt_sequential::{
        mpt_key_ptr, utils::bytes_to_nibbles, MPT_BRANCH_RLP_SIZE, MPT_EXTENSION_RLP_SIZE,
    },
    proof::ProofWithVK,
    types::HashOutput,
    utils::{keccak256, ToFields},
    F,
};
use mp2_v1::{
    api::{generate_proof, CircuitInput},
    contract_extraction::{self, compute_metadata_digest, PublicInputs},
    indexing::block::BlockPrimaryIndex,
};
use plonky2::field::types::Field;
use rlp::{Prototype, Rlp};

impl TestContext {
    /// Generate the Contract Extraction (C.3) proof.
    pub(crate) async fn prove_contract_extraction(
        &self,
        contract_address: &Address,
        slot: StorageSlot,
        block_number: BlockPrimaryIndex,
    ) -> Vec<u8> {
        // Query the block for checking the block hash.
        let block = self
            .query_block_at(BlockNumberOrTag::Number(block_number as u64))
            .await;

        // Query the MPT proof from RPC.
        let query = match slot {
            StorageSlot::Simple(slot) => ProofQuery::new_simple_slot(*contract_address, slot),
            StorageSlot::Mapping(mapping_key, slot) => {
                ProofQuery::new_mapping_slot(*contract_address, slot, mapping_key)
            }
        };
        let res = self
            .query_mpt_proof(&query, BlockNumberOrTag::Number(block_number as u64))
            .await;

        // Get the storage root hash, and check it with `keccak(storage_root)`,
        let storage_root = res.storage_proof[0].proof[0].to_vec();
        let storage_root = keccak256(&storage_root);
        assert_eq!(storage_root, res.storage_hash.0);

        // Get the state nodes, and reverse to get the sequence from leaf to root.
        let mut nodes = res.account_proof;
        nodes.reverse();

        // Generate the leaf proof.
        let leaf = nodes[0].to_vec();
        let mut proof = prove_leaf(self, leaf, &storage_root, contract_address);

        // Prove the all nodes till to the root.
        for node in &nodes[1..] {
            let rlp = Rlp::new(node);
            match rlp.prototype().unwrap() {
                Prototype::List(MPT_EXTENSION_RLP_SIZE) => {
                    proof = prove_extension(self, node.to_vec(), proof);
                }
                Prototype::List(MPT_BRANCH_RLP_SIZE) => {
                    proof = prove_branch(self, node.to_vec(), proof);
                }
                _ => panic!("Invalid RLP size for the state proof"),
            }
        }

        // Check the exposed public inputs.
        let proofk = ProofWithVK::deserialize(&proof).unwrap();
        let pi = PublicInputs::from_slice(&proofk.proof().public_inputs);
        // Check the state and storage root hashes.
        let [exp_state_root_hash, exp_storage_root_hash] =
            [&block.header.state_root.0, storage_root.as_slice()]
                .map(|hash| HashOutput::try_from(hash.to_vec()).unwrap().to_fields());
        assert_eq!(pi.h_raw(), exp_state_root_hash);
        assert_eq!(pi.s_raw(), exp_storage_root_hash);
        // Ensure MPT root pointer == -1.
        assert_eq!(*pi.t_raw(), F::NEG_ONE);

        proof
    }
}

/// Generate the leaf proof.
fn prove_leaf(
    ctx: &TestContext,
    node: Vec<u8>,
    storage_root: &[u8],
    contract_address: &Address,
) -> Vec<u8> {
    let params = ctx.params();
    // Generate the proof.
    let input = contract_extraction::CircuitInput::new_leaf(
        node.clone(),
        &storage_root,
        contract_address.clone(),
    );
    let input = CircuitInput::ContractExtraction(input);
    let proof = ctx
        .b
        .bench("indexing::extraction::contract::leaf", || {
            generate_proof(params, input)
        })
        .expect("unable to generate contract extract proof leaf");

    // Check the leaf public inputs.
    let proof_with_vk = ProofWithVK::deserialize(&proof).unwrap();
    let pi = PublicInputs::from_slice(&proof_with_vk.proof().public_inputs);
    // Check packed block hash
    {
        let exp_block_hash = HashOutput::try_from(keccak256(&node)).unwrap().to_fields();
        assert_eq!(pi.h_raw(), exp_block_hash);
    }
    // Check metadata digest
    {
        let exp_digest = compute_metadata_digest(contract_address);
        assert_eq!(pi.metadata_point(), exp_digest.to_weierstrass());
    }
    // Check MPT key and pointer
    {
        let key = pi.k_raw();
        let ptr = pi.t_raw();

        let mpt_key = keccak256(contract_address.as_slice());
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
        let exp_storage_root_hash: Vec<_> = HashOutput::try_from(storage_root.to_vec())
            .unwrap()
            .to_fields();
        assert_eq!(pi.s_raw(), exp_storage_root_hash);
    }

    proof
}

/// Generate the extension proof.
fn prove_extension(ctx: &TestContext, node: Vec<u8>, child_proof: Vec<u8>) -> Vec<u8> {
    let params = ctx.params();
    // Generate the proof.
    let input = contract_extraction::CircuitInput::new_extension(node.clone(), child_proof.clone());
    let input = CircuitInput::ContractExtraction(input);
    let proof = ctx
        .b
        .bench("indexing::extracting::contract::extension", || {
            generate_proof(params, input)
        })
        .expect("unable to gen. contract extraction extension");

    // Check the extension public inputs.
    let proof_with_vk = ProofWithVK::deserialize(&proof).unwrap();
    let pi = PublicInputs::from_slice(&proof_with_vk.proof().public_inputs);
    let child_proof_with_vk = ProofWithVK::deserialize(&child_proof).unwrap();
    let child_pi = PublicInputs::from_slice(&child_proof_with_vk.proof().public_inputs);
    // Check packed block hash
    {
        let hash = HashOutput::try_from(keccak256(&node)).unwrap().to_fields();
        assert_eq!(pi.h_raw(), hash);
    }
    // Check metadata digest
    assert_eq!(pi.dm_raw(), child_pi.dm_raw());
    // Check MPT key and pointer
    {
        assert_eq!(pi.k_raw(), child_pi.k_raw());

        // child pointer - partial key length
        let keys: Vec<Vec<u8>> = rlp::decode_list(&node);
        let nibbles = Nibbles::from_compact(&keys[0]);
        let exp_ptr = *child_pi.t_raw() - F::from_canonical_usize(nibbles.nibbles().len());
        assert_eq!(*pi.t_raw(), exp_ptr);
    }
    // Check packed storage root hash
    assert_eq!(pi.s_raw(), child_pi.s_raw());

    proof
}

/// Generate the branch proof.
fn prove_branch(ctx: &TestContext, node: Vec<u8>, child_proof: Vec<u8>) -> Vec<u8> {
    let params = ctx.params();
    // Generate the proof.
    let input = contract_extraction::CircuitInput::new_branch(node.clone(), child_proof.clone());
    let input = CircuitInput::ContractExtraction(input);
    let proof = ctx
        .b
        .bench("indexing::extraction::contract::branch", || {
            generate_proof(params, input)
        })
        .expect("unable to gen. contract extraction branch");

    // Check the branch public inputs.
    let proof_with_vk = ProofWithVK::deserialize(&proof).unwrap();
    let pi = PublicInputs::from_slice(&proof_with_vk.proof().public_inputs);
    let child_proof_with_vk = ProofWithVK::deserialize(&child_proof).unwrap();
    let child_pi = PublicInputs::from_slice(&child_proof_with_vk.proof().public_inputs);
    // Check packed block hash
    {
        let hash = HashOutput::try_from(keccak256(&node)).unwrap().to_fields();
        assert_eq!(pi.h_raw(), hash);
    }
    // Check metadata digest
    assert_eq!(pi.dm_raw(), child_pi.dm_raw());
    // Check MPT key and pointer
    {
        assert_eq!(pi.k_raw(), child_pi.k_raw());

        // -1 because branch circuit exposes the new pointer.
        assert_eq!(*pi.t_raw(), *child_pi.t_raw() - F::ONE);
    }
    // Check packed storage root hash
    assert_eq!(pi.s_raw(), child_pi.s_raw());

    proof
}
