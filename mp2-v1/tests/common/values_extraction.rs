//! Test utilities for Values Extraction (C.1)

use super::{storage_trie::TestStorageTrie, TestContext};
use crate::common::StorageSlotInfo;
use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, U256},
    providers::Provider,
};
use log::info;
use mp2_common::{
    eth::{ProofQuery, StorageSlot},
    mpt_sequential::utils::bytes_to_nibbles,
    F,
};
use mp2_v1::values_extraction::public_inputs::PublicInputs;
use plonky2::field::types::Field;

type MappingKey = Vec<u8>;

impl TestContext {
    /// Generate the Values Extraction (C.1) proof for single variables.
    pub(crate) async fn prove_single_values_extraction(
        &self,
        contract_address: &Address,
        slots: &[StorageSlotInfo],
    ) -> Vec<u8> {
        // Initialize the test trie.
        let mut trie = TestStorageTrie::new();
        info!("Initialized the test storage trie");

        // Query the slot and add the node path to the trie.
        for slot_info in slots {
            trie.query_proof_and_add_slot(self, contract_address, slot_info.clone())
                .await;
        }

        let chain_id = self.rpc.get_chain_id().await.unwrap();
        info!("Prove the test storage trie including the simple slots {slots:?}");
        let proof_value = trie.prove_value(contract_address, chain_id, self.params(), &self.b);

        // Check the public inputs.
        let pi = PublicInputs::new(&proof_value.proof().public_inputs);
        assert_eq!(pi.n(), F::from_canonical_usize(slots.len()));
        assert_eq!(pi.root_hash(), trie.root_hash());
        {
            let exp_key = StorageSlot::Simple(slots[0].slot().slot() as usize).mpt_key_vec();
            let exp_key: Vec<_> = bytes_to_nibbles(&exp_key)
                .into_iter()
                .map(F::from_canonical_u8)
                .collect();

            let (key, ptr) = pi.mpt_key_info();
            assert_eq!(key, exp_key);
            assert_eq!(ptr, F::NEG_ONE);
        }

        proof_value.serialize().unwrap()
    }

    /// Generate the Values Extraction (C.1) proof for mapping variables.
    pub(crate) async fn prove_mapping_values_extraction(
        &self,
        contract_address: &Address,
        slot: u8,
        mapping_keys: Vec<MappingKey>,
    ) -> Vec<u8> {
        let slot = slot as usize;

        let first_mapping_key = mapping_keys[0].clone();
        let storage_slot_number = mapping_keys.len();

        // Initialize the test trie.
        let mut trie = TestStorageTrie::new();
        info!("mapping mpt proving: Initialized the test storage trie");

        // Query the slot and add the node path to the trie.
        for mapping_key in mapping_keys {
            let query =
                ProofQuery::new_mapping_slot(contract_address.clone(), slot, mapping_key.clone());
            let response = self
                .query_mpt_proof(&query, BlockNumberOrTag::Number(self.block_number().await))
                .await;

            // Get the nodes to prove. Reverse to the sequence from leaf to root.
            let nodes: Vec<_> = response.storage_proof[0]
                .proof
                .iter()
                .rev()
                .map(|node| node.to_vec())
                .collect();

            let sslot = StorageSlot::Mapping(mapping_key.clone(), slot);
            info!(
                "Save the mapping key {:?} (value {}) on slot {} to the test storage trie",
                U256::from_be_slice(&mapping_key),
                response.storage_proof[0].value,
                slot
            );

            // TODO: Fix mapping slot.
            todo!()
            // trie.add_slot(sslot, nodes);
        }

        let chain_id = self.rpc.get_chain_id().await.unwrap();
        info!("Prove the test storage trie including the mapping slots ({slot}, ...)");
        let proof = trie.prove_value(&contract_address, chain_id, &self.params(), &self.b);

        // Check the public inputs.
        let pi = PublicInputs::new(&proof.proof().public_inputs);
        assert_eq!(pi.n(), F::from_canonical_usize(storage_slot_number));
        assert_eq!(pi.root_hash(), trie.root_hash());
        {
            let exp_key = StorageSlot::Mapping(first_mapping_key, slot).mpt_key_vec();
            let exp_key: Vec<_> = bytes_to_nibbles(&exp_key)
                .into_iter()
                .map(F::from_canonical_u8)
                .collect();

            let (key, ptr) = pi.mpt_key_info();
            assert_eq!(key, exp_key);
            assert_eq!(ptr, F::NEG_ONE);
        }

        proof.serialize().expect("can't serialize mpt proof")
    }
}
