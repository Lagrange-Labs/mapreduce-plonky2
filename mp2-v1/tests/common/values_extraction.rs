//! Test utilities for Values Extraction (C.1)

use super::{storage_trie::TestStorageTrie, TestContext};
use ethers::prelude::Address;
use log::info;
use mp2_common::{
    eth::{ProofQuery, StorageSlot},
    mpt_sequential::utils::bytes_to_nibbles,
    F,
};
use mp2_v1::{api::ProofWithVK, values_extraction::public_inputs::PublicInputs};
use plonky2::field::types::Field;
use std::str::FromStr;

type MappingKey = Vec<u8>;

impl TestContext {
    /// Generate the Values Extraction (C.1) proof for single variables.
    pub async fn prove_single_values_extraction(
        &self,
        contract_address: &str,
        slots: &[u8],
    ) -> ProofWithVK {
        let contract_address = Address::from_str(contract_address).unwrap();

        // Initialize the test trie.
        let mut trie = TestStorageTrie::new();
        info!("Initialized the test storage trie");

        // Query the slot and add the node path to the trie.
        for slot in slots {
            info!("Query the simple slot {slot}");
            let slot = *slot as usize;
            let query = ProofQuery::new_simple_slot(contract_address, slot);
            let response = self.query_mpt_proof(&query).await;

            // Get the nodes to prove. Reverse to the sequence from leaf to root.
            let nodes: Vec<_> = response.storage_proof[0]
                .proof
                .iter()
                .rev()
                .map(|node| node.to_vec())
                .collect();

            let slot = StorageSlot::Simple(slot);
            info!("Save the simple slot {slot:?} to the test storage trie");

            trie.add_slot(slot, nodes);
        }

        info!("Prove the test storage trie including the simple slots {slots:?}");
        let proof = trie.prove_all(&contract_address, self.params());

        // Check the public inputs.
        let pi = PublicInputs::new(&proof.proof().public_inputs);
        assert_eq!(pi.n(), F::from_canonical_usize(slots.len()));
        assert_eq!(pi.root_hash(), trie.root_hash());
        {
            let exp_key = StorageSlot::Simple(slots[0] as usize).mpt_key_vec();
            let exp_key: Vec<_> = bytes_to_nibbles(&exp_key)
                .into_iter()
                .map(F::from_canonical_u8)
                .collect();

            let (key, ptr) = pi.mpt_key_info();
            assert_eq!(key, exp_key);
            assert_eq!(ptr, F::NEG_ONE);
        }

        proof
    }

    /// Generate the Values Extraction (C.1) proof for mapping variables.
    pub async fn prove_mapping_values_extraction(
        &self,
        contract_address: &str,
        slot: u8,
        mapping_keys: Vec<MappingKey>,
    ) -> ProofWithVK {
        let slot = slot as usize;
        let contract_address = Address::from_str(contract_address).unwrap();

        let first_mapping_key = mapping_keys[0].clone();
        let storage_slot_number = mapping_keys.len();

        // Initialize the test trie.
        let mut trie = TestStorageTrie::new();
        info!("Initialized the test storage trie");

        // Query the slot and add the node path to the trie.
        for mapping_key in mapping_keys {
            info!("Query the mapping slot ({slot}, {mapping_key:?})");
            let query = ProofQuery::new_mapping_slot(contract_address, slot, mapping_key.clone());
            let response = self.query_mpt_proof(&query).await;

            // Get the nodes to prove. Reverse to the sequence from leaf to root.
            let mut nodes: Vec<_> = response.storage_proof[0]
                .proof
                .iter()
                .rev()
                .map(|node| node.to_vec())
                .collect();

            let slot = StorageSlot::Mapping(mapping_key, slot);
            info!("Save the mapping slot {slot:?} to the test storage trie");

            trie.add_slot(slot, nodes);
        }

        info!("Prove the test storage trie including the mapping slots ({slot}, ...)");
        let proof = trie.prove_all(&contract_address, self.params());

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

        proof
    }
}
