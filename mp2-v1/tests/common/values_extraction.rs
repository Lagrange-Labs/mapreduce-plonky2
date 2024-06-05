//! Test utilities for Values Extraction (C.1)

use super::{storage_trie::TestStorageTrie, TestContext};
use ethers::prelude::Address;
use log::info;
use mp2_common::eth::{ProofQuery, StorageSlot};
use mp2_v1::api::ProofWithVK;
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
            let mut nodes: Vec<_> = response.storage_proof[0]
                .proof
                .iter()
                .map(|node| node.to_vec())
                .collect();
            nodes.reverse();

            let slot = StorageSlot::Simple(slot);
            info!("Save the simple slot {slot:?} to the test storage trie");

            trie.add_slot(slot, nodes);
        }

        info!("Prove the test storage trie including the simple slots {slots:?}");
        trie.prove_all(&contract_address, self.params())
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
                .map(|node| node.to_vec())
                .collect();
            nodes.reverse();

            let slot = StorageSlot::Mapping(mapping_key, slot);
            info!("Save the mapping slot {slot:?} to the test storage trie");

            trie.add_slot(slot, nodes);
        }

        info!("Prove the test storage trie including the mapping slots ({slot}, ...)");
        trie.prove_all(&contract_address, self.params())
    }
}
