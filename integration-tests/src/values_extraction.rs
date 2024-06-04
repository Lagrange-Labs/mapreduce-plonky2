//! Test utilities for Values Extraction (C.1)

use crate::TestContext;
use ethers::{
    prelude::Address,
    utils::rlp::{Prototype, Rlp},
};
use mp2_common::eth::ProofQuery;
use mp2_v1::{
    api::{CircuitInput, ProofWithVK},
    values_extraction,
};
use std::str::FromStr;

// RLP item size for the extension and branch nodes
const EXTENSION_RLP_SIZE: usize = 2;
const BRANCH_RLP_SIZE: usize = 17;

impl TestContext {
    /// Generate the Values Extraction (C.1) proof for single variables.
    pub async fn prove_single_values_extraction(
        &self,
        contract_address: &str,
        slot: u8,
    ) -> ProofWithVK {
        // Query the MPT proof.
        let contract_address = Address::from_str(contract_address).unwrap();
        let query = ProofQuery::new_simple_slot(contract_address, slot as usize);
        let response = self.query_mpt_proof(&query).await;

        // Get the nodes to prove. The nodes are arranged in the reverse order,
        // and contains 1 branch and 1 leaf as least.
        let nodes = &response.storage_proof[0].proof;
        assert!(nodes.len() > 1);

        // Generate the leaf node for the last node.
        let input = CircuitInput::ValuesExtraction(
            values_extraction::api::CircuitInput::new_single_variable_leaf(
                nodes.last().unwrap().to_vec(),
                slot,
                &contract_address,
            ),
        );
        let proof = self.generate_proof(input);

        // Reverse and iterate the node array (excluding the leaf) to generate
        // the proof for the current trie.
        let proof = nodes[..nodes.len() - 1]
            .iter()
            .rev()
            .fold(proof, |child_proof, node| {
                let rlp = Rlp::new(&node);
                let input = match rlp.prototype().unwrap() {
                    // Extension node
                    Prototype::List(EXTENSION_RLP_SIZE) => {
                        values_extraction::CircuitInput::new_extension(node.to_vec(), child_proof)
                    }
                    // Branch node
                    Prototype::List(BRANCH_RLP_SIZE) => {
                        values_extraction::CircuitInput::new_single_variable_branch(
                            node.to_vec(),
                            vec![child_proof],
                        )
                    }
                    _ => panic!("Invalid RLP size for the storage proof"),
                };

                let input = CircuitInput::ValuesExtraction(input);
                self.generate_proof(input)
            });

        ProofWithVK::deserialize(&proof).unwrap()
    }

    /// Generate the Values Extraction (C.1) proof for mapping variables.
    pub async fn prove_mapping_values_extraction(
        &self,
        contract_address: &str,
        slot: u8,
        mapping_key: Vec<u8>,
    ) -> ProofWithVK {
        // Query the MPT proof.
        let contract_address = Address::from_str(contract_address).unwrap();
        let query =
            ProofQuery::new_mapping_slot(contract_address, slot as usize, mapping_key.clone());
        let response = self.query_mpt_proof(&query).await;

        // Get the nodes to prove. The nodes are arranged in the reverse order,
        // and contains 1 branch and 1 leaf as least.
        let nodes = &response.storage_proof[0].proof;
        assert!(nodes.len() > 1);

        // Generate the leaf node for the last node.
        let input = CircuitInput::ValuesExtraction(
            values_extraction::api::CircuitInput::new_mapping_variable_leaf(
                nodes.last().unwrap().to_vec(),
                slot,
                mapping_key,
                &contract_address,
            ),
        );
        let proof = self.generate_proof(input);

        // Reverse and iterate the node array (excluding the leaf) to generate
        // the proof for the current trie.
        let proof = nodes[..nodes.len() - 1]
            .iter()
            .rev()
            .fold(proof, |child_proof, node| {
                let rlp = Rlp::new(&node);
                let input = match rlp.prototype().unwrap() {
                    // Extension node
                    Prototype::List(EXTENSION_RLP_SIZE) => {
                        values_extraction::CircuitInput::new_extension(node.to_vec(), child_proof)
                    }
                    // Branch node
                    Prototype::List(BRANCH_RLP_SIZE) => {
                        values_extraction::CircuitInput::new_mapping_variable_branch(
                            node.to_vec(),
                            vec![child_proof],
                        )
                    }
                    _ => panic!("Invalid RLP size for the storage proof"),
                };

                let input = CircuitInput::ValuesExtraction(input);
                self.generate_proof(input)
            });

        ProofWithVK::deserialize(&proof).unwrap()
    }
}
