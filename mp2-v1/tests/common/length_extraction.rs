use std::str::FromStr;

use ethers::prelude::Address;
use log::info;
use mp2_common::{eth::StorageSlot, mpt_sequential::utils::bytes_to_nibbles, types::GFp};
use mp2_v1::{api::ProofWithVK, length_extraction::PublicInputs};
use plonky2::field::types::Field;

use crate::common::storage_trie::TestStorageTrie;

use super::TestContext;

impl TestContext {
    /// Generate the Values Extraction (C.2) proof for single variables.
    pub(crate) async fn prove_length_extraction(
        &self,
        contract_address: &str,
        slots: &[u8],
        variable_slot: u8,
    ) -> ProofWithVK {
        let contract_address = Address::from_str(contract_address).unwrap();

        // Initialize the test trie.
        let mut trie = TestStorageTrie::new();
        info!("Initialized the test storage trie");

        // Query the slot and add the node path to the trie.
        for slot in slots {
            trie.query_proof_and_add_slot(self, contract_address, *slot as usize)
                .await;
        }

        info!("Prove the test storage trie including the simple slots {slots:?}");
        let proof = trie.prove_length(&contract_address, variable_slot, self.params());

        // Check the public inputs.
        let pi = PublicInputs::from_slice(&proof.proof().public_inputs);
        let root: Vec<_> = trie
            .root_hash()
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        assert_eq!(pi.root_hash(), &root, "root of the trie should match");

        {
            let exp_key = StorageSlot::Simple(slots[0] as usize).mpt_key_vec();
            let exp_key: Vec<_> = bytes_to_nibbles(&exp_key)
                .into_iter()
                .map(GFp::from_canonical_u8)
                .collect();

            assert_eq!(
                pi.mpt_key(),
                exp_key,
                "MPT key is immutable for the whole path"
            );
            assert_eq!(
                pi.mpt_key_pointer(),
                &GFp::NEG_ONE,
                "at root, pointer should be -1"
            );
        }

        proof
    }
}