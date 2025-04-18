use alloy::{eips::BlockNumberOrTag, primitives::Address, providers::Provider};
use log::info;
use mp2_common::{
    eth::StorageSlot, mpt_sequential::utils::bytes_to_nibbles, proof::ProofWithVK, types::GFp,
};
use mp2_v1::{length_extraction::PublicInputs, values_extraction::StorageSlotInfo};
use plonky2::field::types::Field;

use crate::common::storage_trie::TestStorageTrie;

use super::TestContext;

impl TestContext {
    /// Generate the Values Extraction (C.2) proof for single variables.
    #[allow(dead_code)]
    pub(crate) async fn prove_length_extraction(
        &self,
        contract_address: &Address,
        bn: BlockNumberOrTag,
        slot_info: StorageSlotInfo,
        value: u8,
    ) -> ProofWithVK {
        // Initialize the test trie.
        let mut trie = TestStorageTrie::new();
        info!("Initialized the test storage trie");

        let slot = slot_info.slot().slot();

        // Query the slot and add the node path to the trie.
        trie.query_proof_and_add_slot(self, contract_address, bn, slot_info)
            .await;
        let chain_id = self.rpc.get_chain_id().await.unwrap();
        let proof = trie.prove_length(contract_address, chain_id, value, self.params(), &self.b);

        // Check the public inputs.
        let pi = PublicInputs::from_slice(&proof.proof().public_inputs);
        let root: Vec<_> = trie
            .root_hash()
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        assert_eq!(pi.root_hash_raw(), &root, "root of the trie should match");

        {
            let exp_key = StorageSlot::Simple(slot as usize).mpt_key_vec();
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
