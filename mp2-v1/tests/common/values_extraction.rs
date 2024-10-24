//! Test utilities for Values Extraction (C.1)

use super::{storage_trie::TestStorageTrie, TestContext};
use crate::common::StorageSlotInfo;
use alloy::{eips::BlockNumberOrTag, primitives::Address, providers::Provider};
use log::info;
use mp2_common::F;
use mp2_v1::values_extraction::public_inputs::PublicInputs;
use plonky2::field::types::Field;

impl TestContext {
    /// Generate the Values Extraction proof for single or mapping variables.
    pub(crate) async fn prove_values_extraction(
        &self,
        contract_address: &Address,
        bn: BlockNumberOrTag,
        slots: &[StorageSlotInfo],
    ) -> Vec<u8> {
        // Initialize the test trie.
        let mut trie = TestStorageTrie::new();
        info!("Initialized the test storage trie");

        // Query the slot and add the node path to the trie.
        for slot_info in slots {
            trie.query_proof_and_add_slot(self, contract_address, bn, slot_info.clone())
                .await;
        }

        let chain_id = self.rpc.get_chain_id().await.unwrap();
        let proof_value = trie.prove_value(contract_address, chain_id, self.params(), &self.b);

        // Check the public inputs.
        let pi = PublicInputs::new(&proof_value.proof().public_inputs);
        assert_eq!(pi.root_hash(), trie.root_hash());
        assert_eq!(pi.n(), F::from_canonical_usize(slots.len()));

        proof_value.serialize().unwrap()
    }
}
