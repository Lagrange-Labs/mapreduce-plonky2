use alloy::primitives::{keccak256, B256};
use anyhow::Result;
use mp2_common::{
    eth::{EventLogInfo, ReceiptProofInfo},
    mpt_sequential::PAD_LEN,
};

use ryhope::storage::updatetree::UpdateTree;
use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use crate::values_extraction::compute_receipt_metadata_digest_for_empty_circuit;

use super::{
    CircuitInput, Extractable, ExtractionUpdatePlan, InputEnum, MP2PlannerError, ProofData,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptBlockData {
    proofs: Vec<ReceiptProofInfo>,
    receipt_root: B256,
    epoch: u64,
}

impl ReceiptBlockData {
    pub fn new(proofs: Vec<ReceiptProofInfo>, receipt_root: B256, epoch: u64) -> Self {
        Self {
            proofs,
            receipt_root,
            epoch,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    pub fn receipt_root(&self) -> B256 {
        self.receipt_root
    }

    pub fn proofs(&self) -> &[ReceiptProofInfo] {
        &self.proofs
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl<const NO_TOPICS: usize, const MAX_DATA_WORDS: usize> Extractable
    for EventLogInfo<NO_TOPICS, MAX_DATA_WORDS>
{
    type ExtraLeafInput = u64;
    type BlockData = ReceiptBlockData;

    fn create_update_plan(
        data: &Self::BlockData,
    ) -> Result<ExtractionUpdatePlan<Self>, MP2PlannerError> {
        let mut proof_cache = HashMap::<B256, ProofData<Self>>::new();

        // Convert the paths into their keys using keccak
        if data.is_empty() {
            let dummy_input = InputEnum::Dummy(data.receipt_root());
            let proof_data = ProofData::<Self> {
                node: vec![],
                extra_inputs: dummy_input,
            };

            proof_cache.insert(data.receipt_root(), proof_data);

            let update_tree =
                UpdateTree::<B256>::from_path(vec![data.receipt_root()], data.epoch() as i64);

            Ok(ExtractionUpdatePlan::new(update_tree, proof_cache))
        } else {
            let key_paths = data
                .proofs()
                .iter()
                .map(|input| {
                    let proof_len = input.mpt_proof.len();

                    // First we add the leaf and its proving data to the cache
                    let leaf = input
                        .mpt_proof
                        .last()
                        .ok_or(MP2PlannerError::UpdateTreeError(
                            "MPT proof had no nodes".to_string(),
                        ))?;
                    let leaf_key = keccak256(leaf);
                    let leaf_proof_data =
                        ProofData::<Self>::from_slice(leaf, InputEnum::Leaf(input.tx_index))?;

                    proof_cache.insert(leaf_key, leaf_proof_data);

                    input
                        .mpt_proof
                        .iter()
                        .take(proof_len - 1)
                        .map(|proof_vec| {
                            let proof_key = keccak256(proof_vec);
                            let proof_input = InputEnum::<Self>::empty_non_leaf(proof_vec)?;
                            let proof_data = ProofData::<Self>::from_slice(proof_vec, proof_input)?;
                            proof_cache.insert(proof_key, proof_data);
                            Ok(proof_key)
                        })
                        .chain(std::iter::once(Ok(leaf_key)))
                        .collect::<Result<Vec<B256>, MP2PlannerError>>()
                })
                .collect::<Result<Vec<Vec<B256>>, MP2PlannerError>>()?;

            // Now we make the UpdateTree
            let update_tree = UpdateTree::<B256>::from_paths(key_paths, data.epoch() as i64);

            // Finally make the plan
            Ok(ExtractionUpdatePlan::<Self>::new(update_tree, proof_cache))
        }
    }

    fn to_circuit_input<const LEAF_LEN: usize, const MAX_EXTRACTED_COLUMNS: usize>(
        extractable: &Self,
        proof_data: &ProofData<Self>,
    ) -> CircuitInput<LEAF_LEN, MAX_EXTRACTED_COLUMNS>
    where
        [(); PAD_LEN(LEAF_LEN)]:,
        Self: Sized,
    {
        let ProofData { node, extra_inputs } = proof_data;
        match extra_inputs {
            InputEnum::Branch(child_proofs) => {
                CircuitInput::new_branch(node.clone(), child_proofs.clone())
            }
            InputEnum::Extension(child_proof) => {
                CircuitInput::new_extension(node.clone(), child_proof.clone())
            }
            InputEnum::Leaf(tx_index) => {
                CircuitInput::new_receipt_leaf(node, *tx_index, extractable)
            }
            InputEnum::Dummy(block_hash) => {
                let metadata_digest =
                    compute_receipt_metadata_digest_for_empty_circuit(extractable);
                CircuitInput::new_dummy(*block_hash, metadata_digest)
            }
        }
    }
}

#[cfg(test)]
pub mod tests {

    use alloy::{primitives::Address, providers::ProviderBuilder, sol};
    use anyhow::anyhow;

    use mp2_common::eth::ReceiptProofInfo;
    use mp2_test::eth::get_mainnet_url;

    use std::str::FromStr;

    use super::*;

    #[tokio::test]
    async fn test_receipt_update_tree() -> Result<()> {
        // First get the info we will feed in to our function
        let epoch: u64 = 21362445;
        let (receipts_root, event_info, _) = build_test_data(epoch).await?;

        let url = get_mainnet_url();
        // get some tx and receipt
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());

        let (proofs, receipt_root) = event_info
            .query_receipt_proofs(&provider, epoch.into())
            .await?;

        let block_data = ReceiptBlockData::new(proofs, receipt_root, epoch);
        let extraction_plan = EventLogInfo::<2, 1>::create_update_plan(&block_data)?;

        assert_eq!(*extraction_plan.update_tree.root(), receipts_root);
        Ok(())
    }

    type TestData = (B256, EventLogInfo<2, 1>, Vec<ReceiptProofInfo>);
    /// Function that fetches a block together with its transaction trie and receipt trie for testing purposes.
    async fn build_test_data(block_number: u64) -> Result<TestData> {
        let url = get_mainnet_url();
        // get some tx and receipt
        let provider = ProviderBuilder::new().on_http(url.parse()?);

        let event_info = test_receipt_trie_helper().await?;
        let mut proof_info = vec![];
        let mut root = B256::default();
        let mut success = false;
        for _ in 0..10 {
            match event_info
                .query_receipt_proofs(&provider, block_number.into())
                .await
            {
                // For each of the logs return the transacion its included in, then sort and remove duplicates.
                Ok((response, fetched_root)) => {
                    proof_info = response;
                    root = fetched_root;
                    success = true;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            }
        }

        if !success {
            return Err(anyhow!("Could not query mainnet successfully"));
        }

        Ok((root, event_info, proof_info))
    }

    /// Function to build a list of [`ReceiptProofInfo`] for a set block.
    async fn test_receipt_trie_helper() -> Result<EventLogInfo<2, 1>> {
        // First we choose the contract and event we are going to monitor.
        // We use the mainnet PudgyPenguins contract at address 0xbd3531da5cf5857e7cfaa92426877b022e612cf8
        // and monitor for the `Approval` event.
        let address = Address::from_str("0xbd3531da5cf5857e7cfaa92426877b022e612cf8")?;

        // We have to create what the event abi looks like
        sol! {
            #[allow(missing_docs)]
            #[sol(rpc, abi)]
            contract EventTest {
            #[derive(Debug)]
            event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

            }
        };

        let approval_event = EventTest::abi::events()
            .get("ApprovalForAll")
            .ok_or(anyhow!("No ApprovalForAll event exists"))?[0]
            .clone();

        Ok(EventLogInfo::<2, 1>::new(
            address,
            1u64,
            &approval_event.signature(),
        ))
    }
}
