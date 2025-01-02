//! This code returns an [`UpdateTree`] used to plan how we prove a series of values was extracted from a Merkle Patricia Trie.
use alloy::{
    network::Ethereum,
    primitives::{keccak256, Address, B256},
    providers::RootProvider,
    transports::Transport,
};
use anyhow::Result;
use mp2_common::eth::{node_type, EventLogInfo, NodeType, ReceiptQuery};
use ryhope::storage::updatetree::{Next, UpdateTree};
use std::future::Future;

use std::collections::HashMap;

use super::{generate_proof, CircuitInput, PublicParameters};
/// Trait that is implemented for all data that we can provably extract.
pub trait Extractable {
    fn create_update_tree<T: Transport + Clone>(
        &self,
        contract: Address,
        epoch: u64,
        provider: &RootProvider<T, Ethereum>,
    ) -> impl Future<Output = Result<UpdateTree<B256>>>;

    fn prove_value_extraction<T: Transport + Clone>(
        &self,
        contract: Address,
        epoch: u64,
        pp: &PublicParameters,
        provider: &RootProvider<T, Ethereum>,
    ) -> impl Future<Output = Result<Vec<u8>>>;
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ProofData {
    node: Vec<u8>,
    node_type: NodeType,
    tx_index: Option<u64>,
    proof: Option<Vec<u8>>,
}

impl ProofData {
    pub fn new(node: Vec<u8>, node_type: NodeType, tx_index: Option<u64>) -> ProofData {
        ProofData {
            node,
            node_type,
            tx_index,
            proof: None,
        }
    }
}

impl<const NO_TOPICS: usize, const MAX_DATA: usize> Extractable
    for EventLogInfo<NO_TOPICS, MAX_DATA>
{
    async fn create_update_tree<T: Transport + Clone>(
        &self,
        contract: Address,
        epoch: u64,
        provider: &RootProvider<T, Ethereum>,
    ) -> Result<UpdateTree<B256>> {
        let query = ReceiptQuery::<NO_TOPICS, MAX_DATA> {
            contract,
            event: *self,
        };

        let proofs = query.query_receipt_proofs(provider, epoch.into()).await?;

        // Convert the paths into their keys using keccak
        let key_paths = proofs
            .iter()
            .map(|input| input.mpt_proof.iter().map(keccak256).collect::<Vec<B256>>())
            .collect::<Vec<Vec<B256>>>();

        // Now we make the UpdateTree
        Ok(UpdateTree::<B256>::from_paths(key_paths, epoch as i64))
    }

    async fn prove_value_extraction<T: Transport + Clone>(
        &self,
        contract: Address,
        epoch: u64,
        pp: &PublicParameters,
        provider: &RootProvider<T, Ethereum>,
    ) -> Result<Vec<u8>> {
        let query = ReceiptQuery::<NO_TOPICS, MAX_DATA> {
            contract,
            event: *self,
        };

        let proofs = query.query_receipt_proofs(provider, epoch.into()).await?;

        let mut data_store = HashMap::<B256, ProofData>::new();

        // Convert the paths into their keys using keccak
        let key_paths = proofs
            .iter()
            .map(|input| {
                let digest =
                    crate::values_extraction::compute_receipt_leaf_value_digest(input, self)
                        .to_weierstrass();
                println!("extraction proof values digest: {:?}", digest);
                let tx_index = input.tx_index;
                input
                    .mpt_proof
                    .iter()
                    .map(|node| {
                        let node_key = keccak256(node);
                        let node_type = node_type(node)?;
                        let tx = if let NodeType::Leaf = node_type {
                            Some(tx_index)
                        } else {
                            None
                        };
                        data_store.insert(node_key, ProofData::new(node.clone(), node_type, tx));

                        Ok(node_key)
                    })
                    .collect::<Result<Vec<B256>>>()
            })
            .collect::<Result<Vec<Vec<B256>>>>()?;

        let update_tree = UpdateTree::<B256>::from_paths(key_paths, epoch as i64);

        let mut update_plan = update_tree.clone().into_workplan();

        while let Some(Next::Ready(work_plan_item)) = update_plan.next() {
            let node_type = data_store
                .get(work_plan_item.k())
                .ok_or(anyhow::anyhow!(
                    "No ProofData found for key: {:?}",
                    work_plan_item.k()
                ))?
                .node_type;

            let update_tree_node =
                update_tree
                    .get_node(work_plan_item.k())
                    .ok_or(anyhow::anyhow!(
                        "No UpdateTreeNode found for key: {:?}",
                        work_plan_item.k()
                    ))?;

            match node_type {
                NodeType::Leaf => {
                    let proof_data =
                        data_store
                            .get_mut(work_plan_item.k())
                            .ok_or(anyhow::anyhow!(
                                "No ProofData found for key: {:?}",
                                work_plan_item.k()
                            ))?;
                    let input = CircuitInput::new_receipt_leaf(
                        &proof_data.node,
                        proof_data.tx_index.unwrap(),
                        self,
                    );
                    let proof = generate_proof(pp, input)?;
                    proof_data.proof = Some(proof);
                    update_plan.done(&work_plan_item)?;
                }
                NodeType::Extension => {
                    let child_key = update_tree.get_child_keys(update_tree_node);
                    if child_key.len() != 1 {
                        return Err(anyhow::anyhow!("When proving extension node had {} many child keys when we should only have 1", child_key.len()));
                    }
                    let child_proof = data_store
                        .get(&child_key[0])
                        .ok_or(anyhow::anyhow!(
                            "Extension node child had no proof data for key: {:?}",
                            child_key[0]
                        ))?
                        .clone();
                    let proof_data =
                        data_store
                            .get_mut(work_plan_item.k())
                            .ok_or(anyhow::anyhow!(
                                "No ProofData found for key: {:?}",
                                work_plan_item.k()
                            ))?;
                    let input = CircuitInput::new_extension(
                        proof_data.node.clone(),
                        child_proof.proof.ok_or(anyhow::anyhow!(
                            "Extension node child proof was a None value"
                        ))?,
                    );
                    let proof = generate_proof(pp, input)?;
                    proof_data.proof = Some(proof);
                    update_plan.done(&work_plan_item)?;
                }
                NodeType::Branch => {
                    let child_keys = update_tree.get_child_keys(update_tree_node);
                    let child_proofs = child_keys
                        .iter()
                        .map(|key| {
                            data_store
                                .get(key)
                                .ok_or(anyhow::anyhow!(
                                    "Branch child data could not be found for key: {:?}",
                                    key
                                ))?
                                .clone()
                                .proof
                                .ok_or(anyhow::anyhow!("No proof found in brnach node child"))
                        })
                        .collect::<Result<Vec<Vec<u8>>>>()?;
                    let proof_data =
                        data_store
                            .get_mut(work_plan_item.k())
                            .ok_or(anyhow::anyhow!(
                                "No ProofData found for key: {:?}",
                                work_plan_item.k()
                            ))?;
                    let input = CircuitInput::new_mapping_variable_branch(
                        proof_data.node.clone(),
                        child_proofs,
                    );
                    let proof = generate_proof(pp, input)?;
                    proof_data.proof = Some(proof);
                    update_plan.done(&work_plan_item)?;
                }
            }
        }

        let final_data = data_store
            .get(update_tree.root())
            .ok_or(anyhow::anyhow!("No data for root of update tree found"))?
            .clone();

        final_data
            .proof
            .ok_or(anyhow::anyhow!("No proof stored for final data"))
    }
}

#[cfg(test)]
pub mod tests {

    use alloy::{eips::BlockNumberOrTag, primitives::Address, providers::ProviderBuilder, sol};
    use anyhow::anyhow;
    use eth_trie::Trie;
    use mp2_common::{
        digest::Digest,
        eth::BlockUtil,
        proof::ProofWithVK,
        utils::{Endianness, Packer},
    };
    use mp2_test::eth::get_mainnet_url;
    use std::str::FromStr;

    use crate::values_extraction::{
        api::build_circuits_params, compute_receipt_leaf_metadata_digest,
        compute_receipt_leaf_value_digest, PublicInputs,
    };

    use super::*;

    #[tokio::test]
    async fn test_receipt_update_tree() -> Result<()> {
        // First get the info we will feed in to our function
        let event_info = test_receipt_trie_helper().await?;

        let contract = Address::from_str("0xbd3531da5cf5857e7cfaa92426877b022e612cf8")?;
        let epoch: u64 = 21362445;

        let url = get_mainnet_url();
        // get some tx and receipt
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());

        let update_tree = event_info
            .create_update_tree(contract, epoch, &provider)
            .await?;

        let block_util = build_test_data().await;

        assert_eq!(*update_tree.root(), block_util.block.header.receipts_root);
        Ok(())
    }

    #[tokio::test]
    async fn test_receipt_proving() -> Result<()> {
        // First get the info we will feed in to our function
        let event_info = test_receipt_trie_helper().await?;

        let contract = Address::from_str("0xbd3531da5cf5857e7cfaa92426877b022e612cf8")?;
        let epoch: u64 = 21362445;

        let url = get_mainnet_url();
        // get some tx and receipt
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());

        let pp = build_circuits_params();
        let final_proof_bytes = event_info
            .prove_value_extraction(contract, epoch, &pp, &provider)
            .await?;

        let final_proof = ProofWithVK::deserialize(&final_proof_bytes)?;
        let query = ReceiptQuery::<2, 1> {
            contract,
            event: event_info,
        };

        let metadata_digest = compute_receipt_leaf_metadata_digest(&event_info);

        let value_digest = query
            .query_receipt_proofs(&provider, epoch.into())
            .await?
            .iter()
            .fold(Digest::NEUTRAL, |acc, info| {
                acc + compute_receipt_leaf_value_digest(info, &event_info)
            });

        let pi = PublicInputs::new(&final_proof.proof.public_inputs);

        let mut block_util = build_test_data().await;
        // Check the output hash
        {
            assert_eq!(
                pi.root_hash(),
                block_util
                    .receipts_trie
                    .root_hash()?
                    .0
                    .to_vec()
                    .pack(Endianness::Little)
            );
        }

        // Check value digest
        {
            assert_eq!(pi.values_digest(), value_digest.to_weierstrass());
        }

        // Check metadata digest
        {
            assert_eq!(pi.metadata_digest(), metadata_digest.to_weierstrass());
        }
        Ok(())
    }

    /// Function that fetches a block together with its transaction trie and receipt trie for testing purposes.
    async fn build_test_data() -> BlockUtil {
        let url = get_mainnet_url();
        // get some tx and receipt
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());

        // We fetch a specific block which we know includes transactions relating to the PudgyPenguins contract.
        BlockUtil::fetch(&provider, BlockNumberOrTag::Number(21362445))
            .await
            .unwrap()
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
            &approval_event.signature(),
        ))
    }
}
