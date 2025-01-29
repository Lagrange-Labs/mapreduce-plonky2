//! This code returns an [`UpdateTree`] used to plan how we prove a series of values was extracted from a Merkle Patricia Trie.
use alloy::{
    network::Ethereum,
    primitives::{keccak256, Address, B256},
    providers::RootProvider,
    transports::Transport,
};
use anyhow::Result;
use mp2_common::eth::{node_type, EventLogInfo, MP2EthError, NodeType, ReceiptQuery};
use ryhope::storage::updatetree::{Next, UpdateTree};
use std::future::Future;

use std::{
    collections::HashMap,
    error::Error,
    fmt::{Display, Formatter},
    write,
};

use super::{generate_proof, CircuitInput, PublicParameters};

#[derive(Debug)]
/// Error enum used for Extractable data
pub enum MP2PlannerError {
    /// An error that occurs when trying to fetch data from an RPC node, used so that we can know we should retry the call in this case.
    FetchError,
    /// An error that occurs when the [`UpdateTree`] returns an unexpected output from one of its methods.
    UpdateTreeError(String),
    /// A conversion from the error type defined in [`mp2_common::eth`] that is not a [`MP2EthError::FetchError`].
    EthError(MP2EthError),
    /// An error that occurs from a method in the proving API.
    ProvingError(String),
}

impl Error for MP2PlannerError {}

impl Display for MP2PlannerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MP2PlannerError::FetchError => write!(
                f,
                "Error occured when trying to fetch data from an RPC node"
            ),
            MP2PlannerError::UpdateTreeError(s) => write!(
                f,
                "Error occured when working with the update Tree: {{ inner: {} }}",
                s
            ),
            MP2PlannerError::EthError(e) => write!(
                f,
                "Error occured in call from mp2_common::eth function {{ inner: {:?} }}",
                e
            ),
            MP2PlannerError::ProvingError(s) => {
                write!(f, "Error while proving, extra message: {}", s)
            }
        }
    }
}

impl From<MP2EthError> for MP2PlannerError {
    fn from(value: MP2EthError) -> Self {
        match value {
            MP2EthError::FetchError => MP2PlannerError::FetchError,
            _ => MP2PlannerError::EthError(value),
        }
    }
}

/// Trait that is implemented for all data that we can provably extract.
pub trait Extractable {
    fn create_update_tree<T: Transport + Clone>(
        &self,
        contract: Address,
        epoch: u64,
        provider: &RootProvider<T, Ethereum>,
    ) -> impl Future<Output = Result<UpdateTree<B256>, MP2PlannerError>>;

    fn prove_value_extraction<const MAX_COLUMNS: usize, T: Transport + Clone>(
        &self,
        contract: Address,
        epoch: u64,
        pp: &PublicParameters<512, MAX_COLUMNS>,
        provider: &RootProvider<T, Ethereum>,
    ) -> impl Future<Output = Result<Vec<u8>, MP2PlannerError>>;
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

impl<const NO_TOPICS: usize, const MAX_DATA_WORDS: usize> Extractable
    for EventLogInfo<NO_TOPICS, MAX_DATA_WORDS>
{
    async fn create_update_tree<T: Transport + Clone>(
        &self,
        contract: Address,
        epoch: u64,
        provider: &RootProvider<T, Ethereum>,
    ) -> Result<UpdateTree<B256>, MP2PlannerError> {
        let query = ReceiptQuery::<NO_TOPICS, MAX_DATA_WORDS> {
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

    async fn prove_value_extraction<const MAX_EXTRACTED_COLUMNS: usize, T: Transport + Clone>(
        &self,
        contract: Address,
        epoch: u64,
        pp: &PublicParameters<512, MAX_EXTRACTED_COLUMNS>,
        provider: &RootProvider<T, Ethereum>,
    ) -> Result<Vec<u8>, MP2PlannerError> {
        let query = ReceiptQuery::<NO_TOPICS, MAX_DATA_WORDS> {
            contract,
            event: *self,
        };

        let proofs = query.query_receipt_proofs(provider, epoch.into()).await?;

        let mut data_store = HashMap::<B256, ProofData>::new();

        // Convert the paths into their keys using keccak
        let key_paths = proofs
            .iter()
            .map(|input| {
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
                    .collect::<Result<Vec<B256>, MP2PlannerError>>()
            })
            .collect::<Result<Vec<Vec<B256>>, MP2PlannerError>>()?;

        let update_tree = UpdateTree::<B256>::from_paths(key_paths, epoch as i64);

        let mut update_plan = update_tree.clone().into_workplan();

        while let Some(Next::Ready(work_plan_item)) = update_plan.next() {
            let node_type = data_store
                .get(work_plan_item.k())
                .ok_or(MP2PlannerError::UpdateTreeError(format!(
                    "No ProofData found for key: {:?}",
                    work_plan_item.k()
                )))?
                .node_type;

            let update_tree_node = update_tree.get_node(work_plan_item.k()).ok_or(
                MP2PlannerError::UpdateTreeError(format!(
                    "No UpdateTreeNode found for key: {:?}",
                    work_plan_item.k(),
                )),
            )?;

            match node_type {
                NodeType::Leaf => {
                    let proof_data = data_store.get_mut(work_plan_item.k()).ok_or(
                        MP2PlannerError::UpdateTreeError(format!(
                            "No ProofData found for key: {:?}",
                            work_plan_item.k()
                        )),
                    )?;
                    let input = CircuitInput::new_receipt_leaf(
                        &proof_data.node,
                        proof_data.tx_index.unwrap(),
                        self,
                    );
                    let proof = generate_proof(pp, input).map_err(|_| {
                        MP2PlannerError::ProvingError(
                            "Error calling generate proof API".to_string(),
                        )
                    })?;
                    proof_data.proof = Some(proof);
                    update_plan.done(&work_plan_item).map_err(|_| {
                        MP2PlannerError::UpdateTreeError(
                            "Could not mark work plan item as done".to_string(),
                        )
                    })?;
                }
                NodeType::Extension => {
                    let child_key = update_tree.get_child_keys(update_tree_node);
                    if child_key.len() != 1 {
                        return Err(MP2PlannerError::ProvingError(format!(
                            "Expected nodes child keys to have length 1, actual length: {}",
                            child_key.len()
                        )));
                    }
                    let child_proof = data_store
                        .get(&child_key[0])
                        .ok_or(MP2PlannerError::UpdateTreeError(format!(
                            "Extension node child had no proof data for key: {:?}",
                            child_key[0]
                        )))?
                        .clone();
                    let proof_data = data_store.get_mut(work_plan_item.k()).ok_or(
                        MP2PlannerError::UpdateTreeError(format!(
                            "No ProofData found for key: {:?}",
                            work_plan_item.k()
                        )),
                    )?;
                    let input = CircuitInput::new_extension(
                        proof_data.node.clone(),
                        child_proof.proof.ok_or(MP2PlannerError::UpdateTreeError(
                            "Extension node child proof was a None value".to_string(),
                        ))?,
                    );
                    let proof = generate_proof(pp, input).map_err(|_| {
                        MP2PlannerError::ProvingError(
                            "Error calling generate proof API".to_string(),
                        )
                    })?;
                    proof_data.proof = Some(proof);
                    update_plan.done(&work_plan_item).map_err(|_| {
                        MP2PlannerError::UpdateTreeError(
                            "Could not mark work plan item as done".to_string(),
                        )
                    })?;
                }
                NodeType::Branch => {
                    let child_keys = update_tree.get_child_keys(update_tree_node);
                    let child_proofs = child_keys
                        .iter()
                        .map(|key| {
                            data_store
                                .get(key)
                                .ok_or(MP2PlannerError::UpdateTreeError(format!(
                                    "Branch child data could not be found for key: {:?}",
                                    key
                                )))?
                                .clone()
                                .proof
                                .ok_or(MP2PlannerError::UpdateTreeError(
                                    "No proof found in brnach node child".to_string(),
                                ))
                        })
                        .collect::<Result<Vec<Vec<u8>>, MP2PlannerError>>()?;
                    let proof_data = data_store.get_mut(work_plan_item.k()).ok_or(
                        MP2PlannerError::UpdateTreeError(format!(
                            "No ProofData found for key: {:?}",
                            work_plan_item.k()
                        )),
                    )?;
                    let input = CircuitInput::new_branch(proof_data.node.clone(), child_proofs);
                    let proof = generate_proof(pp, input).map_err(|_| {
                        MP2PlannerError::ProvingError(
                            "Error calling generate proof API".to_string(),
                        )
                    })?;
                    proof_data.proof = Some(proof);
                    update_plan.done(&work_plan_item).map_err(|_| {
                        MP2PlannerError::UpdateTreeError(
                            "Could not mark work plan item as done".to_string(),
                        )
                    })?;
                }
            }
        }

        let final_data = data_store
            .get(update_tree.root())
            .ok_or(MP2PlannerError::UpdateTreeError(
                "No data for root of update tree found".to_string(),
            ))?
            .clone();

        final_data.proof.ok_or(MP2PlannerError::UpdateTreeError(
            "No proof stored for final data".to_string(),
        ))
    }
}

#[cfg(test)]
pub mod tests {

    use alloy::{eips::BlockNumberOrTag, primitives::Address, providers::ProviderBuilder, sol};
    use anyhow::anyhow;
    use eth_trie::Trie;
    use mp2_common::{
        digest::Digest,
        eth::{left_pad32, BlockUtil},
        poseidon::{hash_to_int_value, H},
        proof::ProofWithVK,
        types::GFp,
        utils::{Endianness, Packer, ToFields},
    };
    use mp2_test::eth::get_mainnet_url;
    use plonky2::{field::types::Field, hash::hash_types::HashOut, plonk::config::Hasher};
    use plonky2_ecgfp5::curve::scalar_field::Scalar;
    use std::str::FromStr;

    use crate::values_extraction::{
        api::build_circuits_params, gadgets::metadata_gadget::TableMetadata, PublicInputs,
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

        let pp = build_circuits_params::<512, 7>();
        let final_proof_bytes = event_info
            .prove_value_extraction(contract, epoch, &pp, &provider)
            .await?;

        let final_proof = ProofWithVK::deserialize(&final_proof_bytes)?;
        let query = ReceiptQuery::<2, 1> {
            contract,
            event: event_info,
        };

        let metadata = TableMetadata::from(event_info);

        let metadata_digest = metadata.digest();

        let value_digest = query
            .query_receipt_proofs(&provider, epoch.into())
            .await?
            .iter()
            .fold(Digest::NEUTRAL, |acc, info| {
                let node = info.mpt_proof.last().unwrap().clone();

                let mut tx_index_input = [0u8; 32];
                tx_index_input[31] = info.tx_index as u8;

                let node_rlp = rlp::Rlp::new(&node);
                // The actual receipt data is item 1 in the list
                let receipt_rlp = node_rlp.at(1).unwrap();

                // We make a new `Rlp` struct that should be the encoding of the inner list representing the `ReceiptEnvelope`
                let receipt_list = rlp::Rlp::new(&receipt_rlp.data().unwrap()[1..]);

                // The logs themselves start are the item at index 3 in this list
                let gas_used_rlp = receipt_list.at(1).unwrap();

                let gas_used_bytes = left_pad32(gas_used_rlp.data().unwrap());

                let (input_vd, row_unique_data) =
                    metadata.input_value_digest(&[&tx_index_input, &gas_used_bytes]);
                let extracted_vd = metadata.extracted_receipt_value_digest(&node, &event_info);

                let total = input_vd + extracted_vd;

                // row_id = H2int(row_unique_data || num_actual_columns)
                let inputs = HashOut::from(row_unique_data)
                    .to_fields()
                    .into_iter()
                    .chain(std::iter::once(GFp::from_canonical_usize(
                        metadata.num_actual_columns,
                    )))
                    .collect::<Vec<GFp>>();
                let hash = H::hash_no_pad(&inputs);
                let row_id = hash_to_int_value(hash);

                // values_digest = values_digest * row_id
                let row_id = Scalar::from_noncanonical_biguint(row_id);

                let exp_digest = total * row_id;

                acc + exp_digest
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
