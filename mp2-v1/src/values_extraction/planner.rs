//! This code returns an [`UpdateTree`] used to plan how we prove a series of values was extracted from a Merkle Patricia Trie.
use alloy::{
    eips::BlockNumberOrTag,
    network::Ethereum,
    primitives::{keccak256, B256},
    providers::{Provider, RootProvider},
    transports::Transport,
};
use anyhow::Result;
use mp2_common::{
    eth::{node_type, EventLogInfo, MP2EthError, NodeType},
    mpt_sequential::PAD_LEN,
};

use ryhope::{
    error::RyhopeError,
    storage::updatetree::{Next, UpdateTree},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{fmt::Debug, future::Future, hash::Hash};

use std::{
    collections::HashMap,
    error::Error,
    fmt::{Display, Formatter},
    write,
};

use super::{
    gadgets::metadata_gadget::TableMetadata, generate_proof, CircuitInput, PublicParameters,
};

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
    /// Error from within Ryhope
    RyhopeError(RyhopeError),
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
            MP2PlannerError::RyhopeError(e) => {
                write!(f, "Error in Ryhope method {{ inner: {:?} }}", e)
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

impl From<RyhopeError> for MP2PlannerError {
    fn from(value: RyhopeError) -> Self {
        MP2PlannerError::RyhopeError(value)
    }
}

/// Enum used for supplying extra inputs needed to convert [`ProofData`] to [`CircuitInput`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InputEnum<E: Extractable> {
    /// Leaf Variant that contains the extra inputs that depend on the implementation of [`Extractable`]
    Leaf(E::ExtraLeafInput),
    /// Extension extra input should be a single child proof
    Extension(Vec<u8>),
    /// Branch extra inputs should be a list of child proofs
    Branch(Vec<Vec<u8>>),
    /// A dummy input just requires the root hash of the tree and the metadata digest for the extracted item
    Dummy(B256),
}

impl<E: Extractable> InputEnum<E> {
    /// Create a new Branch or extension node with empty input
    pub fn empty_non_leaf(node: &[u8]) -> Result<Self, MP2PlannerError> {
        let node_type = node_type(node)?;
        // Match on the node type to make sure we can create an empty version.
        match node_type {
            NodeType::Branch => Ok(InputEnum::Branch(vec![])),
            NodeType::Extension => Ok(InputEnum::Extension(vec![])),
            _ => Err(MP2PlannerError::UpdateTreeError(
                "Tried to make an empty node from a MPT node that wasn't a Branch or Extension"
                    .to_string(),
            )),
        }
    }
}

/// Trait that is implemented for all data that we can provably extract.
pub trait Extractable: Debug {
    /// The extra info needed to make a leaf proof for this extraction type.
    type ExtraLeafInput: Clone
        + Debug
        + Serialize
        + DeserializeOwned
        + PartialEq
        + Eq
        + Ord
        + PartialOrd
        + Hash;
    /// Method that creates an [`ExtractionUpdatePlan`] that can then be processed either locally or in a distributed fashion.
    fn create_update_plan<T: Transport + Clone>(
        &self,
        epoch: u64,
        provider: &RootProvider<T, Ethereum>,
    ) -> impl Future<Output = Result<ExtractionUpdatePlan<Self>, MP2PlannerError>>
    where
        Self: Sized;
    /// Method that defines how to convert [`ProofData`] into [`CircuitInput`] for this implementation.
    fn to_circuit_input<const LEAF_LEN: usize, const MAX_EXTRACTED_COLUMNS: usize>(
        &self,
        proof_data: &ProofData<Self>,
    ) -> CircuitInput<LEAF_LEN, MAX_EXTRACTED_COLUMNS>
    where
        [(); PAD_LEN(LEAF_LEN)]:,
        Self: Sized;
    /// Method provided for building and processing an [`ExtractionUpdatePlan`] locally.
    fn prove_value_extraction<
        const MAX_EXTRACTED_COLUMNS: usize,
        const LEAF_LEN: usize,
        T: Transport + Clone,
    >(
        &self,
        epoch: u64,
        pp: &PublicParameters<LEAF_LEN, MAX_EXTRACTED_COLUMNS>,
        provider: &RootProvider<T, Ethereum>,
    ) -> impl Future<Output = Result<Vec<u8>, MP2PlannerError>>
    where
        [(); PAD_LEN(LEAF_LEN)]:;
}

/// Struct that stores the MPT node along with any extra data needed for the [`CircuitInput`] API.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct ProofData<E: Extractable> {
    /// The MPT node
    node: Vec<u8>,
    /// Extra inputs as defined by the implementor of [`Extractable`]
    extra_inputs: InputEnum<E>,
}

impl<E: Extractable> ProofData<E> {
    /// Create a new instance of [`ProofData`]
    pub fn new(node: Vec<u8>, extra_inputs: InputEnum<E>) -> ProofData<E> {
        ProofData::<E> { node, extra_inputs }
    }

    /// Create a new instance of [`ProofData`] from a slice of [`u8`] and any extra data required.
    pub fn from_slice(
        node: &[u8],
        extra_inputs: InputEnum<E>,
    ) -> Result<ProofData<E>, MP2PlannerError> {
        let node_type = node_type(node)?;

        // Check that the node type matches the extra input type we expect.
        if !matches!(
            (node_type, &extra_inputs),
            (NodeType::Branch, InputEnum::Branch(..))
                | (NodeType::Extension, InputEnum::Extension(..))
                | (NodeType::Leaf, InputEnum::Leaf(..))
        ) {
            return Err(MP2PlannerError::ProvingError(format!(
                "The node provided: {:?} did not match the extra input type provided: {:?} ",
                node_type, extra_inputs
            )));
        }

        Ok(ProofData::<E>::new(node.to_vec(), extra_inputs))
    }

    /// Update a [`ProofData`] with a proof represented as a [`Vec<u8>`]. This method
    /// will error if called on a node whose `extra_inputs` are not either the
    /// [`InputEnum::Extension`] or [`InputEnum::Branch`] variant.
    pub fn update(&mut self, proof: Vec<u8>) -> Result<(), MP2PlannerError> {
        match self.extra_inputs {
            // If its a branch simply push the proof into the stored vec
            InputEnum::Branch(ref mut proofs) => proofs.push(proof),
            // For an extension we check that the vec is currently empty, if it is we replace it with
            // the provided one.
            InputEnum::Extension(ref mut inner_proof) => {
                if !proof.is_empty() {
                    return Err(MP2PlannerError::UpdateTreeError(
                        "Can't update Extension ProofData if its child proof isn't empty"
                            .to_string(),
                    ));
                }
                *inner_proof = proof;
            }
            _ => {
                return Err(MP2PlannerError::UpdateTreeError(
                    "Can't update a Proof Data that isn't an Extension or Branch".to_string(),
                ))
            }
        };

        Ok(())
    }
}

/// A struct that stores an [`UpdateTree`] of keys and a local cache of [`ProofData`].
/// This way when a [`WorkplanItem`](ryhope::storage::updatetree::WorkplanItem) is processed we can update the cache so any parent proofs can
/// be processed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionUpdatePlan<E: Extractable> {
    /// The [`UpdateTree`] that specifies the order proofs should be generated.
    pub(crate) update_tree: UpdateTree<B256>,
    /// The cache of input data, at the beginning only the keys relating to leaf proofs will have all data
    /// provided, it should then be updated as these tasks are processed.
    pub(crate) proof_cache: HashMap<B256, ProofData<E>>,
}

impl<E: Extractable> ExtractionUpdatePlan<E> {
    /// Create a new [`ExtractionUpdatePlan`] from its constituent parts.
    pub fn new(update_tree: UpdateTree<B256>, proof_cache: HashMap<B256, ProofData<E>>) -> Self {
        Self {
            update_tree,
            proof_cache,
        }
    }
    /// Method to run the plan to completion locally. For each item in the [`UpdatePlan`](ryhope::storage::updatetree::UpdatePlan) we fetch the data from [`self.proof_cache`](ExtractionUpdatePlan::proof_cache)
    /// convert the [`ProofData`] to a [`CircuitInput`] which we then pass to the [`generate_proof`] function defined in [`crate::values_extraction::api`]. We then take the output proof
    /// and if the current key has a parent node in [`self.update_tree`](ExtractionUpdatePlan::update_tree) we update the [`ProofData`] stored for this key. If no parent is present we must be at the root of the tree
    /// and so we just return the final proof.
    pub fn process_locally<const LEAF_LEN: usize, const MAX_EXTRACTED_COLUMNS: usize>(
        &mut self,
        params: &PublicParameters<LEAF_LEN, MAX_EXTRACTED_COLUMNS>,
        extractable: &E,
    ) -> Result<Vec<u8>, MP2PlannerError>
    where
        [(); PAD_LEN(LEAF_LEN)]:,
    {
        // Convert the UpdateTree into an UpdatePlan
        let mut update_plan = self.update_tree.clone().into_workplan();
        // Instantiate a vector that will eventually be the output.
        let mut final_proof = Vec::<u8>::new();
        // Run the loop while the UpdatePlan continues to yield tasks.
        while let Some(Next::Ready(work_plan_item)) = update_plan.next() {
            // Retrieve proof data related to this key
            let proof_data = self.proof_cache.get(work_plan_item.k()).ok_or(
                MP2PlannerError::UpdateTreeError("Key not present in the proof cache".to_string()),
            )?;
            // Convert to CircuitInput
            let circuit_type = extractable.to_circuit_input(proof_data);

            // Generate the proof
            let proof = generate_proof(params, circuit_type).map_err(|e| {
                MP2PlannerError::ProvingError(format!(
                    "Error while generating proof for node {{ inner: {:?} }}",
                    e
                ))
            })?;

            // Fetch the parent of this key
            let parent = self.update_tree.get_parent_key(work_plan_item.k());
            // Determine next steps based on whether the parent exists
            match parent {
                Some(parent_key) => {
                    let proof_data_ref = self.proof_cache.get_mut(&parent_key).unwrap();
                    proof_data_ref.update(proof)?
                }
                None => {
                    final_proof = proof;
                }
            }
            // Mark the item as done
            update_plan.done(&work_plan_item)?;
        }
        Ok(final_proof)
    }
}

impl<const NO_TOPICS: usize, const MAX_DATA_WORDS: usize> Extractable
    for EventLogInfo<NO_TOPICS, MAX_DATA_WORDS>
{
    type ExtraLeafInput = u64;
    async fn create_update_plan<T: Transport + Clone>(
        &self,
        epoch: u64,
        provider: &RootProvider<T, Ethereum>,
    ) -> Result<ExtractionUpdatePlan<Self>, MP2PlannerError> {
        // Query for the receipt proofs relating to this event at block number `epoch`
        let proofs = self.query_receipt_proofs(provider, epoch.into()).await?;

        let mut proof_cache = HashMap::<B256, ProofData<Self>>::new();

        // Convert the paths into their keys using keccak
        if proofs.is_empty() {
            let block = provider
                .get_block_by_number(BlockNumberOrTag::Number(epoch), false.into())
                .await
                .map_err(|_| MP2PlannerError::FetchError)?
                .ok_or(MP2PlannerError::UpdateTreeError(
                    "Fetched Block with no relevant events but the result was None".to_string(),
                ))?;
            let receipt_root = block.header.receipts_root;

            let dummy_input = InputEnum::Dummy(receipt_root);
            let proof_data = ProofData::<Self> {
                node: vec![],
                extra_inputs: dummy_input,
            };

            proof_cache.insert(receipt_root, proof_data);

            let update_tree = UpdateTree::<B256>::from_path(vec![receipt_root], epoch as i64);

            Ok(ExtractionUpdatePlan::new(update_tree, proof_cache))
        } else {
            let key_paths = proofs
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
            let update_tree = UpdateTree::<B256>::from_paths(key_paths, epoch as i64);

            // Finally make the plan
            Ok(ExtractionUpdatePlan::<Self>::new(update_tree, proof_cache))
        }
    }

    fn to_circuit_input<const LEAF_LEN: usize, const MAX_EXTRACTED_COLUMNS: usize>(
        &self,
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
            InputEnum::Leaf(tx_index) => CircuitInput::new_receipt_leaf(node, *tx_index, self),
            InputEnum::Dummy(block_hash) => {
                let metadata = TableMetadata::from_event_info(self);
                let metadata_digest = metadata.digest();
                CircuitInput::new_dummy(*block_hash, metadata_digest)
            }
        }
    }

    async fn prove_value_extraction<
        const MAX_EXTRACTED_COLUMNS: usize,
        const LEAF_LEN: usize,
        T: Transport + Clone,
    >(
        &self,
        epoch: u64,
        pp: &PublicParameters<LEAF_LEN, MAX_EXTRACTED_COLUMNS>,
        provider: &RootProvider<T, Ethereum>,
    ) -> Result<Vec<u8>, MP2PlannerError>
    where
        [(); PAD_LEN(LEAF_LEN)]:,
    {
        let mut extraction_plan = self.create_update_plan(epoch, provider).await?;

        extraction_plan.process_locally(pp, self)
    }
}

#[cfg(test)]
pub mod tests {

    use alloy::{eips::BlockNumberOrTag, primitives::Address, providers::ProviderBuilder, sol};
    use anyhow::anyhow;
    use eth_trie::Trie;
    use mp2_common::{
        digest::Digest,
        eth::{BlockUtil, ReceiptProofInfo},
        proof::ProofWithVK,
        types::GFp,
        utils::{Endianness, Packer},
    };
    use mp2_test::eth::get_mainnet_url;
    use plonky2::field::types::Field;
    use plonky2_ecgfp5::curve::curve::Point;
    use std::str::FromStr;

    use crate::values_extraction::{
        api::build_circuits_params, gadgets::metadata_gadget::TableMetadata, PublicInputs,
    };

    use super::*;

    #[tokio::test]
    async fn test_receipt_update_tree() -> Result<()> {
        // First get the info we will feed in to our function
        let epoch: u64 = 21362445;
        let (block_util, event_info, _) = build_test_data(epoch).await?;

        let url = get_mainnet_url();
        // get some tx and receipt
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());

        let extraction_plan = event_info.create_update_plan(epoch, &provider).await?;

        assert_eq!(
            *extraction_plan.update_tree.root(),
            block_util.block.header.receipts_root
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_receipt_local_proving() -> Result<()> {
        let pp = build_circuits_params::<512, 5>();
        // Test proving on a block with some relevant events
        test_receipt_proving(21362445, &pp).await?;
        // Test proving on a block with no relevant events
        test_receipt_proving(21767312, &pp).await
    }

    async fn test_receipt_proving(epoch: u64, pp: &PublicParameters<512, 5>) -> Result<()> {
        // First get the info we will feed in to our function
        let (mut block_util, event_info, proof_info) = build_test_data(epoch).await?;

        let url = get_mainnet_url();
        // get some tx and receipt
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());

        let final_proof_bytes = event_info
            .prove_value_extraction(epoch, pp, &provider)
            .await?;

        let final_proof = ProofWithVK::deserialize(&final_proof_bytes)?;

        let metadata = TableMetadata::from(event_info);

        let metadata_digest = metadata.digest();

        let value_digest = proof_info.iter().try_fold(Digest::NEUTRAL, |acc, info| {
            let node = info
                .mpt_proof
                .last()
                .ok_or(MP2PlannerError::UpdateTreeError(
                    "MPT proof had no nodes".to_string(),
                ))?;
            Result::<Point, MP2PlannerError>::Ok(
                acc + metadata.receipt_value_digest(info.tx_index, node, &event_info),
            )
        })?;

        let pi = PublicInputs::new(&final_proof.proof.public_inputs);

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

        // Check that the number of rows is equal to the length of
        {
            assert_eq!(pi.n(), GFp::from_canonical_usize(proof_info.len()));
        }
        Ok(())
    }

    type TestData = (BlockUtil, EventLogInfo<2, 1>, Vec<ReceiptProofInfo>);
    /// Function that fetches a block together with its transaction trie and receipt trie for testing purposes.
    async fn build_test_data(block_number: u64) -> Result<TestData> {
        let url = get_mainnet_url();
        // get some tx and receipt
        let provider = ProviderBuilder::new().on_http(url.parse()?);

        // We fetch a specific block which we know includes transactions relating to the PudgyPenguins contract.
        let block_util =
            BlockUtil::fetch(&provider, BlockNumberOrTag::Number(block_number)).await?;

        let event_info = test_receipt_trie_helper().await?;
        let mut proof_info = vec![];
        let mut success = false;
        for _ in 0..10 {
            match event_info
                .query_receipt_proofs(&provider, block_number.into())
                .await
            {
                // For each of the logs return the transacion its included in, then sort and remove duplicates.
                Ok(response) => {
                    proof_info = response;
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

        Ok((block_util, event_info, proof_info))
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
