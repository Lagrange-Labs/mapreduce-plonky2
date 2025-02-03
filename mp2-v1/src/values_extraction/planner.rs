//! This code returns an [`UpdateTree`] used to plan how we prove a series of values was extracted from a Merkle Patricia Trie.
use alloy::{
    eips::BlockNumberOrTag,
    network::Ethereum,
    primitives::{keccak256, Address, B256},
    providers::{Provider, RootProvider},
    transports::Transport,
};
use anyhow::Result;
use mp2_common::{
    eth::{node_type, EventLogInfo, MP2EthError, NodeType, ReceiptQuery},
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

/// Trait used to mark types that are needed as extra circuit inputs
pub trait ExtraInput {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InputEnum<E: Extractable> {
    Leaf(E::ExtraLeafInput),
    Extension(Vec<u8>),
    Branch(Vec<Vec<u8>>),
    Dummy(B256),
}

impl<E: Extractable> InputEnum<E> {
    /// Create a new Branch or extension node with empty input
    pub fn empty_non_leaf(node: &[u8]) -> Result<Self, MP2PlannerError> {
        let node_type = node_type(node)?;
        match node_type {
            NodeType::Branch => Ok(InputEnum::Branch(vec![])),
            NodeType::Extension => Ok(InputEnum::Extension(vec![])),
            _ => Err(MP2PlannerError::UpdateTreeError("Tried to make an empty non leaf node from a node that wasn't a Branch or Extension".to_string()))
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

    fn create_update_tree<T: Transport + Clone>(
        &self,
        contract: Address,
        epoch: u64,
        provider: &RootProvider<T, Ethereum>,
    ) -> impl Future<Output = Result<ExtractionUpdatePlan<Self>, MP2PlannerError>>
    where
        Self: Sized;

    fn to_circuit_input<const LEAF_LEN: usize, const MAX_EXTRACTED_COLUMNS: usize>(
        &self,
        proof_data: &ProofData<Self>,
    ) -> CircuitInput<LEAF_LEN, MAX_EXTRACTED_COLUMNS>
    where
        [(); PAD_LEN(LEAF_LEN)]:,
        Self: Sized;

    fn prove_value_extraction<
        const MAX_EXTRACTED_COLUMNS: usize,
        const LEAF_LEN: usize,
        T: Transport + Clone,
    >(
        &self,
        contract: Address,
        epoch: u64,
        pp: &PublicParameters<LEAF_LEN, MAX_EXTRACTED_COLUMNS>,
        provider: &RootProvider<T, Ethereum>,
    ) -> impl Future<Output = Result<Vec<u8>, MP2PlannerError>>
    where
        [(); PAD_LEN(LEAF_LEN)]:;
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct ProofData<E: Extractable> {
    node: Vec<u8>,
    extra_inputs: InputEnum<E>,
}

impl<E: Extractable> ProofData<E> {
    pub fn new(node: Vec<u8>, extra_inputs: InputEnum<E>) -> ProofData<E> {
        ProofData::<E> { node, extra_inputs }
    }

    /// Create a new instance of [`ProofData`] from a slice of [`u8`]
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

    /// Update a [`ProofData`] with a proof represented as a [`Vec<u8>`]
    pub fn update(&mut self, proof: Vec<u8>) -> Result<(), MP2PlannerError> {
        match self.extra_inputs {
            InputEnum::Branch(ref mut proofs) => proofs.push(proof),

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionUpdatePlan<E: Extractable> {
    pub(crate) update_tree: UpdateTree<B256>,
    pub(crate) proof_cache: HashMap<B256, ProofData<E>>,
}

impl<E: Extractable> ExtractionUpdatePlan<E> {
    pub fn new(update_tree: UpdateTree<B256>, proof_cache: HashMap<B256, ProofData<E>>) -> Self {
        Self {
            update_tree,
            proof_cache,
        }
    }

    pub fn process_locally<const LEAF_LEN: usize, const MAX_EXTRACTED_COLUMNS: usize>(
        &mut self,
        params: &PublicParameters<LEAF_LEN, MAX_EXTRACTED_COLUMNS>,
        extractable: &E,
    ) -> Result<Vec<u8>, MP2PlannerError>
    where
        [(); PAD_LEN(LEAF_LEN)]:,
    {
        let mut update_plan = self.update_tree.clone().into_workplan();
        let mut final_proof = Vec::<u8>::new();
        while let Some(Next::Ready(work_plan_item)) = update_plan.next() {
            let proof_data = self.proof_cache.get(work_plan_item.k()).ok_or(
                MP2PlannerError::UpdateTreeError("Key not present in the proof cache".to_string()),
            )?;
            let circuit_type = extractable.to_circuit_input(proof_data);

            let proof = generate_proof(params, circuit_type).map_err(|e| {
                MP2PlannerError::ProvingError(format!(
                    "Error while generating proof for node {{ inner: {:?} }}",
                    e
                ))
            })?;

            let parent = self.update_tree.get_parent_key(work_plan_item.k());

            match parent {
                Some(parent_key) => {
                    let proof_data_ref = self.proof_cache.get_mut(&parent_key).unwrap();
                    proof_data_ref.update(proof)?
                }
                None => {
                    final_proof = proof;
                }
            }

            update_plan.done(&work_plan_item)?;
        }
        Ok(final_proof)
    }
}

impl<const NO_TOPICS: usize, const MAX_DATA_WORDS: usize> Extractable
    for EventLogInfo<NO_TOPICS, MAX_DATA_WORDS>
{
    type ExtraLeafInput = u64;
    async fn create_update_tree<T: Transport + Clone>(
        &self,
        contract: Address,
        epoch: u64,
        provider: &RootProvider<T, Ethereum>,
    ) -> Result<ExtractionUpdatePlan<Self>, MP2PlannerError> {
        let query = ReceiptQuery::<NO_TOPICS, MAX_DATA_WORDS> {
            contract,
            event: *self,
        };

        let proofs = query.query_receipt_proofs(provider, epoch.into()).await?;

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
        contract: Address,
        epoch: u64,
        pp: &PublicParameters<LEAF_LEN, MAX_EXTRACTED_COLUMNS>,
        provider: &RootProvider<T, Ethereum>,
    ) -> Result<Vec<u8>, MP2PlannerError>
    where
        [(); PAD_LEN(LEAF_LEN)]:,
    {
        let mut extraction_plan = self.create_update_tree(contract, epoch, provider).await?;

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
        eth::{left_pad32, BlockUtil},
        poseidon::{hash_to_int_value, H},
        proof::ProofWithVK,
        types::GFp,
        utils::{Endianness, Packer, ToFields},
    };
    use mp2_test::eth::get_mainnet_url;
    use plonky2::{field::types::Field, hash::hash_types::HashOut, plonk::config::Hasher};
    use plonky2_ecgfp5::curve::{curve::Point, scalar_field::Scalar};
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

        let extraction_plan = event_info
            .create_update_tree(contract, epoch, &provider)
            .await?;

        let block_util = build_test_data(epoch).await;

        assert_eq!(
            *extraction_plan.update_tree.root(),
            block_util.block.header.receipts_root
        );
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

        let mut block_util = build_test_data(epoch).await;
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

    #[tokio::test]
    async fn test_empty_block_receipt_proving() -> Result<()> {
        // First get the info we will feed in to our function
        let event_info = test_receipt_trie_helper().await?;

        let contract = Address::from_str("0xbd3531da5cf5857e7cfaa92426877b022e612cf8")?;
        let epoch: u64 = 21767312;

        let url = get_mainnet_url();
        // get some tx and receipt
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());

        let pp = build_circuits_params::<512, 7>();
        let final_proof_bytes = event_info
            .prove_value_extraction(contract, epoch, &pp, &provider)
            .await?;

        let final_proof = ProofWithVK::deserialize(&final_proof_bytes)?;

        let metadata = TableMetadata::from(event_info);

        let metadata_digest = metadata.digest();

        let value_digest = Point::NEUTRAL;

        let pi = PublicInputs::new(&final_proof.proof.public_inputs);

        let mut block_util = build_test_data(epoch).await;
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

        // Check that the number of rows is zero
        {
            assert_eq!(pi.n(), GFp::ZERO);
        }
        Ok(())
    }

    /// Function that fetches a block together with its transaction trie and receipt trie for testing purposes.
    async fn build_test_data(block_number: u64) -> BlockUtil {
        let url = get_mainnet_url();
        // get some tx and receipt
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());

        // We fetch a specific block which we know includes transactions relating to the PudgyPenguins contract.
        BlockUtil::fetch(&provider, BlockNumberOrTag::Number(block_number))
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
