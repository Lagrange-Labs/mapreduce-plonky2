//! This code returns an [`UpdateTree`] used to plan how we prove a series of values was extracted from a Merkle Patricia Trie.
pub mod receipts;
use alloy::primitives::B256;
use anyhow::Result;
use mp2_common::{
    eth::{node_type, MP2EthError, NodeType},
    mpt_sequential::PAD_LEN,
};

use ryhope::{error::RyhopeError, storage::updatetree::UpdateTree};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{fmt::Debug, hash::Hash};

use std::{
    collections::HashMap,
    error::Error,
    fmt::{Display, Formatter},
    write,
};

use super::CircuitInput;

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
    /// This is the solid type that we can use to construct a [`ExtractionUpdatePlan`] for a specifc block.
    type BlockData;

    /// Method that creates an [`ExtractionUpdatePlan`] that can then be processed either locally or in a distributed fashion.
    fn create_update_plan(
        data: &Self::BlockData,
    ) -> Result<ExtractionUpdatePlan<Self>, MP2PlannerError>
    where
        Self: Sized;
    /// Method that defines how to convert [`ProofData`] into [`CircuitInput`] for this implementation.
    fn to_circuit_input<const LEAF_LEN: usize, const MAX_EXTRACTED_COLUMNS: usize>(
        extractable: &Self,
        proof_data: &ProofData<Self>,
    ) -> CircuitInput<LEAF_LEN, MAX_EXTRACTED_COLUMNS>
    where
        [(); PAD_LEN(LEAF_LEN)]:,
        Self: Sized;
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
                if !inner_proof.is_empty() {
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
    pub update_tree: UpdateTree<B256>,
    /// The cache of input data, at the beginning only the keys relating to leaf proofs will have all data
    /// provided, it should then be updated as these tasks are processed.
    pub proof_cache: HashMap<B256, ProofData<E>>,
}

impl<E: Extractable> ExtractionUpdatePlan<E> {
    /// Create a new [`ExtractionUpdatePlan`] from its constituent parts.
    pub fn new(update_tree: UpdateTree<B256>, proof_cache: HashMap<B256, ProofData<E>>) -> Self {
        Self {
            update_tree,
            proof_cache,
        }
    }
}
