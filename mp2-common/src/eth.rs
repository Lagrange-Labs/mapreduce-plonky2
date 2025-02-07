//! Module containing several structure definitions for Ethereum related operations
//! such as fetching blocks, transactions, creating MPTs, getting proofs, etc.
use alloy::{
    consensus::{ReceiptEnvelope as CRE, ReceiptWithBloom},
    eips::BlockNumberOrTag,
    network::{eip2718::Encodable2718, BlockResponse},
    primitives::{Address, Log, B256, U256},
    providers::{Provider, RootProvider},
    rlp::{Decodable, Encodable as AlloyEncodable},
    rpc::{
        json_rpc::RpcError,
        types::{
            Block, BlockTransactions, EIP1186AccountProofResponse, ReceiptEnvelope, Transaction,
            TransactionReceipt,
        },
    },
    transports::Transport,
};

use eth_trie::{EthTrie, MemoryDB, Trie, TrieError};
use ethereum_types::H256;
use itertools::Itertools;
use log::{debug, warn};

use rlp::{DecoderError, Encodable, Rlp};
use serde::{Deserialize, Serialize};

use std::{
    array::from_fn as create_array,
    collections::{BTreeSet, HashMap},
    fmt::{Debug, Display, Formatter},
    sync::Arc,
};

use crate::{
    keccak::HASH_LEN,
    mpt_sequential::utils::bytes_to_nibbles,
    rlp::MAX_KEY_NIBBLE_LEN,
    serialization::{deserialize_long_array, serialize_long_array},
    utils::keccak256,
};

/// Retry number for the RPC request
const RETRY_NUM: usize = 3;

/// The maximum size an additional piece of data can be in bytes.
/// It should always be a multiple of 32 since Solidity event data encodes every object in 32 byte chunks
/// regardless of its true size.
const MAX_RECEIPT_DATA_SIZE: usize = 32;

/// The size of an event topic rlp encoded.
const ENCODED_TOPIC_SIZE: usize = 33;

/// The number of bytes the transaction type takes up in a Receipts RLP encoding.
const TX_TYPE_BYTES: usize = 1;

/// Error enum encompassing different errors that can arise in this module.
#[derive(Debug)]
pub enum MP2EthError {
    /// Error occuring from a [`RpcError`], but not necessarily one we should retry.
    RpcError(String),
    /// An error that occurs when trying to fetch data from an RPC node, used so that we can know we should retry the call in this case.
    FetchError,
    /// An error that arises from a method within the [`rlp`] crate.
    RlpError(DecoderError),
    /// An error arising from rlp decoding methods in the [`alloy::rlp`] crate.
    AlloyRlpError(alloy::rlp::Error),
    /// An error arising from methods in the [`eth_trie`] crate.
    TrieError(TrieError),
    /// Any other error arising from the functions in this module.
    InternalError(String),
}

impl std::error::Error for MP2EthError {}

impl Display for MP2EthError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MP2EthError::RpcError(s) => write!(f,"Error returned when making an RPC call {{ inner: {:?} }}", s),
            MP2EthError::FetchError => write!(f, "Error occured when trying to fetch data from an RPC node"),
            MP2EthError::RlpError(e) => write!(f,"Error returned when performing Rlp encoding or decoding function {{ inner: {:?} }}", e),
            MP2EthError::AlloyRlpError(e) => write!(f, "Error when decding to alloy type: {:?}", e),
            MP2EthError::TrieError(e) => write!(f, "Error returned when construct or querying an MPT {{ inner: {:?} }}", e),
            MP2EthError::InternalError(s) => write!(f, "Error occured in eth related code: {}", s)
        }
    }
}

impl<E: Debug> From<RpcError<E>> for MP2EthError {
    fn from(value: RpcError<E>) -> Self {
        MP2EthError::RpcError(format!("{:?}", value))
    }
}

impl From<DecoderError> for MP2EthError {
    fn from(value: DecoderError) -> Self {
        MP2EthError::RlpError(value)
    }
}

impl From<TrieError> for MP2EthError {
    fn from(value: TrieError) -> Self {
        MP2EthError::TrieError(value)
    }
}

impl From<alloy::rlp::Error> for MP2EthError {
    fn from(value: alloy::rlp::Error) -> Self {
        MP2EthError::AlloyRlpError(value)
    }
}

pub trait Rlpable {
    fn block_hash(&self) -> Vec<u8> {
        keccak256(&self.rlp())
    }
    fn rlp(&self) -> Vec<u8>;
}

/// Extract the hash in case of Extension node, or all the hashes in case of a Branch node.
pub fn extract_child_hashes(rlp_data: &[u8]) -> Vec<Vec<u8>> {
    let rlp = Rlp::new(rlp_data);
    let mut hashes = Vec::new();

    // Check for branch node (length of 17 items)
    if rlp.item_count().unwrap_or(0) == 17 {
        for i in 0..16 {
            let item = rlp.at(i).unwrap();
            if item.is_data() && item.data().unwrap().len() == 32 {
                hashes.push(item.data().unwrap().to_vec());
            }
        }
    } else if rlp.item_count().unwrap_or(0) == 2 {
        // Check for extension or leaf node
        let possible_hash = rlp.at(1).unwrap();
        if possible_hash.is_data() && possible_hash.data().unwrap().len() == 32 {
            hashes.push(possible_hash.data().unwrap().to_vec());
        }
    }
    hashes
}

/// Enum used to distinguish between different types of node in an MPT.
#[derive(Clone, Debug, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum NodeType {
    Branch,
    Extension,
    Leaf,
}

/// Function that returns the [`NodeType`] of an RLP encoded MPT node
pub fn node_type(rlp_data: &[u8]) -> Result<NodeType, MP2EthError> {
    let rlp = Rlp::new(rlp_data);

    let item_count = rlp.item_count()?;

    if item_count == 17 {
        Ok(NodeType::Branch)
    } else if item_count == 2 {
        // The first item is the encoded path, if it begins with a 2 or 3 it is a leaf, else it is an extension node
        let first_item = rlp.at(0)?;

        // We want the first byte
        let first_byte = first_item.as_raw()[0];

        // The we divide by 16 to get the first nibble
        match first_byte / 16 {
            0 | 1 => Ok(NodeType::Extension),
            2 | 3 => Ok(NodeType::Leaf),
            _ => Err(MP2EthError::InternalError(
                "Expected compact encoding beginning with 0,1,2 or 3".to_string(),
            )),
        }
    } else {
        Err(MP2EthError::InternalError(format!(
            "RLP encoded Node item count was {item_count}, expected either 17 or 2"
        )))
    }
}

pub fn left_pad32(slice: &[u8]) -> [u8; 32] {
    left_pad::<32>(slice)
}

pub fn left_pad_generic<T: Default + Copy, const N: usize>(slice: &[T]) -> [T; N] {
    match slice.len() {
        a if a > N => panic!(
            "left_pad{} must not be called with higher slice len than {} (given{})",
            N,
            N,
            slice.len()
        ),
        a if a == N => slice.try_into().unwrap(),
        a => {
            let mut output = [T::default(); N];
            output[N - a..].copy_from_slice(slice);
            output
        }
    }
}
pub fn left_pad<const N: usize>(slice: &[u8]) -> [u8; N] {
    match slice.len() {
        a if a > N => panic!(
            "left_pad{} must not be called with higher slice len than {} (given{})",
            N,
            N,
            slice.len()
        ),
        a if a == N => slice.try_into().unwrap(),
        a => {
            let mut output = [0u8; N];
            output[N - a..].copy_from_slice(slice);
            output
        }
    }
}

/// Query a specific block.
pub async fn query_block<T: Transport + Clone>(
    provider: &RootProvider<T>,
    id: BlockNumberOrTag,
) -> Result<Block, MP2EthError> {
    // Query the MPT proof with retries.
    for i in 0..RETRY_NUM - 1 {
        if let Ok(response) = provider.get_block_by_number(id, true.into()).await {
            // Has one block at least.
            return response.ok_or(MP2EthError::RpcError(
                "Call to get block successful but returned None".to_string(),
            ));
        } else {
            warn!("Failed to query the block - {i} time")
        }
    }

    // For the final attempt we return the error
    let resp = provider.get_block_by_number(id, true.into()).await;

    match resp {
        Ok(option) => match option {
            Some(block) => Ok(block),
            None => Err(MP2EthError::RpcError(
                "Get block by number call did not error but returned a None value".to_string(),
            )),
        },
        Err(_) => {
            warn!("Failed to query the block - {} time", RETRY_NUM - 1);
            Err(MP2EthError::FetchError)
        }
    }
}

/// Query a specific block for its receipts.
pub async fn query_block_receipts<T: Transport + Clone>(
    provider: &RootProvider<T>,
    id: BlockNumberOrTag,
) -> Result<Vec<TransactionReceipt>, MP2EthError> {
    // Query the MPT proof with retries.
    for i in 0..RETRY_NUM - 1 {
        if let Ok(response) = provider.get_block_receipts(id.into()).await {
            // Has one block at least.
            return response.ok_or(MP2EthError::InternalError(
                "Call to get block receipts successful but returned None".to_string(),
            ));
        } else {
            warn!("Failed to query the block receipts - {i} time")
        }
    }

    // For the final attempt we return the error
    let resp = provider.get_block_receipts(id.into()).await;

    match resp {
        Ok(option) => match option {
            Some(block) => Ok(block),
            None => Err(MP2EthError::RpcError(
                "Get Receipts by block number call did not error but returned a None value"
                    .to_string(),
            )),
        },
        Err(_) => {
            warn!(
                "Failed to query the block receipts - {} time",
                RETRY_NUM - 1
            );
            Err(MP2EthError::FetchError)
        }
    }
}

pub struct ProofQuery {
    pub contract: Address,
    pub(crate) slot: StorageSlot,
}

/// Struct used to store all the information needed for proving a leaf is in the Receipt Trie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptProofInfo {
    /// The MPT proof that this Receipt is in the tree
    pub mpt_proof: Vec<Vec<u8>>,
    /// The root of the Receipt Trie this receipt belongs to
    pub mpt_root: H256,
    /// The index of this transaction in the block
    pub tx_index: u64,
}

/// Contains all the information for an [`Event`] in rlp form
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct EventLogInfo<const NO_TOPICS: usize, const MAX_DATA_WORDS: usize> {
    /// Size in bytes of the whole log rlp encoded
    pub size: usize,
    /// The chain ID
    pub chain_id: u64,
    /// Packed contract address to check
    pub address: Address,
    /// Byte offset for the address from the beginning of a Log
    pub add_rel_offset: usize,
    /// Packed event signature,
    pub event_signature: [u8; HASH_LEN],
    /// Byte offset from the start of the log to event signature
    pub sig_rel_offset: usize,
    /// The the offsets to the other topics for this Log
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub topics: [usize; NO_TOPICS],
    /// The offsets to the start of the extra data stored by this Log
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub data: [usize; MAX_DATA_WORDS],
}

impl<const NO_TOPICS: usize, const MAX_DATA_WORDS: usize> EventLogInfo<NO_TOPICS, MAX_DATA_WORDS> {
    /// Create a new instance from a contract [`Address`] and a [`str`] that is the event signature
    pub fn new(contract: Address, chain_id: u64, event_signature: &str) -> Self {
        // To calculate the total size of the log rlp encoded we use the fact that the address takes 21 bytes to encode, topics
        // take 33 bytes each to incode and form a list that has length between 33 bytes and 132 bytes and data is a string that has 32 * MAX_DATA_WORDS length

        // If we have more than one topic that is not the event signature the rlp encoding is a list that is over 55 bytes whose total length can be encoded in one byte, so the header length is 2
        // Otherwise its still a list but the header is a single byte.
        let topics_header_len = alloy::rlp::length_of_length((1 + NO_TOPICS) * ENCODED_TOPIC_SIZE);

        // If the we have more than one piece of data it is rlp encoded as a string with length greater than 55 bytes
        let data_header_len = alloy::rlp::length_of_length(MAX_DATA_WORDS * MAX_RECEIPT_DATA_SIZE);

        let address_size = 21;
        let topics_size = (1 + NO_TOPICS) * ENCODED_TOPIC_SIZE + topics_header_len;
        let data_size = MAX_DATA_WORDS * MAX_RECEIPT_DATA_SIZE + data_header_len;

        let payload_size = address_size + topics_size + data_size;
        let header_size = alloy::rlp::length_of_length(payload_size);

        let size = header_size + payload_size;

        // The address itself starts after the header plus one byte for the address header.
        let add_rel_offset = header_size + 1;

        // The event signature offset is after the header, the address and the topics list header.
        let sig_rel_offset = header_size + address_size + topics_header_len + 1;

        let topics: [usize; NO_TOPICS] =
            create_array(|i| sig_rel_offset + (i + 1) * ENCODED_TOPIC_SIZE);

        let data: [usize; MAX_DATA_WORDS] = create_array(|i| {
            header_size + address_size + topics_size + data_header_len + (i * MAX_RECEIPT_DATA_SIZE)
        });

        let event_sig = alloy::primitives::keccak256(event_signature.as_bytes());

        Self {
            size,
            chain_id,
            address: contract,
            add_rel_offset,
            event_signature: event_sig.0,
            sig_rel_offset,
            topics,
            data,
        }
    }

    /// Function used to return the offset from the start of an Receipt Trie Leaf Node to the log relevant to [`EventLogInfo`]
    pub fn get_log_offset(&self, node: &[u8]) -> Result<usize, MP2EthError> {
        let node_rlp = rlp::Rlp::new(node);

        // The actual receipt data is item 1 in the list
        let (receipt_rlp, receipt_off) = node_rlp.at_with_offset(1)?;
        // The rlp encoded Receipt is not a list but a string that is formed of the `tx_type` followed by the remaining receipt
        // data rlp encoded as a list. We retrieve the payload info so that we can work out relevant offsets later.
        let receipt_str_payload = receipt_rlp.payload_info()?;

        // We make a new `Rlp` struct that should be the encoding of the inner list representing the `ReceiptEnvelope`
        let receipt_list = rlp::Rlp::new(&receipt_rlp.data()?[TX_TYPE_BYTES..]);

        // The logs themselves start are the item at index 3 in this list
        let (logs_rlp, logs_off) = receipt_list.at_with_offset(3)?;

        // We calculate the offset the that the logs are at from the start of the node
        let logs_offset = receipt_off + receipt_str_payload.header_len + 1 + logs_off;

        // Now we produce an iterator over the logs with each logs offset.
        let relevant_log_offset = std::iter::successors(Some(0usize), |i| Some(i + 1))
            .map_while(|i| logs_rlp.at_with_offset(i).ok())
            .find_map(|(log_rlp, log_off)| {
                let mut bytes = log_rlp.as_raw();
                let log = Log::decode(&mut bytes).ok()?;

                if log.address == self.address
                    && log
                        .data
                        .topics()
                        .contains(&B256::from(self.event_signature))
                {
                    Some(logs_offset + log_off)
                } else {
                    None
                }
            })
            .ok_or(MP2EthError::InternalError(
                "There were no relevant logs in this transaction".to_string(),
            ))?;

        Ok(relevant_log_offset)
    }

    /// Function that returns the MPT Trie inclusion proofs for all receipts in a block whose logs contain
    /// the specified event for the contract.
    pub async fn query_receipt_proofs<T: Transport + Clone>(
        &self,
        provider: &RootProvider<T>,
        block: BlockNumberOrTag,
    ) -> Result<(Vec<ReceiptProofInfo>, B256), MP2EthError> {
        let receipts = query_block_receipts(provider, block).await?;

        let memdb = Arc::new(MemoryDB::new(true));
        let mut receipts_trie = EthTrie::new(memdb.clone());

        let mut indices = BTreeSet::<u64>::new();
        receipts.into_iter().try_for_each(|receipt| {
            let tx_index_u64 = receipt.transaction_index.unwrap();

            let tx_index = tx_index_u64.rlp_bytes();

            let receipt_primitive = match receipt.inner {
                CRE::Legacy(ref r) => CRE::Legacy(from_rpc_logs_to_consensus(r)),
                CRE::Eip2930(ref r) => CRE::Eip2930(from_rpc_logs_to_consensus(r)),
                CRE::Eip1559(ref r) => CRE::Eip1559(from_rpc_logs_to_consensus(r)),
                CRE::Eip4844(ref r) => CRE::Eip4844(from_rpc_logs_to_consensus(r)),
                CRE::Eip7702(ref r) => CRE::Eip7702(from_rpc_logs_to_consensus(r)),
                _ => panic!("aie"),
            };
            // To receipt method is infallible so unwrap is safe here
            let receipt = receipt_primitive.as_receipt().unwrap();
            let relevant = receipt.logs.iter().find(|log| {
                let address_check = log.address == self.address;
                let topics = log.topics();
                if topics.is_empty() {
                    false
                } else {
                    let sig_check = topics[0].0 == self.event_signature;
                    sig_check && address_check
                }
            });

            if relevant.is_some() {
                indices.insert(tx_index_u64);
            }

            let body_rlp = receipt_primitive.encoded_2718();

            receipts_trie.insert(&tx_index, &body_rlp)
        })?;
        let mpt_root = receipts_trie.root_hash()?;

        Ok((
            indices
                .iter()
                .map(|&tx_index| {
                    let key = tx_index.rlp_bytes();

                    let proof = receipts_trie.get_proof(&key[..])?;

                    Ok(ReceiptProofInfo {
                        mpt_proof: proof,
                        mpt_root,
                        tx_index,
                    })
                })
                .collect::<Result<Vec<ReceiptProofInfo>, MP2EthError>>()?,
            B256::from(mpt_root.0),
        ))
    }
}

/// Represent an intermediate or leaf node of a storage slot in contract.
///
/// It has a `parent` node, and its ancestor (root) must be a simple or mapping slot.
/// Any intermediate nodes could be represented as:
/// - For mapping entry, it has a parent node and the mapping key.
/// - For Struct entry, it has a parent node and the EVM offset.
// NOTE: This is not strict, since the parent of a Slot mapping entry must type of
// mapping (cannot be a Struct).
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum StorageSlotNode {
    /// Mapping entry including a parent node and the mapping key
    Mapping(Box<StorageSlot>, Vec<u8>),
    /// Struct entry including a parent node and EVM offset
    Struct(Box<StorageSlot>, u32),
}

impl StorageSlotNode {
    pub fn new_mapping(parent: StorageSlot, mapping_key: Vec<u8>) -> Result<Self, MP2EthError> {
        let parent = Box::new(parent);
        if !matches!(
            *parent,
            StorageSlot::Mapping(_, _) | StorageSlot::Node(Self::Mapping(_, _))
        ) {
            return Err(MP2EthError::InternalError(
                "The parent of a Slot mapping entry must be type of mapping".to_string(),
            ));
        }

        Ok(Self::Mapping(parent, mapping_key))
    }

    pub fn new_struct(parent: StorageSlot, evm_offset: u32) -> Self {
        let parent = Box::new(parent);

        Self::Struct(parent, evm_offset)
    }

    pub fn parent(&self) -> &StorageSlot {
        match self {
            Self::Mapping(parent, _) => parent,
            Self::Struct(parent, _) => parent,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum StorageSlot {
    /// simple storage slot like a uin256 etc that fits in 32bytes
    /// Argument is the slot location in the contract
    Simple(usize),
    /// Mapping storage slot - to get the proof, one needs to know
    /// the entry, the "mapping key" to derive the MPT key
    /// Second argument is the slot location inthe contract
    /// (mapping_key, mapping_slot)
    Mapping(Vec<u8>, usize),
    /// Represent an intermediate or leaf node of a storage slot in contract.
    /// It has a `parent` node, and its ancestor (root) must be a simple or mapping slot.
    Node(StorageSlotNode),
}

impl StorageSlot {
    pub fn slot(&self) -> u8 {
        match self {
            StorageSlot::Simple(slot) => *slot as u8,
            StorageSlot::Mapping(_, slot) => *slot as u8,
            StorageSlot::Node(node) => node.parent().slot(),
        }
    }
    pub fn evm_offset(&self) -> u32 {
        match self {
            // Only the Struct storage has the EVM offset.
            StorageSlot::Node(StorageSlotNode::Struct(_, evm_offset)) => *evm_offset,
            StorageSlot::Simple(_)
            | StorageSlot::Mapping(_, _)
            | StorageSlot::Node(StorageSlotNode::Mapping(_, _)) => 0,
        }
    }
    pub fn location(&self) -> B256 {
        match self {
            StorageSlot::Simple(slot) => B256::left_padding_from(&(*slot as u64).to_be_bytes()[..]),
            StorageSlot::Mapping(mapping_key, mapping_slot) => {
                // H( pad32(address), pad32(mapping_slot))
                let padded_mkey = left_pad32(mapping_key);
                let padded_slot = left_pad32(&[*mapping_slot as u8]);
                let inputs = padded_mkey.into_iter().chain(padded_slot).collect_vec();
                B256::from_slice(&keccak256(&inputs))
            }
            StorageSlot::Node(StorageSlotNode::Mapping(parent, mapping_key)) => {
                // location = keccak256(left_pad32(mapping_key) || parent_location)
                let padded_mapping_key = left_pad32(mapping_key);
                let parent_location = parent.location();
                let inputs = padded_mapping_key
                    .into_iter()
                    .chain(parent_location.0)
                    .collect_vec();
                B256::from_slice(&keccak256(&inputs))
            }
            StorageSlot::Node(StorageSlotNode::Struct(parent, evm_offset)) => {
                // location = parent_location + evm_offset
                let parent_location = U256::from_be_slice(parent.location().as_slice());
                let location: [_; U256::BYTES] = parent_location
                    .checked_add(U256::from(*evm_offset))
                    .unwrap()
                    .to_be_bytes();
                debug!(
                    "Storage slot struct: parent_location = {}, evm_offset = {}",
                    parent_location, evm_offset,
                );
                B256::from_slice(&location)
            }
        }
    }
    pub fn mpt_key_vec(&self) -> Vec<u8> {
        keccak256(self.location().as_slice())
    }
    pub fn mpt_key(&self) -> [u8; 32] {
        let hash = keccak256(self.location().as_slice());
        create_array(|i| hash[i])
    }
    pub fn mpt_nibbles(&self) -> [u8; MAX_KEY_NIBBLE_LEN] {
        bytes_to_nibbles(&self.mpt_key_vec()).try_into().unwrap()
    }
    pub fn is_simple_slot(&self) -> bool {
        match self {
            StorageSlot::Simple(_) => true,
            StorageSlot::Mapping(_, _) => false,
            StorageSlot::Node(node) => node.parent().is_simple_slot(),
        }
    }
    /// Get the mapping key path from the outer key to the inner.
    pub fn mapping_keys(&self) -> Vec<Vec<u8>> {
        match self {
            StorageSlot::Simple(_) => vec![],
            StorageSlot::Mapping(mapping_key, _) => {
                vec![mapping_key.clone()]
            }
            StorageSlot::Node(StorageSlotNode::Mapping(parent, mapping_key)) => {
                // [parent_mapping_keys || mapping_key]
                let mut mapping_keys = parent.mapping_keys();
                mapping_keys.push(mapping_key.clone());

                mapping_keys
            }
            StorageSlot::Node(StorageSlotNode::Struct(parent, _)) => parent.mapping_keys(),
        }
    }
}
impl ProofQuery {
    pub fn new(contract: Address, slot: StorageSlot) -> Self {
        Self { contract, slot }
    }
    pub fn new_simple_slot(address: Address, slot: usize) -> Self {
        Self {
            contract: address,
            slot: StorageSlot::Simple(slot),
        }
    }
    pub fn new_mapping_slot(address: Address, slot: usize, mapping_key: Vec<u8>) -> Self {
        Self {
            contract: address,
            slot: StorageSlot::Mapping(mapping_key, slot),
        }
    }
    pub async fn query_mpt_proof<T: Transport + Clone>(
        &self,
        provider: &RootProvider<T>,
        block: BlockNumberOrTag,
    ) -> Result<EIP1186AccountProofResponse, MP2EthError> {
        // Query the MPT proof with retries.
        let location = self.slot.location();
        for i in 0..RETRY_NUM - 1 {
            debug!(
                "Querying MPT proof:\n\tslot = {:?}, location = {:?}",
                self.slot,
                U256::from_be_slice(location.as_slice()),
            );
            match provider
                .get_proof(self.contract, vec![location])
                .block_id(block.into())
                .await
            {
                Ok(response) => return Ok(response),
                Err(e) => println!("Failed to query the MPT proof at {i} time: {e:?}"),
            }
        }

        match provider
            .get_proof(self.contract, vec![location])
            .block_id(block.into())
            .await
        {
            Ok(response) => Ok(response),
            Err(_) => Err(MP2EthError::FetchError),
        }
    }
    /// Returns the raw value from the storage proof, not the one "interpreted" by the
    /// JSON RPC so we can see how the encoding is done.
    pub fn verify_storage_proof(
        proof: &EIP1186AccountProofResponse,
    ) -> Result<Vec<u8>, MP2EthError> {
        let memdb = Arc::new(MemoryDB::new(true));
        let tx_trie = EthTrie::new(Arc::clone(&memdb));
        let proof_key_bytes = proof.storage_proof[0].key.as_b256();
        let mpt_key = keccak256(&proof_key_bytes[..]);
        let storage_hash = H256(proof.storage_hash.0);
        let is_valid = tx_trie.verify_proof(
            storage_hash,
            &mpt_key,
            proof.storage_proof[0]
                .proof
                .iter()
                .map(|b| b.to_vec())
                .collect(),
        )?;

        if let Some(ext_value) = is_valid {
            Ok(ext_value)
        } else {
            Err(MP2EthError::InternalError(
                "proof says the value associated with that key does not exist".to_string(),
            ))
        }
    }
    pub fn verify_state_proof(&self, res: &EIP1186AccountProofResponse) -> Result<(), MP2EthError> {
        let memdb = Arc::new(MemoryDB::new(true));
        let tx_trie = EthTrie::new(Arc::clone(&memdb));

        // According to EIP-1186, accountProof starts with the the state root.
        let state_root_hash = H256(keccak256(&res.account_proof[0]).try_into().unwrap());

        // The MPT key is Keccak hash of the contract (requested) address.
        let mpt_key = keccak256(self.contract.0.as_slice());

        let is_valid = tx_trie.verify_proof(
            state_root_hash,
            &mpt_key,
            res.account_proof.iter().map(|b| b.to_vec()).collect(),
        )?;

        if is_valid.is_none() {
            return Err(MP2EthError::InternalError(
                "Account proof says the value associated with that key does not exist".to_string(),
            ));
        }

        // The length of acount node must be 104 bytes (8 + 32 + 32 + 32) as:
        // [nonce (U64), balance (U256), storage_hash (H256), code_hash (H256)]
        let account_node = res.account_proof.last().ok_or(MP2EthError::InternalError(
            "Account proof response was empty".to_string(),
        ))?;
        if account_node.len() != 104 {
            Err(MP2EthError::InternalError(format!("The length of acount node must be 104 bytes (8 + 32 + 32 + 32), retrieved node length: {}", account_node.len())))
        } else {
            Ok(())
        }
    }
}

impl ReceiptProofInfo {
    pub fn to_receipt(&self) -> Result<ReceiptWithBloom, MP2EthError> {
        let memdb = Arc::new(MemoryDB::new(true));
        let tx_trie = EthTrie::new(Arc::clone(&memdb));

        let mpt_key = self.tx_index.rlp_bytes();

        let valid = tx_trie
            .verify_proof(self.mpt_root, &mpt_key, self.mpt_proof.clone())?
            .ok_or(MP2EthError::InternalError(
                "No proof found when verifying".to_string(),
            ))?;

        let rlp_receipt = rlp::Rlp::new(&valid[1..]);
        ReceiptWithBloom::decode(&mut rlp_receipt.as_raw()).map_err(|e| e.into())
    }
}

impl Rlpable for alloy::rpc::types::Block {
    fn rlp(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.header.encode(&mut out);
        out
    }
}

impl Rlpable for alloy::rpc::types::Header {
    fn rlp(&self) -> Vec<u8> {
        self.inner.rlp()
    }
}

impl Rlpable for alloy::consensus::Header {
    fn rlp(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }
}

#[allow(dead_code)]
pub struct BlockUtil {
    /// The actual [`Block`] that the rest of the data relates to
    pub block: Block,
    /// The transactions and Receipts in the block paired together
    pub txs: Vec<TxWithReceipt>,
    /// The Receipts Trie
    pub receipts_trie: EthTrie<MemoryDB>,
    /// The Transactions Trie
    pub transactions_trie: EthTrie<MemoryDB>,
}

pub struct TxWithReceipt(Transaction, ReceiptEnvelope);
impl TxWithReceipt {
    pub fn receipt(&self) -> &ReceiptEnvelope {
        &self.1
    }
    pub fn transaction(&self) -> &Transaction {
        &self.0
    }
}

impl BlockUtil {
    pub async fn fetch<T: Transport + Clone>(
        t: &RootProvider<T>,
        id: BlockNumberOrTag,
    ) -> Result<BlockUtil, MP2EthError> {
        let block = query_block(t, id).await?;

        let receipts = query_block_receipts(t, id).await?;
        let BlockTransactions::Full(all_tx) = block.transactions() else {
            return Err(MP2EthError::InternalError(
                "Could not recover full transactions from Block".to_string(),
            ));
        };
        // check receipt root
        let all_tx_map = HashMap::<u64, &Transaction>::from_iter(
            all_tx
                .iter()
                .map_while(|tx| tx.transaction_index.map(|tx_index| (tx_index, tx))),
        );
        let memdb = Arc::new(MemoryDB::new(true));
        let mut receipts_trie = EthTrie::new(memdb.clone());
        let mut transactions_trie = EthTrie::new(memdb.clone());
        let consensus_receipts = receipts
            .into_iter()
            .map(|receipt| {
                let tx_index_u64 = receipt.transaction_index.unwrap();
                // If the HashMap doesn't have an entry for this tx_index then the recceipts and transactions aren't from the same block.
                let transaction = all_tx_map.get(&tx_index_u64).cloned().unwrap();
                let tx_index = tx_index_u64.rlp_bytes();

                let receipt_primitive = match receipt.inner {
                    CRE::Legacy(ref r) => CRE::Legacy(from_rpc_logs_to_consensus(r)),
                    CRE::Eip2930(ref r) => CRE::Eip2930(from_rpc_logs_to_consensus(r)),
                    CRE::Eip1559(ref r) => CRE::Eip1559(from_rpc_logs_to_consensus(r)),
                    CRE::Eip4844(ref r) => CRE::Eip4844(from_rpc_logs_to_consensus(r)),
                    CRE::Eip7702(ref r) => CRE::Eip7702(from_rpc_logs_to_consensus(r)),
                    _ => panic!("aie"),
                };

                let body_rlp = receipt_primitive.encoded_2718();

                let tx_body_rlp = transaction.inner.encoded_2718();

                receipts_trie
                    .insert(&tx_index, &body_rlp)
                    .expect("can't insert receipt");
                transactions_trie
                    .insert(&tx_index, &tx_body_rlp)
                    .expect("can't insert transaction");
                TxWithReceipt(transaction.clone(), receipt_primitive)
            })
            .collect::<Vec<_>>();
        receipts_trie.root_hash()?;
        transactions_trie.root_hash()?;
        Ok(BlockUtil {
            block,
            txs: consensus_receipts,
            receipts_trie,
            transactions_trie,
        })
    }

    /// recompute the receipts trie by first converting all receipts form RPC type to consensus type
    /// since in Alloy these are two different types and RLP functions are only implemented for
    /// consensus ones.
    #[cfg(test)]
    fn check(&mut self) -> Result<(), MP2EthError> {
        let computed = self.receipts_trie.root_hash()?;
        let tx_computed = self.transactions_trie.root_hash()?;
        let expected = self.block.header.receipts_root;
        let tx_expected = self.block.header.transactions_root;
        assert_eq!(expected.0, computed.0);
        assert_eq!(tx_expected.0, tx_computed.0);
        Ok(())
    }
}

fn from_rpc_logs_to_consensus(
    r: &ReceiptWithBloom<alloy::rpc::types::Log>,
) -> ReceiptWithBloom<alloy::primitives::Log> {
    ReceiptWithBloom {
        logs_bloom: r.logs_bloom,
        receipt: alloy::consensus::Receipt {
            status: r.receipt.status,
            cumulative_gas_used: r.receipt.cumulative_gas_used,
            logs: r
                .receipt
                .logs
                .iter()
                .map(|l| alloy::primitives::Log {
                    address: l.inner.address,
                    data: l.inner.data.clone(),
                })
                .collect(),
        },
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "ci")]
    use std::env;
    use std::str::FromStr;

    use alloy::{
        network::TransactionResponse,
        primitives::{Bytes, Log},
        providers::{Provider, ProviderBuilder},
        rlp::Decodable,
    };
    use anyhow::{anyhow, Context, Result};
    use eth_trie::Nibbles;
    use ethereum_types::U64;
    use ethers::{
        providers::{Http, Middleware},
        types::BlockNumber,
    };
    use hashbrown::HashMap;

    use crate::{
        mpt_sequential::utils::nibbles_to_bytes,
        utils::{Endianness, Packer},
    };
    use mp2_test::{
        eth::{get_mainnet_url, get_sepolia_url},
        mpt_sequential::generate_receipt_test_info,
    };

    use super::*;

    #[tokio::test]
    async fn test_block_receipt_trie() -> Result<()> {
        let url = get_sepolia_url();
        // get some tx and receipt
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());
        let bn = 6893107;
        let bna = BlockNumberOrTag::Number(bn);
        let mut block = BlockUtil::fetch(&provider, bna).await?;
        // check if we compute the RLP correctly now
        block.check()?;

        // dissect one receipt entry in the trie
        let tx_receipt = block.txs.first().unwrap();
        // https://sepolia.etherscan.io/tx/0x9bef12fafd3962b0e0d66b738445d6ea2c1f3daabe10c889bd1916acc75d698b#eventlog
        println!(
            "Looking at tx hash on sepolia: {}",
            hex::encode(tx_receipt.0.tx_hash())
        );
        // in the MPT trie it's
        // RLP ( RLP(Index), RLP ( DATA ))
        // the second component is done like that:
        // DATA = RLP [ Rlp(status), Rlp(gas_used), Rlp(logs_bloom), Rlp(logs) ]
        // it contains multiple logs so
        // logs = RLP_LIST(RLP(logs[0]), RLP(logs[1])...)
        // Each RLP(logs[0]) = RLP([ RLP(Address), RLP(topics), RLP(data)])
        // RLP(topics) is a list with up to 4 topics
        let rlp_encoding = tx_receipt.receipt().encoded_2718();
        println!(
            "Size of RLP encoded receipt in bytes: {}",
            rlp_encoding.len()
        );
        let state = rlp::Rlp::new(&rlp_encoding);
        assert!(state.is_list());
        //  index 0 -> status,
        //  index 1 -> gas used
        //  index 2 -> logs_bloom
        //  index 3 -> logs
        let gas_used: Vec<u8> = state.val_at(1).context("can't access gas used")?;
        println!("gas used byte length: {}", gas_used.len());
        let bloom: Vec<u8> = state.val_at(2).context("can't access bloom")?;
        println!("bloom byte length: {}", bloom.len());
        //let logs: Vec<Vec<u8>> = state.list_at(3).context("can't access logs")?;
        //println!("logs byte length: {}", logs.len());

        let logs_state = state.at(3).context("can't access logs field3")?;
        assert!(logs_state.is_list());
        println!("logs in hex: {}", hex::encode(logs_state.data()?));
        let log_state = logs_state.at(0).context("can't access single log state")?;
        assert!(log_state.is_list());
        // log:
        // 0: address where it has been emitted
        // 1: Topics (4 topics max, with 1 mandatory, the event sig)
        // 2: Bytes32 array
        let log_address: Vec<u8> = log_state.val_at(0).context("can't decode address")?;
        let hex_address = hex::encode(&log_address);
        assert_eq!(
            hex_address,
            "BBd3EDd4D3b519c0d14965d9311185CFaC8c3220".to_lowercase(),
        );
        // the topics are in a list
        let topics: Vec<Vec<u8>> = log_state.list_at(1).context("can't decode topics")?;
        // Approval (index_topic_1 address owner, index_topic_2 address approved, index_topic_3 uint256 tokenId)View Source
        // first topic is signature of the event keccak(fn_name,args...)
        let expected_sig = "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
        let found_sig = hex::encode(&topics[0]);
        assert_eq!(expected_sig, found_sig);
        // second topic is owner
        let expected_owner = hex::encode(left_pad32(&hex::decode(
            "66d2F437a12d8f9f340C226b1EDC605124e763A6",
        )?));
        let found_owner = hex::encode(&topics[1]);
        assert_eq!(expected_owner, found_owner);
        // third topic is approved
        let expected_approved = hex::encode(left_pad32(&hex::decode(
            "094f1570A8B5fc99d6756aD54DF0Fd6906795cd3",
        )?));
        let found_approved = hex::encode(left_pad32(&topics[2]));
        assert_eq!(expected_approved, found_approved);
        // final is tokenid - not in topic
        let expected_data = "000000000000000000000000000000000000000000115eec47f6cf7e35000000";
        let log_data: Vec<u8> = log_state.val_at(2).context("can't decode log data")?;
        let found_data = hex::encode(left_pad32(
            &log_data.into_iter().take(32).collect::<Vec<_>>(),
        ));
        assert_eq!(expected_data, found_data);

        let mpt_key = tx_receipt.0.transaction_index.unwrap();
        let proof = block
            .receipts_trie
            .get_proof(&mpt_key.rlp_bytes())
            .expect("can't retrieve mpt proof");
        let mpt_node = proof.last().unwrap();
        println!("MPT LEAF NODE: {:?}", mpt_node);
        // First decode the top level header
        let top_header = rlp::Rlp::new(mpt_node);
        assert!(top_header.is_list());
        // then extract the buffer containing all elements (key and value)
        let top_info = top_header.payload_info()?;
        println!("TOP level header: {:?}", top_info);
        let list_buff = &mpt_node[top_info.header_len..top_info.header_len + top_info.value_len];
        // then check the key and make sure it's equal to the RLP encoding of the index
        let key_header = rlp::Rlp::new(list_buff);
        assert!(!key_header.is_list());
        // key is RLP( compact ( RLP(index)))
        let key_info = key_header.payload_info()?;
        let compact_key = &list_buff[key_info.header_len..key_info.header_len + key_info.value_len];
        let decoded_key = rlp::encode(&nibbles_to_bytes(
            Nibbles::from_compact(compact_key).nibbles(),
        ));
        assert_eq!(decoded_key, &mpt_key.rlp_bytes().to_vec(),);

        // then check if the value portion fits what we tested above
        // value is RLP ( RLP(status, etc...))
        let outer_value_min = top_info.header_len + key_info.header_len + key_info.value_len;
        let outer_value_buff = &mpt_node[outer_value_min..];
        let outer_value_state = rlp::Rlp::new(outer_value_buff);
        assert!(!outer_value_state.is_list());
        let outer_payload = outer_value_state.payload_info()?;
        let inner_value_min = outer_value_min + outer_payload.header_len;
        let inner_value_buff = &mpt_node[inner_value_min..];
        assert_eq!(rlp_encoding, inner_value_buff);
        Ok(())
    }

    #[test]
    fn test_receipt_query() -> Result<()> {
        test_receipt_query_helper::<1, 0>()?;
        test_receipt_query_helper::<2, 0>()?;
        test_receipt_query_helper::<3, 0>()?;
        test_receipt_query_helper::<3, 1>()?;
        test_receipt_query_helper::<3, 2>()
    }

    fn test_receipt_query_helper<const NO_TOPICS: usize, const MAX_DATA_WORDS: usize>() -> Result<()>
    {
        // Now for each transaction we fetch the block, then get the MPT Trie proof that the receipt is included and verify it
        let test_info = generate_receipt_test_info::<NO_TOPICS, MAX_DATA_WORDS>();
        let proofs = test_info.proofs();
        let event = test_info.info();
        for proof in proofs.iter() {
            let memdb = Arc::new(MemoryDB::new(true));
            let tx_trie = EthTrie::new(Arc::clone(&memdb));

            let mpt_key = proof.tx_index.rlp_bytes();

            let _ = tx_trie
                .verify_proof(proof.mpt_root, &mpt_key, proof.mpt_proof.clone())?
                .ok_or(anyhow!("No proof found when verifying"))?;

            let last_node = proof
                .mpt_proof
                .last()
                .ok_or(anyhow!("Couldn't get first node in proof"))?;
            let expected_sig: [u8; 32] = event.event_signature;

            // Convert to Rlp form so we can use provided methods.
            let node_rlp = rlp::Rlp::new(last_node);

            // The actual receipt data is item 1 in the list
            let (receipt_rlp, receipt_off) = node_rlp.at_with_offset(1)?;
            // The rlp encoded Receipt is not a list but a string that is formed of the `tx_type` followed by the remaining receipt
            // data rlp encoded as a list. We retrieve the payload info so that we can work out relevant offsets later.
            let receipt_str_payload = receipt_rlp.payload_info()?;

            // We make a new `Rlp` struct that should be the encoding of the inner list representing the `ReceiptEnvelope`
            let receipt_list = rlp::Rlp::new(&receipt_rlp.data()?[1..]);

            // The logs themselves start are the item at index 3 in this list
            let (logs_rlp, logs_off) = receipt_list.at_with_offset(3)?;

            // We calculate the offset the that the logs are at from the start of the node
            let logs_offset = receipt_off + receipt_str_payload.header_len + 1 + logs_off;

            // Now we produce an iterator over the logs with each logs offset.
            let relevant_logs_offset = std::iter::successors(Some(0usize), |i| Some(i + 1))
                .map_while(|i| logs_rlp.at_with_offset(i).ok())
                .filter_map(|(log_rlp, log_off)| {
                    let mut bytes = log_rlp.data().ok()?;
                    let log = Log::decode(&mut bytes).ok()?;
                    if log.address == event.address
                        && log
                            .data
                            .topics()
                            .contains(&B256::from(event.event_signature))
                    {
                        Some(logs_offset + log_off)
                    } else {
                        Some(0usize)
                    }
                })
                .collect::<Vec<usize>>();

            for log_offset in relevant_logs_offset.iter() {
                let mut buf = &last_node[*log_offset..*log_offset + event.size];
                let decoded_log = Log::decode(&mut buf)?;
                let raw_bytes: [u8; 20] = last_node
                    [*log_offset + event.add_rel_offset..*log_offset + event.add_rel_offset + 20]
                    .to_vec()
                    .try_into()
                    .unwrap();
                assert_eq!(decoded_log.address, event.address);
                assert_eq!(raw_bytes, event.address);
                let topics = decoded_log.topics();
                assert_eq!(topics[0].0, expected_sig);
                let raw_bytes: [u8; 32] = last_node
                    [*log_offset + event.sig_rel_offset..*log_offset + event.sig_rel_offset + 32]
                    .to_vec()
                    .try_into()
                    .unwrap();
                assert_eq!(topics[0].0, raw_bytes);
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_sepolia_slot() -> Result<()> {
        #[cfg(feature = "ci")]
        let url = env::var("CI_SEPOLIA").expect("CI_SEPOLIA env var not set");
        #[cfg(not(feature = "ci"))]
        let url = "https://ethereum-sepolia-rpc.publicnode.com";

        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());
        let pidgy_address = Address::from_str("0x363971ee2b96f360ec9d04b5809afd15c77b1af1")?;
        let length_slot = 8;
        let query = ProofQuery::new_simple_slot(pidgy_address, length_slot);
        let res = query
            .query_mpt_proof(&provider, BlockNumberOrTag::Latest)
            .await?;
        let tree_res = ProofQuery::verify_storage_proof(&res)?;
        println!("official response: {}", res.storage_proof[0].value);
        println!("tree response = {:?}", tree_res);
        let leaf = res.storage_proof[0].proof.last().unwrap().to_vec();
        let leaf_list: Vec<Vec<u8>> = rlp::decode_list(&leaf);
        assert_eq!(leaf_list.len(), 2);
        // implement the circuit logic:
        let first_byte = leaf_list[1][0];
        let slice = if first_byte < 0x80 {
            println!("taking full byte");
            &leaf_list[1][..]
        } else {
            println!("skipping full byte");
            &leaf_list[1][1..]
        }
        .to_vec();
        let slice = left_pad::<4>(&slice); // what happens in circuit effectively
                                           // we have to reverse since encoding is big endian on EVM and our function is little endian based
        let length = slice
            .into_iter()
            .rev()
            .collect::<Vec<u8>>()
            .pack(Endianness::Little)[0];
        println!("length extracted = {}", length);
        println!("res.storage_proof.value = {}", res.storage_proof[0].value);
        assert_eq!(length, 2); // custom value that may change if we update contract!
        Ok(())
    }

    #[tokio::test]
    async fn test_pidgy_pinguin_length_slot() -> Result<()> {
        #[cfg(feature = "ci")]
        let url = env::var("CI_ETH").expect("CI_ETH env var not set");
        #[cfg(not(feature = "ci"))]
        let url = "https://eth.llamarpc.com";
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());

        // pidgy pinguins address
        let pidgy_address = Address::from_str("0xBd3531dA5CF5857e7CfAA92426877b022e612cf8")?;
        let query = ProofQuery::new_simple_slot(pidgy_address, 8);
        let res = query
            .query_mpt_proof(&provider, BlockNumberOrTag::Latest)
            .await?;
        let tree_res = ProofQuery::verify_storage_proof(&res)?;
        println!("official response: {}", res.storage_proof[0].value);
        println!("tree response = {:?}", tree_res);
        let leaf = res.storage_proof[0].proof.last().unwrap().to_vec();
        let leaf_list: Vec<Vec<u8>> = rlp::decode_list(&leaf);
        println!("leaf[1].len() = {}", leaf_list[1].len());
        assert_eq!(leaf_list.len(), 2);
        let leaf_value: Vec<u8> = rlp::decode(&leaf_list[1]).unwrap();
        // making sure we can simply skip the first byte
        let sliced = &leaf_list[1][1..];
        assert_eq!(sliced, leaf_value.as_slice());
        println!(
            "length of storage proof: {}",
            res.storage_proof[0].proof.len()
        );
        println!(
            "max node length: {}",
            res.storage_proof[0]
                .proof
                .iter()
                .map(|x| x.len())
                .max()
                .unwrap()
        );
        let mut n = sliced.to_vec();
        n.resize(4, 0); // what happens in circuit effectively
        println!("sliced: {:?} - hex {}", sliced, hex::encode(sliced));
        let length = n.pack(Endianness::Little)[0];
        let length2 = sliced
            .iter()
            .cloned()
            .rev()
            .collect::<Vec<u8>>()
            .pack(Endianness::Little)[0];
        println!("length extracted = {}", length);
        println!("length 2 extracted = {}", length2);
        println!("res.storage_proof.value = {}", res.storage_proof[0].value);
        let analyze = |proof: Vec<Bytes>| {
            proof.iter().fold(HashMap::new(), |mut acc, p| {
                let b: Vec<Vec<u8>> = rlp::decode_list(p);
                if b.len() == 17 {
                    let n = acc.entry(p.len()).or_insert(0);
                    *n += 1;
                }
                acc
            })
        };
        let storage_sizes = analyze(res.storage_proof[0].proof.clone());
        let state_sizes = analyze(res.account_proof.clone());
        println!("storage_sizes = {:?}", storage_sizes);
        println!("state_sizes = {:?}", state_sizes);
        Ok(())
    }

    #[tokio::test]
    async fn test_pidgy_pinguin_mapping_slot() -> Result<()> {
        // first pinguin holder https://dune.com/queries/2450476/4027653
        // This was outdated so the following is the updated address
        // holder: 0xee5ac9c6db07c26e71207a41e64df42e1a2b05cf
        // NFT id https://opensea.io/assets/ethereum/0xbd3531da5cf5857e7cfaa92426877b022e612cf8/1116
        let mapping_value =
            Address::from_str("0xee5ac9c6db07c26e71207a41e64df42e1a2b05cf").unwrap();
        let nft_id: u32 = 1116;
        let mapping_key = left_pad32(&nft_id.to_be_bytes());
        let url = get_mainnet_url();
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());

        // extracting from
        // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol
        // assuming it's using ERC731Enumerable that inherits ERC721
        let mapping_slot = 2;
        // pudgy pinguins
        let pudgy_address = Address::from_str("0xBd3531dA5CF5857e7CfAA92426877b022e612cf8")?;
        let query = ProofQuery::new_mapping_slot(pudgy_address, mapping_slot, mapping_key.to_vec());
        let res = query
            .query_mpt_proof(&provider, BlockNumberOrTag::Latest)
            .await?;
        let raw_address = ProofQuery::verify_storage_proof(&res)?;
        // the value is actually RLP encoded !
        let decoded_address: Vec<u8> = rlp::decode(&raw_address).unwrap();
        let leaf_node: Vec<Vec<u8>> = rlp::decode_list(res.storage_proof[0].proof.last().unwrap());
        println!("leaf_node[1].len() = {}", leaf_node[1].len());
        // this is read in the same order
        let found_address = Address::from_slice(&decoded_address.into_iter().collect::<Vec<u8>>());
        assert_eq!(found_address, mapping_value);
        Ok(())
    }

    #[tokio::test]
    async fn test_kashish_contract_proof_query() -> Result<()> {
        // https://sepolia.etherscan.io/address/0xd6a2bFb7f76cAa64Dad0d13Ed8A9EFB73398F39E#code
        // uint256 public n_registered; // storage slot 0
        // mapping(address => uint256) public holders; // storage slot 1
        let url = get_sepolia_url();
        println!("URL given = {}", url);
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());

        // sepolia contract
        let contract = Address::from_str("0xd6a2bFb7f76cAa64Dad0d13Ed8A9EFB73398F39E")?;
        // simple storage test
        {
            let query = ProofQuery::new_simple_slot(contract, 0);
            let res = query
                .query_mpt_proof(&provider, BlockNumberOrTag::Latest)
                .await?;
            ProofQuery::verify_storage_proof(&res)?;
            query.verify_state_proof(&res)?;
        }
        {
            // mapping key
            let mapping_key =
                hex::decode("000000000000000000000000000000000000000000000000000000000001abcd")?;
            let query = ProofQuery::new_mapping_slot(contract, 1, mapping_key);
            let res = query
                .query_mpt_proof(&provider, BlockNumberOrTag::Latest)
                .await?;
            ProofQuery::verify_storage_proof(&res)?;
            query.verify_state_proof(&res)?;
        }
        Ok(())
    }
    #[tokio::test]
    async fn test_alloy_header_conversion() -> Result<()> {
        let url = get_sepolia_url();
        println!("URL given = {}", url);
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Latest, true.into())
            .await?
            .unwrap();
        let previous_block = provider
            .get_block_by_number(
                BlockNumberOrTag::Number(block.header.number - 1),
                alloy::rpc::types::BlockTransactionsKind::Full,
            )
            .await?
            .unwrap();

        let mp2_computed = block.block_hash();
        let alloy_computed = block.header.hash_slow();
        assert_eq!(mp2_computed.as_slice(), alloy_computed.as_slice());

        // CHECK RLP ENCODING FROM ETHERS MMODIF AND ALLOY
        let ethers_provider = ethers::providers::Provider::<Http>::try_from(url)
            .expect("could not instantiate HTTP Provider");
        let ethers_block = ethers_provider
            .get_block_with_txs(BlockNumber::Number(U64::from(block.header.number)))
            .await?
            .unwrap();
        // sanity check that ethers manual rlp implementation works
        assert_eq!(block.header.hash.as_slice(), ethers_block.block_hash());
        let ethers_rlp = ethers_block.rlp();
        let alloy_rlp = block.header.rlp();
        assert_eq!(ethers_rlp, alloy_rlp);
        let manual_alloy_rlp = block.header.rlp();
        let ethers_stream = rlp::Rlp::new(&ethers_rlp);
        let manual_stream = rlp::Rlp::new(&manual_alloy_rlp);
        compare_rlp(ethers_stream, manual_stream);
        assert_eq!(ethers_rlp, manual_alloy_rlp);

        let previous_computed = previous_block.block_hash();
        assert_eq!(&previous_computed, block.header.parent_hash.as_slice());
        let alloy_given = block.header.hash;
        assert_eq!(alloy_given, alloy_computed);
        Ok(())
    }

    fn compare_rlp<'a>(a: rlp::Rlp<'a>, b: rlp::Rlp<'a>) {
        let ap = a.payload_info().unwrap();
        let bp = b.payload_info().unwrap();
        assert_eq!(
            a.item_count().unwrap(),
            b.item_count().unwrap(),
            "not same item count in  list"
        );
        assert_eq!(
            ap.header_len, bp.header_len,
            "payloads different header len"
        );
        assert_eq!(a.is_list(), b.is_list());
        println!(
            "Item count for block RLP => a = {}, b = {}",
            a.item_count().unwrap(),
            b.item_count().unwrap()
        );
        for i in 0..a.item_count().unwrap() {
            let ae = a.at(i).unwrap().as_raw();
            let be = b.at(i).unwrap().as_raw();
            println!("Checking element {} - len {} vs {}", i, ae.len(), be.len());
            assert_eq!(ae, be, "elements not the same at index {i}");
        }
        // FAILING
        assert_eq!(ap.value_len, bp.value_len, "payloads different value len");
    }
    /// TEST to compare alloy with ethers
    pub struct RLPBlock<'a, X>(pub &'a ethers::types::Block<X>);
    impl<X> Rlpable for ethers::types::Block<X> {
        fn rlp(&self) -> Vec<u8> {
            let rlp = RLPBlock(self);
            rlp::encode(&rlp).to_vec()
        }
    }
    impl<X> rlp::Encodable for RLPBlock<'_, X> {
        fn rlp_append(&self, s: &mut rlp::RlpStream) {
            s.begin_unbounded_list();
            s.append(&self.0.parent_hash);
            s.append(&self.0.uncles_hash);
            s.append(&self.0.author.unwrap_or_default());
            s.append(&self.0.state_root);
            s.append(&self.0.transactions_root);
            s.append(&self.0.receipts_root);
            s.append(&self.0.logs_bloom.unwrap_or_default());
            s.append(&self.0.difficulty);
            s.append(&self.0.number.unwrap_or_default());
            s.append(&self.0.gas_limit);
            s.append(&self.0.gas_used);
            s.append(&self.0.timestamp);
            s.append(&self.0.extra_data.to_vec());
            s.append(&self.0.mix_hash.unwrap_or_default());
            s.append(&self.0.nonce.unwrap_or_default());
            rlp_opt(s, &self.0.base_fee_per_gas);
            rlp_opt(s, &self.0.withdrawals_root);
            rlp_opt(s, &self.0.blob_gas_used);
            rlp_opt(s, &self.0.excess_blob_gas);
            rlp_opt(s, &self.0.parent_beacon_block_root);
            s.finalize_unbounded_list();
        }
    }
    /// Extracted from ether-rs
    pub(crate) fn rlp_opt<T: rlp::Encodable>(rlp: &mut rlp::RlpStream, opt: &Option<T>) {
        if let Some(inner) = opt {
            rlp.append(inner);
        }
    }
}
