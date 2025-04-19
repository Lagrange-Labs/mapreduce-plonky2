//! Module containing several structure definitions for Ethereum related operations
//! such as fetching blocks, transactions, creating MPTs, getting proofs, etc.
use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, B256, U256},
    providers::{Provider, RootProvider},
    rlp::Encodable as AlloyEncodable,
    rpc::types::{Block, EIP1186AccountProofResponse},
    transports::Transport,
};
use anyhow::{anyhow, bail, Result};
use eth_trie::{EthTrie, MemoryDB, Trie};
use ethereum_types::H256;
use itertools::Itertools;
use log::debug;
use log::warn;
use rlp::Rlp;
use serde::{Deserialize, Serialize};
use std::{array::from_fn as create_array, sync::Arc};

use crate::{mpt_sequential::utils::bytes_to_nibbles, rlp::MAX_KEY_NIBBLE_LEN, utils::keccak256};

/// Retry number for the RPC request
const RETRY_NUM: usize = 3;

pub trait BlockUtil {
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

#[derive(Clone, Debug, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum NodeType {
    Branch,
    Extension,
    Leaf,
}

/// Function that returns the [`NodeType`] of an RLP encoded MPT node
pub fn node_type(rlp_data: &[u8]) -> Result<NodeType> {
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
            _ => Err(anyhow!(
                "Expected compact encoding beginning with 0,1,2 or 3".to_string(),
            )),
        }
    } else {
        Err(anyhow!(
            "RLP encoded Node item count was {item_count}, expected either 17 or 2"
        ))
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

/// Query the latest block.
pub async fn query_latest_block<T: Transport + Clone>(provider: &RootProvider<T>) -> Result<Block> {
    // Query the MPT proof with retries.
    for i in 0..RETRY_NUM {
        if let Ok(response) = provider
            .get_block_by_number(BlockNumberOrTag::Latest, true.into())
            .await
        {
            // Has one block at least.
            return Ok(response.unwrap());
        } else {
            warn!("Failed to query the block - {i} time")
        }
    }

    bail!("Failed to query the block ");
}

pub struct ProofQuery {
    pub contract: Address,
    pub(crate) slot: StorageSlot,
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
    pub fn new_mapping(parent: StorageSlot, mapping_key: Vec<u8>) -> Result<Self> {
        let parent = Box::new(parent);
        if !matches!(
            *parent,
            StorageSlot::Mapping(_, _) | StorageSlot::Node(Self::Mapping(_, _))
        ) {
            bail!("The parent of a Slot mapping entry must be type of mapping");
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
    ) -> Result<EIP1186AccountProofResponse> {
        // Query the MPT proof with retries.
        for i in 0..RETRY_NUM {
            let location = self.slot.location();
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

        bail!("Failed to query the MPT proof {RETRY_NUM} in total");
    }
    /// Returns the raw value from the storage proof, not the one "interpreted" by the
    /// JSON RPC so we can see how the encoding is done.
    pub fn verify_storage_proof(proof: &EIP1186AccountProofResponse) -> Result<Vec<u8>> {
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
        );
        // key must be valid, proof must be valid and value must exist
        if is_valid.is_err() {
            bail!("proof is not valid");
        }
        if let Some(ext_value) = is_valid.unwrap() {
            Ok(ext_value)
        } else {
            bail!("proof says the value associated with that key does not exist");
        }
    }
    pub fn verify_state_proof(&self, res: &EIP1186AccountProofResponse) -> Result<()> {
        let memdb = Arc::new(MemoryDB::new(true));
        let tx_trie = EthTrie::new(Arc::clone(&memdb));

        // According to EIP-1186, accountProof starts with the state root.
        let state_root_hash = H256(keccak256(&res.account_proof[0]).try_into().unwrap());

        // The MPT key is Keccak hash of the contract (requested) address.
        let mpt_key = keccak256(self.contract.0.as_slice());

        let is_valid = tx_trie.verify_proof(
            state_root_hash,
            &mpt_key,
            res.account_proof.iter().map(|b| b.to_vec()).collect(),
        );

        if is_valid.is_err() {
            bail!("Account proof is invalid");
        }
        if is_valid.unwrap().is_none() {
            bail!("Account proof says the value associated with that key does not exist");
        }

        // The length of acount node must be 104 bytes (8 + 32 + 32 + 32) as:
        // [nonce (U64), balance (U256), storage_hash (H256), code_hash (H256)]
        let account_node = res.account_proof.last().unwrap();
        assert_eq!(account_node.len(), 104);

        Ok(())
    }
}

impl BlockUtil for alloy::rpc::types::Block {
    fn rlp(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.header.encode(&mut out);
        out
    }
}

impl BlockUtil for alloy::rpc::types::Header {
    fn rlp(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "ci")]
    use std::env;
    use std::str::FromStr;

    use alloy::{primitives::Bytes, providers::ProviderBuilder};
    use hashbrown::HashMap;

    use crate::{
        types::MAX_BLOCK_LEN,
        utils::{Endianness, Packer},
    };
    use mp2_test::eth::{get_mainnet_url, get_sepolia_url};

    #[tokio::test]
    #[ignore]
    async fn test_rlp_andrus() -> Result<()> {
        let url = get_sepolia_url();
        let block_number1 = 5674446;
        let block_number2 = block_number1 + 1;
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());
        let block = provider
            .get_block(BlockNumberOrTag::Number(block_number1).into(), false.into())
            .await?
            .unwrap();
        let comp_hash = keccak256(&block.rlp());
        let block_next = provider
            .get_block(BlockNumberOrTag::from(block_number2).into(), false.into())
            .await?
            .unwrap();
        let exp_hash = block_next.header.parent_hash;
        assert!(comp_hash == exp_hash.as_slice());
        assert!(
            block.rlp().len() <= MAX_BLOCK_LEN,
            " rlp len = {}",
            block.rlp().len()
        );
        Ok(())
    }

    use super::*;
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
        // holder: 0x188b264aa1456b869c3a92eeed32117ebb835f47
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
                true.into(),
            )
            .await?
            .unwrap();

        let mp2_computed = block.block_hash();
        let alloy_computed = block.header.hash_slow();
        assert_eq!(mp2_computed.as_slice(), alloy_computed.as_slice());

        let previous_computed = previous_block.block_hash();
        assert_eq!(&previous_computed, block.header.parent_hash.as_slice());
        let alloy_given = block.header.hash;
        assert_eq!(alloy_given, alloy_computed);
        Ok(())
    }
}
