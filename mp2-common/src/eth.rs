//! Module containing several structure definitions for Ethereum related operations
//! such as fetching blocks, transactions, creating MPTs, getting proofs, etc.
use alloy::{
    consensus::{ReceiptEnvelope as CRE, ReceiptWithBloom, TxReceipt, TxType},
    eips::BlockNumberOrTag,
    network::eip2718::Encodable2718,
    primitives::{Address, B256},
    providers::{Provider, ProviderLayer, RootProvider},
    rlp::Encodable as AlloyEncodable,
    rpc::types::{
        Block, BlockTransactions, EIP1186AccountProofResponse, ReceiptEnvelope, Transaction,
    },
    transports::{
        http::{Client, Http},
        Transport,
    },
};
use anyhow::{bail, Context, Result};
use eth_trie::{EthTrie, MemoryDB, Trie};
use ethereum_types::H256;
use log::warn;
use rlp::{Encodable, Prototype, Rlp};
use serde::{Deserialize, Serialize};
use std::{array::from_fn as create_array, sync::Arc};

use crate::{mpt_sequential::utils::bytes_to_nibbles, rlp::MAX_KEY_NIBBLE_LEN, utils::keccak256};

/// Retry number for the RPC request
const RETRY_NUM: usize = 3;

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
            .get_block_by_number(BlockNumberOrTag::Latest, true)
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StorageSlot {
    /// simple storage slot like a uin256 etc that fits in 32bytes
    /// Argument is the slot location in the contract
    Simple(usize),
    /// Mapping storage slot - to get the proof, one needs to know
    /// the entry, the "mapping key" to derive the MPT key
    /// Second argument is the slot location inthe contract
    /// (mapping_key, mapping_slot)
    Mapping(Vec<u8>, usize),
}
impl StorageSlot {
    pub fn slot(&self) -> u8 {
        match self {
            StorageSlot::Simple(slot) => *slot as u8,
            StorageSlot::Mapping(_, slot) => *slot as u8,
        }
    }
    pub fn location(&self) -> B256 {
        match self {
            StorageSlot::Simple(slot) => B256::left_padding_from(&(*slot as u64).to_be_bytes()[..]),
            StorageSlot::Mapping(mapping_key, mapping_slot) => {
                // H( pad32(address), pad32(mapping_slot))
                let padded_mkey = left_pad32(mapping_key);
                let padded_slot = left_pad32(&[*mapping_slot as u8]);
                let concat = padded_mkey
                    .into_iter()
                    .chain(padded_slot)
                    .collect::<Vec<_>>();
                B256::from_slice(&keccak256(&concat))
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
        }
    }
}
impl ProofQuery {
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
            match provider
                .get_proof(self.contract, vec![self.slot.location()])
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
        let proof_key_bytes = proof.storage_proof[0].key.0;
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

        // According to EIP-1186, accountProof starts with the the state root.
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

// since alloy exports two header structs, and from RPC we only receive the rpc-defined one that
// does not contain the methods to get the RLP encoding and the hash, we have to pass from one to
// another manually.
fn from_rpc_header_to_consensus(h: &alloy::rpc::types::Header) -> alloy::consensus::Header {
    alloy::consensus::Header {
        parent_hash: h.parent_hash,
        ommers_hash: h.uncles_hash,
        beneficiary: h.miner,
        state_root: h.state_root,
        transactions_root: h.transactions_root,
        receipts_root: h.receipts_root,
        withdrawals_root: h.withdrawals_root,
        logs_bloom: h.logs_bloom,
        difficulty: h.difficulty,
        number: h.number,
        gas_limit: h.gas_limit,
        gas_used: h.gas_used,
        timestamp: h.timestamp,
        mix_hash: h.mix_hash.unwrap(),
        nonce: h.nonce.unwrap(),
        base_fee_per_gas: h.base_fee_per_gas,
        blob_gas_used: h.blob_gas_used,
        excess_blob_gas: h.excess_blob_gas,
        parent_beacon_block_root: h.parent_beacon_block_root,
        requests_root: h.requests_root,
        extra_data: h.extra_data.clone(),
    }
}

impl Rlpable for alloy::rpc::types::Block {
    fn rlp(&self) -> Vec<u8> {
        self.header.rlp()
    }
}

impl Rlpable for alloy::rpc::types::Header {
    fn rlp(&self) -> Vec<u8> {
        from_rpc_header_to_consensus(self).rlp()
    }
}

impl Rlpable for alloy::consensus::Header {
    fn rlp(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }
}

pub struct BlockUtil {
    pub block: Block,
    pub txs: Vec<TxWithReceipt>,
    pub receipts_trie: EthTrie<MemoryDB>,
}

pub struct TxWithReceipt(Transaction, ReceiptEnvelope);
impl TxWithReceipt {
    pub fn receipt(&self) -> ReceiptEnvelope {
        self.1.clone()
    }
}

impl BlockUtil {
    pub async fn fetch(t: RootProvider<Http<Client>>, id: BlockNumberOrTag) -> Result<BlockUtil> {
        let block = t
            .get_block(id.into(), alloy::rpc::types::BlockTransactionsKind::Full)
            .await?
            .context("can't get block")?;
        let receipts = t
            .get_block_receipts(id.into())
            .await?
            .context("can't get receipts")?;
        let BlockTransactions::Full(all_tx) = block.transactions.clone() else {
            bail!("can't see full transactions");
        };
        let tx_receipts: Vec<(_, _)> = receipts
            .into_iter()
            .map(|receipt| {
                (
                    all_tx
                        .iter()
                        .find(|tx| tx.hash == receipt.transaction_hash)
                        .expect("no tx with receipt hash")
                        .clone(),
                    receipt,
                )
            })
            .collect();
        // check receipt root
        let memdb = Arc::new(MemoryDB::new(true));
        let mut receipts_trie = EthTrie::new(Arc::clone(&memdb));
        let consensus_receipts = tx_receipts
            .into_iter()
            .map(|tr| {
                let receipt = tr.1;
                let tx_index = receipt.transaction_index.unwrap().rlp_bytes();
                //let mut buff = Vec::new();
                let receipt_primitive = receipt.inner.clone();
                let receipt_primitive = match receipt_primitive {
                    CRE::Legacy(ref r) => CRE::Legacy(from_rpc_logs_to_consensus(&r)),
                    CRE::Eip2930(ref r) => CRE::Eip2930(from_rpc_logs_to_consensus(&r)),
                    CRE::Eip1559(ref r) => CRE::Eip1559(from_rpc_logs_to_consensus(&r)),
                    CRE::Eip4844(ref r) => CRE::Eip4844(from_rpc_logs_to_consensus(&r)),
                    CRE::Eip7702(ref r) => CRE::Eip7702(from_rpc_logs_to_consensus(&r)),
                    _ => panic!("aie"),
                };
                let body_rlp = receipt_primitive.encoded_2718();

                println!(
                    "TX index {} RLP encoded: {:?}",
                    receipt.transaction_index.unwrap(),
                    tx_index.to_vec()
                );
                receipts_trie
                    .insert(&tx_index, &body_rlp)
                    .expect("can't insert tx");
                TxWithReceipt(tr.0, receipt_primitive)
            })
            .collect::<Vec<_>>();
        Ok(BlockUtil {
            block,
            txs: consensus_receipts,
            receipts_trie,
        })
    }

    // recompute the receipts trie by first converting all receipts form RPC type to consensus type
    // since in Alloy these are two different types and RLP functions are only implemented for
    // consensus ones.
    // TODO: transaction trie
    fn check(&mut self) -> Result<()> {
        let computed = self.receipts_trie.root_hash().expect("root hash problem");
        let expected = self.block.header.receipts_root;
        assert_eq!(expected.to_vec(), computed.0.to_vec());
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

// for compatibility check with alloy
#[cfg(test)]
mod tryethers {

    use std::sync::Arc;

    use anyhow::Result;
    use eth_trie::{EthTrie, MemoryDB, Trie};
    use ethers::{
        providers::{Http, Middleware, Provider},
        types::{
            Address, Block, BlockId, Bytes, EIP1186ProofResponse, Transaction, TransactionReceipt,
            H256, U64,
        },
    };
    use rlp::{Encodable, Rlp, RlpStream};

    /// A wrapper around a transaction and its receipt. The receipt is used to filter
    /// bad transactions, so we only compute over valid transactions.
    pub struct TxAndReceipt(Transaction, TransactionReceipt);

    impl TxAndReceipt {
        pub fn tx(&self) -> &Transaction {
            &self.0
        }
        pub fn receipt(&self) -> &TransactionReceipt {
            &self.1
        }
        pub fn tx_rlp(&self) -> Bytes {
            self.0.rlp()
        }
        // TODO: this should be upstreamed to ethers-rs
        pub fn receipt_rlp(&self) -> Bytes {
            let tx_type = self.tx().transaction_type;
            let mut rlp = RlpStream::new();
            rlp.begin_unbounded_list();
            match &self.1.status {
                Some(s) if s.as_u32() == 1 => rlp.append(s),
                _ => rlp.append_empty_data(),
            };
            rlp.append(&self.1.cumulative_gas_used)
                .append(&self.1.logs_bloom)
                .append_list(&self.1.logs);

            rlp.finalize_unbounded_list();
            let rlp_bytes: Bytes = rlp.out().freeze().into();
            let mut encoded = vec![];
            match tx_type {
                // EIP-2930 (0x01)
                Some(x) if x == U64::from(0x1) => {
                    encoded.extend_from_slice(&[0x1]);
                    encoded.extend_from_slice(rlp_bytes.as_ref());
                    encoded.into()
                }
                // EIP-1559 (0x02)
                Some(x) if x == U64::from(0x2) => {
                    encoded.extend_from_slice(&[0x2]);
                    encoded.extend_from_slice(rlp_bytes.as_ref());
                    encoded.into()
                }
                _ => rlp_bytes,
            }
        }
    }
    /// Structure containing the block header and its transactions / receipts. Amongst other things,
    /// it is used to create a proof of inclusion for any transaction inside this block.
    pub struct BlockData {
        pub block: ethers::types::Block<Transaction>,
        pub txs: Vec<TxAndReceipt>,
        // TODO: add generics later - this may be re-used amongst different workers
        pub tx_trie: EthTrie<MemoryDB>,
        pub receipts_trie: EthTrie<MemoryDB>,
    }

    impl BlockData {
        pub async fn fetch<T: Into<BlockId> + Send + Sync>(
            blockid: T,
            url: String,
        ) -> Result<Self> {
            let provider =
                Provider::<Http>::try_from(url).expect("could not instantiate HTTP Provider");
            Self::fetch_from(&provider, blockid).await
        }
        pub async fn fetch_from<T: Into<BlockId> + Send + Sync>(
            provider: &Provider<Http>,
            blockid: T,
        ) -> Result<Self> {
            let block = provider
                .get_block_with_txs(blockid)
                .await?
                .expect("should have been a block");
            let receipts = provider.get_block_receipts(block.number.unwrap()).await?;

            let tx_with_receipt = block
                .transactions
                .clone()
                .into_iter()
                .map(|tx| {
                    let tx_hash = tx.hash();
                    let r = receipts
                        .iter()
                        .find(|r| r.transaction_hash == tx_hash)
                        .expect("RPC sending invalid data");
                    // TODO remove cloning
                    TxAndReceipt(tx, r.clone())
                })
                .collect::<Vec<_>>();

            // check transaction root
            let memdb = Arc::new(MemoryDB::new(true));
            let mut tx_trie = EthTrie::new(Arc::clone(&memdb));
            for tr in tx_with_receipt.iter() {
                tx_trie
                    .insert(&tr.receipt().transaction_index.rlp_bytes(), &tr.tx().rlp())
                    .expect("can't insert tx");
            }

            // check receipt root
            let memdb = Arc::new(MemoryDB::new(true));
            let mut receipts_trie = EthTrie::new(Arc::clone(&memdb));
            for tr in tx_with_receipt.iter() {
                if tr.tx().transaction_index.unwrap() == U64::from(0) {
                    println!(
                        "Ethers: Index {} -> {:?}",
                        tr.tx().transaction_index.unwrap(),
                        tr.receipt_rlp().to_vec()
                    );
                }
                receipts_trie
                    .insert(
                        &tr.receipt().transaction_index.rlp_bytes(),
                        // TODO: make getter value for rlp encoding
                        &tr.receipt_rlp(),
                    )
                    .expect("can't insert tx");
            }
            let computed = tx_trie.root_hash().expect("root hash problem");
            let expected = block.transactions_root;
            assert_eq!(expected, computed);

            let computed = receipts_trie.root_hash().expect("root hash problem");
            let expected = block.receipts_root;
            assert_eq!(expected, computed);

            Ok(BlockData {
                block,
                tx_trie,
                receipts_trie,
                txs: tx_with_receipt,
            })
        }
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "ci")]
    use std::env;
    use std::str::FromStr;

    use alloy::{primitives::Bytes, providers::ProviderBuilder, rpc::types::BlockTransactionsKind};
    use eth_trie::Nibbles;
    use ethereum_types::U64;
    use ethers::{
        providers::{Http, Middleware},
        types::BlockNumber,
    };
    use hashbrown::HashMap;

    use crate::{
        mpt_sequential::utils::nibbles_to_bytes,
        types::MAX_BLOCK_LEN,
        utils::{Endianness, Packer},
    };
    use mp2_test::eth::{get_mainnet_url, get_sepolia_url};

    use super::*;

    #[tokio::test]
    async fn test_block_receipt_trie() -> Result<()> {
        let url = get_sepolia_url();
        // get some tx and receipt
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());
        let bn = 6893107;
        let bna = BlockNumberOrTag::Number(bn);
        let mut block = BlockUtil::fetch(provider, bna).await?;
        // check if we compute the RLP correctly now
        block.check()?;
        let mut be = tryethers::BlockData::fetch(bn, url).await?;
        let er = be.receipts_trie.root_hash()?;
        let ar = block.receipts_trie.root_hash()?;
        assert_eq!(er, ar);
        // dissect one receipt entry in the trie
        let tx_receipt = block.txs.first().clone().unwrap();
        // https://sepolia.etherscan.io/tx/0x9bef12fafd3962b0e0d66b738445d6ea2c1f3daabe10c889bd1916acc75d698b#eventlog
        println!(
            "Looking at tx hash on sepolia: {}",
            hex::encode(tx_receipt.0.hash)
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
        let found_data = hex::encode(&left_pad32(
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
            Address::from_str("0x188B264AA1456B869C3a92eeeD32117EbB835f47").unwrap();
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
            .get_block_by_number(BlockNumberOrTag::Latest, true)
            .await?
            .unwrap();
        let previous_block = provider
            .get_block_by_number(BlockNumberOrTag::Number(block.header.number - 1), true)
            .await?
            .unwrap();

        let mp2_computed = block.block_hash();
        let alloy_computed = from_rpc_header_to_consensus(&block.header).hash_slow();
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
        let alloy_rlp = from_rpc_header_to_consensus(&block.header).rlp();
        assert_eq!(ethers_rlp, alloy_rlp);
        let manual_alloy_rlp = from_rpc_header_to_consensus(&block.header).rlp();
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
    impl<'a, X> rlp::Encodable for RLPBlock<'a, X> {
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
