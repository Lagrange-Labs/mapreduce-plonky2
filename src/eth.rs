//! Module containing several structure definitions for Ethereum related operations
//! such as fetching blocks, transactions, creating MPTs, getting proofs, etc.
use anyhow::{Ok, Result};
use eth_trie::{EthTrie, MemoryDB, Node, Trie};
use ethers::{
    providers::{Http, Middleware, Provider},
    types::{Block, BlockId, Bytes, Transaction, TransactionReceipt, U64},
};
use rlp::{Encodable, Rlp, RlpStream};
use std::{env, sync::Arc};

use crate::utils::keccak256;
/// A wrapper around a transaction and its receipt. The receipt is used to filter
/// bad transactions, so we only compute over valid transactions.
pub(crate) struct TxAndReceipt(Transaction, TransactionReceipt);

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
    pub async fn fetch<T: Into<BlockId> + Send + Sync>(blockid: T) -> Result<Self> {
        #[cfg(feature = "ci")]
        let url = env::var("CI_RPC_URL").expect("RPC_URL env var not set");
        #[cfg(not(feature = "ci"))]
        let url = "https://eth.llamarpc.com";
        //let provider = Provider::<Http>::try_from
        let provider =
            Provider::<Http>::try_from(url).expect("could not instantiate HTTP Provider");

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

pub(crate) trait BlockUtil {
    fn block_hash(&self) -> Vec<u8> {
        keccak256(&self.rlp())
    }
    fn rlp(&self) -> Vec<u8>;
}

impl<X> BlockUtil for Block<X> {
    fn rlp(&self) -> Vec<u8> {
        let rlp = RLPBlock(self);
        rlp::encode(&rlp).to_vec()
    }
}
pub(crate) struct RLPBlock<'a, X>(pub &'a Block<X>);
impl<'a, X> rlp::Encodable for RLPBlock<'a, X> {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_unbounded_list();
        s.append(&self.0.parent_hash);
        s.append(&self.0.uncles_hash);
        s.append(&self.0.author.unwrap());
        s.append(&self.0.state_root);
        s.append(&self.0.transactions_root);
        s.append(&self.0.receipts_root);
        s.append(&self.0.logs_bloom.unwrap());
        s.append(&self.0.difficulty);
        s.append(&self.0.number.unwrap());
        s.append(&self.0.gas_limit);
        s.append(&self.0.gas_used);
        s.append(&self.0.timestamp);
        s.append(&self.0.extra_data.to_vec());
        s.append(&self.0.mix_hash.unwrap());
        s.append(&self.0.nonce.unwrap());
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

/// Extract the hash in case of Extension node, or all the hashes in case of a Branch node.
pub(crate) fn extract_child_hashes(rlp_data: &[u8]) -> Vec<Vec<u8>> {
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
/// Computes the length of the radix, of the "key" to lookup in the MPT trie, from
/// the path of nodes given.
/// TODO: transform that to only use the raw encoded bytes, instead of the nodes. Would
/// allow us to remove the need to give the proofs as nodes.
pub(crate) fn compute_key_length(path: &[Node]) -> usize {
    let mut key_len = 0;
    for node in path {
        match node {
            Node::Branch(b) => key_len += 1,
            Node::Extension(e) => key_len += e.read().unwrap().prefix.len(),
            Node::Leaf(l) => key_len += l.key.len(),
            Node::Hash(h) => panic!("what is a hash node!?"),
            Node::Empty => panic!("should not be an empty node in the path"),
        }
    }
    key_len
}
#[cfg(test)]
mod test {
    use ethers::types::H256;

    use super::*;

    #[tokio::test]
    async fn fetch_block() -> Result<()> {
        let block_number = 10593417;
        let mut block = BlockData::fetch(block_number).await?;
        assert_eq!(block.block.number.unwrap(), block_number.into());
        let computed = block.block.block_hash();
        let expected = block.block.hash.unwrap();
        assert_eq!(computed.to_vec(), expected.as_bytes());
        let thin_block: Block<H256> = block.block.clone().into();
        let encoding = serde_json::to_vec(&thin_block).unwrap();
        let thin_block2: Block<H256> = serde_json::from_slice(&encoding).unwrap();
        //let encoding = bincode::serialize(&thin_block).unwrap();
        //let thin_block2: Block<H256> = bincode::deserialize(&encoding).unwrap();
        //let encoding = rmp_serde::encode::to_vec(&thin_block).unwrap();
        //let thin_block2: Block<H256> = rmp_serde::decode::from_slice(&encoding).unwrap();
        assert_eq!(thin_block, thin_block2);

        println!("block serialize() : {:?}", hex::encode(encoding));
        println!("block hash : {:?}", hex::encode(computed));
        println!(
            "block tx root hash : {:?}",
            hex::encode(block.tx_trie.root_hash()?)
        );
        Ok(())
    }
}
