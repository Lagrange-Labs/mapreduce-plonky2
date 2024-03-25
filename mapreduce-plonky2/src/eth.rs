//! Module containing several structure definitions for Ethereum related operations
//! such as fetching blocks, transactions, creating MPTs, getting proofs, etc.
use anyhow::{bail, Ok, Result};
use eth_trie::{EthTrie, MemoryDB, Node, Trie};
use ethers::{
    providers::{Http, Middleware, Provider},
    types::{
        Address, Block, BlockId, Bytes, EIP1186ProofResponse, Transaction, TransactionReceipt,
        H256, U64,
    },
};
use rlp::{Encodable, Rlp, RlpStream};
#[cfg(feature = "ci")]
use std::env;
use std::{array::from_fn as create_array, sync::Arc};

use crate::{mpt_sequential::bytes_to_nibbles, rlp::MAX_KEY_NIBBLE_LEN, utils::keccak256};
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
    pub async fn fetch<T: Into<BlockId> + Send + Sync>(blockid: T) -> Result<Self> {
        #[cfg(feature = "ci")]
        let url = env::var("CI_ETH").expect("CI_ETH env var not set");
        #[cfg(not(feature = "ci"))]
        let url = "https://eth.llamarpc.com";
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
pub struct RLPBlock<'a, X>(pub &'a Block<X>);
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
/// Computes the length of the radix, of the "key" to lookup in the MPT trie, from
/// the path of nodes given.
/// TODO: transform that to only use the raw encoded bytes, instead of the nodes. Would
/// allow us to remove the need to give the proofs as nodes.
pub(crate) fn compute_key_length(path: &[Node]) -> usize {
    let mut key_len = 0;
    for node in path {
        match node {
            Node::Branch(_) => key_len += 1,
            Node::Extension(e) => key_len += e.read().unwrap().prefix.len(),
            Node::Leaf(l) => key_len += l.key.len(),
            Node::Hash(_) => panic!("what is a hash node!?"),
            Node::Empty => panic!("should not be an empty node in the path"),
        }
    }
    key_len
}

pub(crate) fn left_pad32(slice: &[u8]) -> [u8; 32] {
    left_pad::<32>(slice)
}

pub(crate) fn left_pad<const N: usize>(slice: &[u8]) -> [u8; N] {
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

pub(crate) struct ProofQuery {
    pub(crate) contract: Address,
    pub(crate) slot: StorageSlot,
}

#[derive(Clone, Debug)]
pub(crate) enum StorageSlot {
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
    pub fn location(&self) -> H256 {
        match self {
            StorageSlot::Simple(slot) => H256::from_low_u64_be(*slot as u64),
            StorageSlot::Mapping(mapping_key, mapping_slot) => {
                // H( pad32(address), pad32(mapping_slot))
                let padded_mkey = left_pad32(mapping_key);
                let padded_slot = left_pad32(&[*mapping_slot as u8]);
                let concat = padded_mkey
                    .into_iter()
                    .chain(padded_slot)
                    .collect::<Vec<_>>();
                H256::from_slice(&keccak256(&concat))
            }
        }
    }
    pub fn mpt_key_vec(&self) -> Vec<u8> {
        keccak256(&self.location().to_fixed_bytes())
    }
    pub fn mpt_key(&self) -> [u8; 32] {
        let hash = keccak256(&self.location().to_fixed_bytes());
        create_array(|i| hash[i])
    }
    pub fn mpt_nibbles(&self) -> [u8; MAX_KEY_NIBBLE_LEN] {
        bytes_to_nibbles(&self.mpt_key_vec()).try_into().unwrap()
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
    pub async fn query_mpt_proof<P: Middleware + 'static>(
        &self,
        provider: &P,
        block: Option<BlockId>,
    ) -> Result<EIP1186ProofResponse> {
        let res = provider
            .get_proof(self.contract, vec![self.slot.location()], block)
            .await?;
        Ok(res)
    }
    /// Returns the raw value from the storage proof, not the one "interpreted" by the
    /// JSON RPC so we can see how the encoding is done.
    pub fn verify_storage_proof(proof: &EIP1186ProofResponse) -> Result<Vec<u8>> {
        let memdb = Arc::new(MemoryDB::new(true));
        let tx_trie = EthTrie::new(Arc::clone(&memdb));
        let proof_key_bytes: [u8; 32] = proof.storage_proof[0].key.into();
        let mpt_key = keccak256(&proof_key_bytes[..]);
        let is_valid = tx_trie.verify_proof(
            proof.storage_hash,
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
    pub fn verify_state_proof(&self, res: &EIP1186ProofResponse) -> Result<()> {
        let memdb = Arc::new(MemoryDB::new(true));
        let tx_trie = EthTrie::new(Arc::clone(&memdb));

        // According to EIP-1186, accountProof starts with the the state root.
        let state_root_hash = H256(keccak256(&res.account_proof[0]).try_into().unwrap());

        // The MPT key is Keccak hash of the contract (requested) address.
        let mpt_key = keccak256(&self.contract.0);

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

#[cfg(test)]
mod test {

    use std::str::FromStr;

    use ethers::types::{BlockNumber, H256, U256};
    use rand::{thread_rng, Rng};

    use crate::{
        mpt_sequential::test::verify_storage_proof_from_query,
        utils::{convert_u8_to_u32_slice, find_index_subvector},
    };

    use super::*;

    #[tokio::test]
    async fn test_pidgy_pinguin_length_slot() -> Result<()> {
        #[cfg(feature = "ci")]
        let url = env::var("CI_ETH").expect("CI_ETH env var not set");
        #[cfg(not(feature = "ci"))]
        let url = "https://eth.llamarpc.com";
        let provider =
            Provider::<Http>::try_from(url).expect("could not instantiate HTTP Provider");

        // pidgy pinguins address
        let pidgy_address = Address::from_str("0xBd3531dA5CF5857e7CfAA92426877b022e612cf8")?;
        let query = ProofQuery::new_simple_slot(pidgy_address, 8);
        let res = query.query_mpt_proof(&provider, None).await?;
        ProofQuery::verify_storage_proof(&res)?;
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
        println!("sliced: {:?} - hex {}", sliced, hex::encode(&sliced));
        let length = convert_u8_to_u32_slice(&n)[0];
        let length2 =
            convert_u8_to_u32_slice(&sliced.iter().cloned().rev().collect::<Vec<u8>>())[0];
        println!("length extracted = {}", length);
        println!("length 2 extracted = {}", length2);
        println!("res.storage_proof.value = {}", res.storage_proof[0].value);
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
        let url = "https://eth.llamarpc.com";
        let provider =
            Provider::<Http>::try_from(url).expect("could not instantiate HTTP Provider");

        // extracting from
        // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol
        // assuming it's using ERC731Enumerable that inherits ERC721
        let mapping_slot = 2;
        // pudgy pinguins
        let pudgy_address = Address::from_str("0xBd3531dA5CF5857e7CfAA92426877b022e612cf8")?;
        let query = ProofQuery::new_mapping_slot(pudgy_address, mapping_slot, mapping_key.to_vec());
        let res = query.query_mpt_proof(&provider, None).await?;
        let raw_address = ProofQuery::verify_storage_proof(&res)?;
        // the value is actually RLP encoded !
        let decoded_address: Vec<u8> = rlp::decode(&raw_address).unwrap();
        let leaf_node: Vec<Vec<u8>> = rlp::decode_list(&res.storage_proof[0].proof.last().unwrap());
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
        #[cfg(feature = "ci")]
        let url = env::var("CI_SEPOLIA").expect("CI_SEPOLIA env var not set");
        #[cfg(not(feature = "ci"))]
        let url = "https://ethereum-sepolia-rpc.publicnode.com";

        let provider =
            Provider::<Http>::try_from(url).expect("could not instantiate HTTP Provider");

        // sepolia contract
        let contract = Address::from_str("0xd6a2bFb7f76cAa64Dad0d13Ed8A9EFB73398F39E")?;
        // simple storage test
        {
            let query = ProofQuery::new_simple_slot(contract, 0);
            let res = query.query_mpt_proof(&provider, None).await?;
            ProofQuery::verify_storage_proof(&res)?;
            query.verify_state_proof(&res)?;
        }
        {
            // mapping key
            let mapping_key =
                hex::decode("000000000000000000000000000000000000000000000000000000000001abcd")?;
            let query = ProofQuery::new_mapping_slot(contract, 1, mapping_key);
            let res = query.query_mpt_proof(&provider, None).await?;
            ProofQuery::verify_storage_proof(&res)?;
            query.verify_state_proof(&res)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn fetch_block() -> Result<()> {
        let block_number = 10593419;
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

        println!("block hash : {:?}", hex::encode(computed));
        println!(
            "block tx root hash : {:?}",
            hex::encode(block.tx_trie.root_hash()?)
        );
        let random_idx = thread_rng().gen_range(0..block.txs.len());
        let mut proof = block
            .tx_trie
            .get_proof(&U64::from(random_idx).rlp_bytes())?;
        proof.reverse();
        println!("Proof for tx index {:?}", random_idx);
        for i in 1..proof.len() {
            let child_hash = keccak256(&proof[i - 1]);
            match find_index_subvector(&proof[i], &child_hash) {
                Some(index) => {
                    println!(
                        "Index node {}: child hash found index {} in proof",
                        i, index
                    );
                }
                None => {
                    println!("could not find index in proof");
                }
            }
        }
        Ok(())
    }
}
