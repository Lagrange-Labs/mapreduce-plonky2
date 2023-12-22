use crate::eth::RLPBlock;
use crate::transaction::proof::{IntermediateMPT, ProofType, RootMPTHeader, TransactionMPT};
use crate::{
    eth::{extract_child_hashes, BlockData},
    utils::keccak256,
};
use anyhow::anyhow;
use anyhow::Result;
use eth_trie::Trie;
use ethers::types::{Transaction, H256};
use ethers::{types::BlockId, utils::hex};
use rlp::Encodable;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub enum TxFilter {
    // only prove tx that are less than this size in bytes
    BySize(usize),
    // only prove the tx which have these hashes
    ByHash(Vec<H256>),
    // no policy at all
    #[default]
    Everything,
}

impl TxFilter {
    pub fn should_prove(&self, tx: &Transaction) -> (bool, String) {
        match self {
            Self::BySize(max_size) => (
                tx.rlp().len() <= *max_size,
                format!("tx size {} <= {}", tx.rlp().len(), max_size),
            ),
            Self::ByHash(hashes) => (
                hashes.contains(&tx.hash()),
                format!("tx not contained {:?}", tx.hash()),
            ),
            Self::Everything => (true, "".to_string()),
        }
    }
}
pub struct TxBlockProver {
    pub data: BlockData,
    pub policy: TxFilter,
    #[cfg(test)]
    pub nb_nodes: usize,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MPTNode {
    pub node_bytes: Vec<u8>, // RLP byte representation of the node
    pub hash: Vec<u8>,       // its hash
    // ALL the children of this node if any (zero if leaf for example)
    pub total_nb_children: usize,
    // expected children hashes - will be filled in with only the hashes that we
    // traverse in the proofs of all tx we are looking at. For the nodes that we don't
    // traverse, their hash may be in children_hashes, and we'll only provide a "null" proof
    // for them.
    pub exp_children: Vec<Vec<u8>>,
    // child i : (key, proof) - key needed locate where is the hash of the child in the node
    pub rcvd_children_proofs: Vec<ProverOutput>, // will be filled in
    pub parent_hash: Option<Vec<u8>>, // indicator to go up one level when this node has been "proven"
    /// Used for information about tx in the leaf node proving phase
    pub transaction: Option<Transaction>,
}
impl MPTNode {
    fn is_provable(&self) -> bool {
        if self.exp_children.len() == self.rcvd_children_proofs.len() {
            println!(
                "[+] Node proof {} : only {} / {} (exp) / {} (total) children proofs",
                hex::encode(&self.hash),
                self.rcvd_children_proofs.len(),
                self.exp_children.len(),
                self.total_nb_children,
            );
        }
        if !self
            .rcvd_children_proofs
            .iter()
            .all(|p| self.exp_children.contains(&p.hash))
        {
            panic!("some children proofs are not expected");
        }
        println!(
            "[+] Node proof {} : ALL {} / {} (exp) / {} (total)  received children proofs",
            hex::encode(&self.hash),
            self.rcvd_children_proofs.len(),
            self.exp_children.len(),
            self.total_nb_children,
        );
        true
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ProverOutput {
    parent_hash: Option<Vec<u8>>,
    // hash of this node
    hash: Vec<u8>,
    // plonky2 proof for this node
    proof: Vec<u8>,
}

/// Hash mapping the hash of a node in the trie to the data
type HashTrie = HashMap<Vec<u8>, MPTNode>;
impl TxBlockProver {
    pub async fn init<T: Into<BlockId> + Send + Sync>(id: T, policy: TxFilter) -> Result<Self> {
        let data = BlockData::fetch(id).await?;
        Ok(Self {
            data,
            policy,
            #[cfg(test)]
            nb_nodes: 0,
        })
    }

    pub fn prove(&mut self) -> Result<Vec<u8>> {
        let (mut trie, leaves_hashes) = self.init_proofs_trie();

        println!(
            "[+] Built internal trie with {} leaves, and {} nodes in total",
            leaves_hashes.len(),
            trie.len()
        );
        #[cfg(test)]
        {
            self.nb_nodes = trie.len();
        }
        let mut current_proofs = leaves_hashes
            .iter()
            .map(|h| self.run_leaf_proof(&trie, h.clone()))
            .collect::<Result<Vec<_>>>()?;
        while let Some(output) = current_proofs.pop() {
            let node_hash = hex::encode(&output.hash);
            if output.parent_hash.is_none() {
                // we have reached the root node !
                println!("[+] Reached root node {}", node_hash);
                return Ok(output.proof);
            }
            let parent_hash = output.parent_hash.as_ref().unwrap();
            let proof_node = trie
                .get_mut(parent_hash)
                .expect("every node should be in the trie");
            // a proof for one of the children of this node in the MPT has been computed!
            proof_node.rcvd_children_proofs.push(output);
            if proof_node.is_provable() {
                let parent_proof = if proof_node.parent_hash.is_none() {
                    // we have reached the root node so we now prove inclusion
                    // in the block header as well
                    println!("[+] Proving root node inclusion {}", node_hash);
                    self.run_root_node_proof(proof_node)?
                } else {
                    self.run_recursive_proof(proof_node)?
                };
                current_proofs.push(parent_proof);
            }
        }
        Err(anyhow!("no root node found"))
    }
    fn run_root_node_proof(&self, node: &MPTNode) -> Result<ProverOutput> {
        let header_node = RLPBlock(&self.data.block).rlp_bytes();
        let root_node = node.node_bytes.clone();
        let root_hash = keccak256(&root_node);
        let inner_proofs = node
            .rcvd_children_proofs
            .iter()
            .map(|p| p.proof.clone())
            .collect::<Vec<_>>();
        println!(
            "[+] GO root node {} with {} children",
            hex::encode(&root_hash),
            inner_proofs.len()
        );
        let prover = ProofType::RootMPTHeader(RootMPTHeader {
            header_node: header_node.to_vec(),
            root_node,
            inner_proofs,
        });
        let proof = prover.compute_proof()?;
        println!(
            "[+] OK Valid recursive proof for node hash {}",
            hex::encode(&root_hash)
        );
        Ok(ProverOutput {
            parent_hash: None,
            proof,
            hash: root_hash,
        })
    }
    fn run_recursive_proof(&self, node: &MPTNode) -> Result<ProverOutput> {
        let inner_proofs = node
            .rcvd_children_proofs
            .iter()
            .map(|p| p.proof.clone())
            .collect::<Vec<_>>();
        let node_bytes = node.node_bytes.clone();
        let node_hash = keccak256(&node_bytes);
        let parent_hash = node.parent_hash.clone();
        println!(
            "[+] GO recursive proof for node {} with {} children",
            hex::encode(&node_hash),
            node.total_nb_children
        );
        let prover = ProofType::IntermediateMPT(IntermediateMPT {
            intermediate_node: node_bytes,
            children_proofs: inner_proofs,
        });

        let proof = prover.compute_proof()?;

        println!(
            "[+] OK Valid recursive proof for node hash {}",
            hex::encode(&node_hash)
        );
        Ok(ProverOutput {
            parent_hash,
            proof,
            hash: node_hash,
        })
    }

    fn run_leaf_proof(&self, trie: &HashTrie, leaf_hash: Vec<u8>) -> Result<ProverOutput> {
        let mpt_node = trie.get(&leaf_hash).expect("leaf should be inside trie");
        let node_bytes = mpt_node.node_bytes.clone();
        let parent_hash = mpt_node.parent_hash.clone();
        // Safe because by construction we're in the leaf node
        let transaction = mpt_node.transaction.clone().unwrap();
        println!(
            "[+] GO leaf proof - tx hash {}",
            hex::encode(transaction.hash().as_bytes())
        );
        let prover = ProofType::TransactionMPT(TransactionMPT {
            leaf_node: node_bytes,
            quick_check: false,
            transaction,
        });
        let proof = prover.compute_proof()?;
        Ok(ProverOutput {
            parent_hash,
            proof,
            hash: leaf_hash,
        })
    }

    // Returns the hashmap filled with the trie info
    // and returns the initial list of nodes's hash, which happen to be leaves, to prove
    #[allow(clippy::type_complexity)]
    pub fn init_proofs_trie(&mut self) -> (HashMap<Vec<u8>, MPTNode>, Vec<Vec<u8>>) {
        // H(node) => { MPTNode() }
        let mut tree = HashMap::new();
        let mut leaves = Vec::new();
        for txr in self.data.txs.iter() {
            let (should_prove, reason) = self.policy.should_prove(txr.tx());
            if !should_prove {
                println!(
                    "[-] Policy skipping tx {} - {:?}\n\t-{}",
                    txr.tx().transaction_index.unwrap(),
                    txr.tx().hash(),
                    reason
                );
                continue;
            }
            let idx = txr.receipt().transaction_index;
            let key = idx.rlp_bytes().to_vec();
            let proof_bytes = self.data.tx_trie.get_proof(&key).unwrap();

            let mut child_hash = None;
            for (i, node_bytes) in proof_bytes.iter().rev().enumerate() {
                let idx_in_path = proof_bytes.len() - 1 - i;
                let hash = keccak256(node_bytes);

                if i == 0 {
                    leaves.push(hash.clone());
                }
                let node_bytes = node_bytes.to_vec();
                let parent_hash = if idx_in_path > 0 {
                    Some(keccak256(&proof_bytes[idx_in_path - 1]))
                } else {
                    None // root node !
                };
                // nikko TODO: This assumes there is no value in the branch node.
                // Will need to make sure this assumption is true in practice for tx at least
                let nb_children = extract_child_hashes(&node_bytes).len();
                // only record the child hash starting from the parent of the leaf
                let mut exp_child = if let Some(h) = child_hash {
                    vec![h]
                } else {
                    vec![]
                };
                tree.entry(hash.clone())
                    .and_modify(|n: &mut MPTNode| {
                        n.exp_children.append(&mut exp_child);
                    })
                    .or_insert(MPTNode {
                        node_bytes,
                        hash: hash.clone(),
                        rcvd_children_proofs: vec![],
                        exp_children: exp_child,
                        total_nb_children: nb_children,
                        parent_hash,
                        transaction: if i == 0 { Some(txr.tx().clone()) } else { None },
                    });
                child_hash = Some(hash);
            }
        }
        (tree, leaves)
    }
}

#[cfg(test)]
mod test {
    use std::time::Instant;

    use csv::Writer;
    use ethers::types::{BlockId, BlockNumber};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use serde::Serialize;

    use crate::{
        hash::hash_to_fields,
        transaction::{
            header::HeaderProofInputs,
            mpt::MAX_RLP_TX_LEN,
            prover::{TxBlockProver, TxFilter},
        },
        ByteProofTuple,
    };
    use anyhow::Result;

    #[tokio::test]
    pub async fn prove_all_tx_legacy() -> Result<()> {
        // block containing only 4 tx all of type legacy
        let block_number = 10593417;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let filter = TxFilter::BySize(MAX_RLP_TX_LEN);
        let mut prover = TxBlockProver::init(BlockNumber::from(block_number), filter).await?;
        let root_proof = prover.prove()?;
        //let root_hash = prover.data.tx_trie.root_hash()?.as_bytes().to_vec();
        let expected_pub_inputs = hash_to_fields::<F>(prover.data.block.hash.unwrap().as_bytes());
        let deserialized = ByteProofTuple::deserialize::<F, C, D>(&root_proof)?;
        assert_eq!(
            expected_pub_inputs,
            HeaderProofInputs::new(&deserialized.0.public_inputs).hash()
        );
        Ok(())
    }

    #[tokio::test]
    pub async fn prove_all_tx_1559() -> Result<()> {
        // block containing only 4 tx all of type 1559
        let block_number = 18761362;
        //let block_number = 18761234;
        //let block_number = 18761175;
        //let block_number = 18756870;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let filter = TxFilter::BySize(MAX_RLP_TX_LEN);
        let mut prover = TxBlockProver::init(BlockNumber::from(block_number), filter).await?;
        let root_proof = prover.prove()?;
        //let root_hash = prover.data.tx_trie.root_hash()?.as_bytes().to_vec();
        let expected_pub_inputs = hash_to_fields::<F>(prover.data.block.hash.unwrap().as_bytes());
        let deserialized = ByteProofTuple::deserialize::<F, C, D>(&root_proof)?;
        assert_eq!(
            expected_pub_inputs,
            HeaderProofInputs::new(&deserialized.0.public_inputs).hash()
        );
        Ok(())
    }

    #[derive(Serialize, Debug)]
    struct BenchData {
        pub block_nb: u64,
        // total nb of tx
        pub nb_tx: usize,
        pub nb_nodes: usize,
        // actually the ones being proven (after filtering)
        pub nb_proven: usize,
        pub lde_size: usize,
        pub time_proving: u64,
    }

    async fn test_one_block<T: Into<BlockId> + Send + Sync>(blockid: T) -> Result<BenchData> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let filter = TxFilter::BySize(MAX_RLP_TX_LEN);
        let mut prover = TxBlockProver::init(blockid, filter).await?;
        let start = Instant::now();
        let root_proof = prover.prove()?;
        let end = start.elapsed().as_secs();
        let expected_pub_inputs = hash_to_fields::<F>(prover.data.block.hash.unwrap().as_bytes());
        let deserialized = ByteProofTuple::deserialize::<F, C, D>(&root_proof)?;
        assert_eq!(
            expected_pub_inputs,
            HeaderProofInputs::new(&deserialized.0.public_inputs).hash()
        );
        let nb_tx = prover.data.txs.len();
        let filtered = prover
            .data
            .txs
            .iter()
            .filter(|txr| prover.policy.should_prove(txr.tx()).0)
            .count();
        let lde_size = deserialized.2.lde_size();
        Ok(BenchData {
            block_nb: prover.data.block.number.unwrap().as_u64(),
            nb_tx,
            nb_nodes: prover.nb_nodes,
            nb_proven: filtered,
            lde_size,
            time_proving: end,
        })
    }

    #[tokio::test]
    pub async fn test_many_blocks() -> Result<()> {
        let mut data = Vec::new();
        //let blocks = vec![18775351, 18768804, 18774792, 18774297];
        let blocks = vec![18775351];
        for b in blocks {
            let blockid = BlockNumber::from(b);
            let bench_data = test_one_block(blockid).await?;
            data.push(bench_data);
        }
        let mut wtr = Writer::from_path("bench_tx.csv")?;
        wtr.serialize(data)?;
        Ok(())
    }
}
