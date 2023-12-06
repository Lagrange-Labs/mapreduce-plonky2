use crate::transaction::proof::{IntermediateMPT, ProofType, TransactionMPT};
use crate::{
    eth::{extract_child_hashes, BlockData},
    utils::keccak256,
};
use anyhow::anyhow;
use anyhow::Result;
use eth_trie::Trie;
use ethers::{types::BlockId, utils::hex};
use rlp::Encodable;
use std::collections::HashMap;

struct TxBlockProver {
    data: BlockData,
}

struct MPTNode {
    node_bytes: Vec<u8>, // RLP byte representation of the node
    hash: Vec<u8>,       // its hash
    // child i : (key, proof) - key needed locate where is the hash of the child in the node
    children_proofs: Vec<ProverOutput>, // will be filled in
    // expected hashes of the children if any (zero if leaf for example)
    // TODO: we want to support the case where we don't put all hashes
    children_hashes: Vec<Vec<u8>>,
    parent_hash: Option<Vec<u8>>, // indicator to go up one level when this node has been "proven"
}

struct ProverOutput {
    parent_hash: Option<Vec<u8>>,
    // hash of this node
    hash: Vec<u8>,
    // plonky2 proof for this node
    proof: Vec<u8>,
}

/// Hash mapping the hash of a node in the trie to the data
type HashTrie = HashMap<Vec<u8>, MPTNode>;
impl TxBlockProver {
    pub async fn init<T: Into<BlockId> + Send + Sync>(id: T) -> Result<Self> {
        let data = BlockData::fetch(id).await?;
        Ok(Self { data })
    }

    pub fn prove(&mut self) -> Result<Vec<u8>> {
        let (mut trie, leaves_hashes) = self.init_proofs_trie();
        println!("[+] Built internal trie with {} nodes in total", trie.len());
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
            proof_node.children_proofs.push(output);
            // look if we have all the individual children proofs to start proving this node now
            let exp_children_hashes = &proof_node.children_hashes;
            let rcvd_children = proof_node.children_proofs.len();
            let children_proofs_done = if exp_children_hashes.len() != rcvd_children {
                println!(
                    "[+] Node proof {} : only {}/{} children proofs",
                    &node_hash,
                    rcvd_children,
                    exp_children_hashes.len()
                );
                false // not the same number of proofs than children in branch node
            } else {
                // make sure we have all the same hashes
                let all = exp_children_hashes
                    .iter()
                    .all(|h| proof_node.children_proofs.iter().any(|p| *p.hash == *h));
                println!(
                    "[+] Node proof {} : ALL {}/{} children proofs!",
                    &node_hash,
                    rcvd_children,
                    exp_children_hashes.len()
                );
                assert!(all, "same number of proofs but different hashes !?");
                true
            };
            if children_proofs_done {
                let parent_proof = self.run_recursive_proof(proof_node)?;
                current_proofs.push(parent_proof);
            }
        }
        Err(anyhow!("no root node found"))
    }

    fn run_recursive_proof(&self, node: &MPTNode) -> Result<ProverOutput> {
        let inner_proofs = node
            .children_proofs
            .iter()
            .map(|p| p.proof.clone())
            .collect::<Vec<_>>();
        let node_bytes = node.node_bytes.clone();
        let node_hash = keccak256(&node_bytes);
        let parent_hash = node.parent_hash.clone();
        println!(
            "[+] GO recursive proof for node {} with {} children",
            hex::encode(&node_hash),
            node.children_hashes.len()
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
        println!("[+] GO leaf proof - hash {}", hex::encode(&leaf_hash));
        let prover = ProofType::TransactionMPT(TransactionMPT {
            leaf_node: node_bytes,
            quick_check: true,
        });
        let proof = prover.compute_proof()?;

        println!(
            "[+] OK Valid proof for leaf - hash {}",
            hex::encode(&leaf_hash)
        );
        Ok(ProverOutput {
            parent_hash,
            proof,
            hash: leaf_hash,
        })
    }

    // Returns the hashmap filled with the trie info
    // and returns the initial list of nodes's hash, which happen to be leaves, to prove
    #[allow(clippy::type_complexity)]
    fn init_proofs_trie(&mut self) -> (HashMap<Vec<u8>, MPTNode>, Vec<Vec<u8>>) {
        // H(node) => { MPTNode() }
        let mut tree = HashMap::new();
        let mut leaves = Vec::new();
        for txr in self.data.txs.iter() {
            let idx = txr.receipt().transaction_index;
            let key = idx.rlp_bytes().to_vec();
            let proof_bytes = self.data.tx_trie.get_proof(&key).unwrap();
            for (i, node_bytes) in proof_bytes.iter().rev().enumerate() {
                let idx_in_path = proof_bytes.len() - 1 - i;
                let hash = keccak256(node_bytes);
                if i == 0 {
                    leaves.push(hash.clone());
                }
                let node_bytes = node_bytes.to_vec();
                let children_proofs = vec![];
                let parent_hash = if idx_in_path > 0 {
                    Some(keccak256(&proof_bytes[idx_in_path - 1]))
                } else {
                    None // root node !
                };
                // nikko TODO: This assumes there is no value in the branch node.
                // Will need to make sure this assumption is true in practice for tx at least
                let children_hashes = extract_child_hashes(&node_bytes);
                let trie_node = MPTNode {
                    node_bytes,
                    hash: hash.clone(),
                    children_proofs,
                    children_hashes,
                    parent_hash,
                };
                tree.entry(hash).or_insert(trie_node);
            }
        }
        (tree, leaves)
    }
}

mod test {
    use eth_trie::Trie;
    use ethers::types::BlockNumber;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use crate::{
        hash::hash_to_fields,
        transaction::{mpt::NodeProofInputs, prover::TxBlockProver},
        ByteProofTuple,
    };
    use anyhow::Result;

    #[tokio::test]
    pub async fn prove_all_tx() -> Result<()> {
        let block_number = 10593417;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut prover = TxBlockProver::init(BlockNumber::from(block_number)).await?;
        let root_proof = prover.prove()?;
        let root_hash = prover.data.tx_trie.root_hash()?.as_bytes().to_vec();
        let expected_pub_inputs = hash_to_fields::<F>(&root_hash);
        let deserialized = ByteProofTuple::deserialize::<F, C, D>(&root_proof)?;
        assert_eq!(
            expected_pub_inputs,
            NodeProofInputs::new(&deserialized.0.public_inputs)?.hash()
        );
        Ok(())
    }
}
