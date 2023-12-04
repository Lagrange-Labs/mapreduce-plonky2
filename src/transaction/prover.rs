use crate::utils::find_index_subvector;
use crate::{
    eth::{compute_key_length, extract_child_hashes, BlockData},
    transaction::mpt::{legacy_tx_leaf_node_proof, recursive_node_proof, ExtractionMethod},
    utils::keccak256,
    ProofTuple,
};
use anyhow::anyhow;
use anyhow::Result;
use eth_trie::{Node, Trie};
use ethers::{types::BlockId, utils::hex};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::{CircuitConfig, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use rlp::Encodable;
use std::{collections::HashMap, marker::PhantomData};

struct TxBlockProver<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    data: BlockData,
    config: CircuitConfig,
    _pf: PhantomData<F>,
    _pc: PhantomData<C>,
}

struct RecursiveProofData<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
{
    // The nodes left to traverse in the path to go to the root
    mpt_proof: Vec<Node>,
    mpt_bytes: Vec<Vec<u8>>,
    key: Vec<u8>,
    key_ptr: usize,
    // the current proof proving the whole subtree of the node with the
    // given "hash"
    proof: ProofWithPublicInputs<F, C, D>,
    hash: Vec<u8>,
}

struct MPTNode<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    node_bytes: Vec<u8>, // RLP byte representation of the node
    hash: Vec<u8>,       // its hash
    key_ptr: usize,      // ptr to any key in the subtree - act like a "height" in some sort
    key: Vec<u8>, // any key that leads to this node - key[0..key_ptr] is the same for the whole subtree of this node
    // child i : (key, proof) - key needed locate where is the hash of the child in the node
    children_proofs: Vec<ProverOutput<F, C, D>>, // will be filled in
    children_hashes: Vec<Vec<u8>>, // potential hashes of the children if any (zero if leaf for example)
    parent_hash: Option<Vec<u8>>,  // indicator to go up one level when this node has been "proven"
}

struct ProverOutput<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    parent_hash: Option<Vec<u8>>,
    // hash of this node
    hash: Vec<u8>,
    // plonky2 proof for this node
    proof: ProofTuple<F, C, D>,
}

type HashTrie<F, C, const D: usize> = HashMap<Vec<u8>, MPTNode<F, C, D>>;
impl<F, C, const D: usize> TxBlockProver<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub async fn init<T: Into<BlockId> + Send + Sync>(id: T) -> Result<Self> {
        let data = BlockData::fetch(id).await?;
        Ok(Self {
            data,
            config: CircuitConfig::standard_recursion_config(),
            _pf: PhantomData,
            _pc: PhantomData,
        })
    }

    pub fn prove(&mut self) -> Result<ProofTuple<F, C, D>> {
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

    fn run_recursive_proof(&self, node: &MPTNode<F, C, D>) -> Result<ProverOutput<F, C, D>> {
        let inner_proofs = node
            .children_proofs
            .iter()
            .map(|p| p.proof.clone())
            .collect::<Vec<_>>();
        let node_bytes = node.node_bytes.clone();
        let node_hash = keccak256(&node_bytes);
        let parent_hash = node.parent_hash.clone();
        let config = self.config.clone();
        let node_key = node.key.clone();
        // where to find the hashes for each children of the node
        let children_hash_offsets = node
            .children_proofs
            .iter()
            .map(|p| p.hash.clone())
            .map(|hash| find_index_subvector(&node_bytes, &hash).expect("invalid hash"))
            .collect::<Vec<_>>();
        println!(
            "[+] GO recursive proof for node {} with {} children",
            hex::encode(&node_hash),
            node.children_hashes.len()
        );
        // F, C, C, D because we use same recursive config at each step
        let plonk_proof = recursive_node_proof::<F, C, C, D>(
            &config,
            node_bytes,
            inner_proofs.as_slice(),
            &children_hash_offsets,
        )?;
        Self::verify_proof_tuple(&plonk_proof)?;
        println!(
            "[+] OK Valid recursive proof for node hash {}",
            hex::encode(&node_hash)
        );
        Ok(ProverOutput {
            parent_hash,
            proof: plonk_proof,
            hash: node_hash,
        })
    }

    fn run_leaf_proof(
        &self,
        trie: &HashTrie<F, C, D>,
        leaf_hash: Vec<u8>,
    ) -> Result<ProverOutput<F, C, D>> {
        let mpt_node = trie.get(&leaf_hash).expect("leaf should be inside trie");
        let key = mpt_node.key.clone();
        let node_bytes = mpt_node.node_bytes.clone();
        let parent_hash = mpt_node.parent_hash.clone();
        let config = self.config.clone();
        println!(
            "[+] GO leaf proof idx {} - hash {}",
            hex::encode(&key),
            hex::encode(&leaf_hash)
        );
        let plonk_proof =
            legacy_tx_leaf_node_proof(&config, node_bytes, ExtractionMethod::RLPBased)?;
        Self::verify_proof_tuple(&plonk_proof)?;

        println!(
            "[+] OK Valid proof for leaf idx {} - hash {}",
            hex::encode(&key),
            hex::encode(&leaf_hash)
        );
        Ok(ProverOutput {
            parent_hash,
            proof: plonk_proof,
            hash: leaf_hash,
        })
    }

    // Returns the hashmap filled with the trie info
    // and returns the initial list of nodes's hash, which happen to be leaves, to prove
    #[allow(clippy::type_complexity)]
    fn init_proofs_trie(&mut self) -> (HashMap<Vec<u8>, MPTNode<F, C, D>>, Vec<Vec<u8>>) {
        // H(node) => { MPTNode() }
        let mut tree = HashMap::new();
        let mut leaves = Vec::new();
        for txr in self.data.txs.iter() {
            let idx = txr.receipt().transaction_index;
            let key = idx.rlp_bytes().to_vec();
            // nikko TODO: only kept for computing key length but can be done only with
            // the raw bytes - should change.
            let proof_nodes = self.data.tx_trie.get_proof_nodes(&key).unwrap();
            let proof_bytes = self.data.tx_trie.get_proof(&key).unwrap();
            for (i, node_bytes) in proof_bytes.iter().rev().enumerate() {
                let idx_in_path = proof_nodes.len() - 1 - i;
                let hash = keccak256(node_bytes);
                let key_ptr = compute_key_length(&proof_nodes[..idx_in_path]);
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
                    key_ptr,
                    children_proofs,
                    children_hashes,
                    parent_hash,
                    // nikko: note this will be different for different for diff. leaves under the same
                    // subtree. However, currently the code expects a key when proving recursively
                    // so we only need to put one, regardless of all the others in the same subtree.
                    // in this example, only the key of the last tx in the subtree will be stored/used.
                    // TODO: remove the key from the recursive API and only pass the new nibble
                    key: key.clone(),
                };
                #[cfg(test)]
                {
                    // if entry is already in the tree, we don't need to add it, but we
                    // check it's correct still - i.e. all ptr in the subtree starting
                    // at this node should be the same since all leafs in this subtree
                    // have the same key until at least this node.
                    if tree.contains_key(&hash) {
                        let present_trie_node: &MPTNode<F, C, D> = tree.get(&hash).unwrap();
                        assert!(present_trie_node.key_ptr == trie_node.key_ptr);
                    }
                }
                tree.entry(hash).or_insert(trie_node);
            }
        }
        (tree, leaves)
    }

    fn verify_proof_tuple(proof: &ProofTuple<F, C, D>) -> Result<()> {
        let vcd = VerifierCircuitData {
            verifier_only: proof.1.clone(),
            common: proof.2.clone(),
        };
        vcd.verify(proof.0.clone())
    }
}

mod test {
    use eth_trie::Trie;
    use ethers::types::BlockNumber;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use crate::{transaction::prover::TxBlockProver, utils::hash_to_fields};
    use anyhow::Result;

    #[tokio::test]
    pub async fn prove_all_tx() -> Result<()> {
        let block_number = 10593417;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut prover = TxBlockProver::<F, C, D>::init(BlockNumber::from(block_number)).await?;
        let root_proof = prover.prove()?;
        let root_hash = prover.data.tx_trie.root_hash()?.as_bytes().to_vec();
        let expected_pub_inputs = hash_to_fields::<F>(&root_hash);
        assert_eq!(expected_pub_inputs, root_proof.0.public_inputs[0..8]);
        Ok(())
    }
}
