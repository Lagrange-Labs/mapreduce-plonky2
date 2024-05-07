//! Test utilities for Values Extraction (C.1)

use eth_trie::{BranchNode, EthTrie, ExtensionNode, HashNode, LeafNode, MemoryDB, Node, Trie};
use ethers::prelude::{Address, H256};
use mp2_common::eth::StorageSlot;
use mp2_test::utils::random_vector;
use mp2_v1::{
    api::{generate_proof, CircuitInput, ProofWithVK, PublicParameters},
    values_extraction,
};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

type PartialKey = Vec<u8>;
type SerializedProof = Vec<u8>;

const VALUE_LEN: usize = 32;

/// Test storage trie
#[derive(Debug)]
pub struct TestStorageTrie {
    /// Contract address
    contract_address: Address,
    /// Root hash of the trie
    root_hash: H256,
    /// Storage trie
    trie: EthTrie<MemoryDB>,
    /// Slot map indexed by the partial key
    slot_map: HashMap<PartialKey, StorageSlot>,
}

impl TestStorageTrie {
    /// Generate the test storage trie.
    pub fn new(contract_address: Address, slots: Vec<StorageSlot>) -> Self {
        // Would not prove for an empty trie.
        assert!(slots.len() > 0);

        // Initialize the trie.
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());

        // Add the slots to the trie.
        let is_simple_slot = slots[0].is_simple_slot();
        slots.iter().for_each(|slot| {
            // Ensure the same type of storage slot.
            assert_eq!(slot.is_simple_slot(), is_simple_slot);

            // Generate the MPT key and insert into the trie.
            let k = slot.mpt_key_vec();
            let v = rlp::encode(&random_vector(VALUE_LEN));
            trie.insert(&k, &v).unwrap();
        });

        // Recalculates the root.
        let root_hash = trie.root_hash().unwrap();

        // Save the slots to a map and index by the partial key.
        let mut slot_map = HashMap::new();
        slots.into_iter().for_each(|slot| {
            // Traverse to get the leaf node.
            let k = slot.mpt_key_vec();
            let node = trie.get_proof_nodes(&k).unwrap().last().unwrap().clone();

            // Get the encoded partial key.
            let partial_key = match node {
                Node::Leaf(leaf) => {
                    let partial_key = leaf.key.encode_raw();

                    // Ensure it's a leaf.
                    assert!(partial_key.1);

                    partial_key.0
                }
                _ => panic!("Must be a leaf node"),
            };

            // Ensure to save the slot to the map.
            let result = slot_map.insert(partial_key, slot);
            assert!(result.is_none());
        });

        Self {
            contract_address,
            root_hash,
            trie,
            slot_map,
        }
    }

    /// Generate the proof for the trie.
    pub fn prove_all(&mut self, params: &PublicParameters) -> ProofWithVK {
        // Reuse HashNode to get from the memory DB.
        let proof = self
            .prove_node(params, Node::from_hash(self.root_hash))
            .unwrap();

        ProofWithVK::deserialize(&proof).unwrap()
    }

    /// Prove a trie node recursively.
    fn prove_node(&mut self, params: &PublicParameters, node: Node) -> Option<SerializedProof> {
        Some(match node {
            // Only the children of branch could be empty.
            Node::Empty => return None,
            Node::Leaf(leaf) => self.prove_leaf(params, leaf),
            Node::Extension(ext) => self.prove_extentsion(params, ext),
            Node::Branch(branch) => self.prove_branch(params, branch),
            Node::Hash(hash) => self.prove_hash(params, hash),
        })
    }

    /// Prove a leaf node.
    fn prove_leaf(&mut self, params: &PublicParameters, leaf: Arc<LeafNode>) -> SerializedProof {
        // Encode to get the partial key, and ensure it must be a leaf.
        let partial_key = leaf.key.encode_raw();
        assert!(partial_key.1);
        let partial_key = partial_key.0;

        // Find the slot by the partial key.
        let slot = self.slot_map.get(&partial_key).unwrap();

        // Encode the node to bytes.
        let node = self.trie.encode_raw(&Node::Leaf(leaf));

        // Build the leaf circuit input.
        let input = match slot {
            StorageSlot::Simple(slot) => values_extraction::CircuitInput::new_single_variable_leaf(
                node,
                *slot as u8,
                &self.contract_address,
            ),
            StorageSlot::Mapping(mapping_key, slot) => {
                values_extraction::CircuitInput::new_mapping_variable_leaf(
                    node,
                    *slot as u8,
                    mapping_key.clone(),
                    &self.contract_address,
                )
            }
        };
        let input = CircuitInput::ValuesExtraction(input);

        // Generate the proof.
        generate_proof(params, input).unwrap()
    }

    /// Prove an extension node.
    fn prove_extentsion(
        &mut self,
        params: &PublicParameters,
        ext: Arc<RwLock<ExtensionNode>>,
    ) -> SerializedProof {
        // Generate the proof of child node.
        let child_node = ext.read().unwrap().node.clone();
        let child_proof = self.prove_node(params, child_node).unwrap();

        // Encode the node to the bytes.
        let node = self.trie.encode_raw(&Node::Extension(ext));

        // Build the extension circuit input.
        let input = values_extraction::CircuitInput::new_extension(node, child_proof);
        let input = CircuitInput::ValuesExtraction(input);

        // Generate the proof.
        generate_proof(params, input).unwrap()
    }

    /// Prove a branch node.
    fn prove_branch(
        &mut self,
        params: &PublicParameters,
        branch: Arc<RwLock<BranchNode>>,
    ) -> SerializedProof {
        // Generate the proofs of child nodes.
        let child_nodes = branch.read().unwrap().children.clone();
        // TODO: may prove in parrallel.
        let child_proofs: Vec<_> = child_nodes
            .into_iter()
            .filter_map(|node| self.prove_node(params, node))
            .collect();

        // Has one child at least.
        assert!(child_proofs.len() > 0);

        // Encode the node to the bytes.
        let node = self.trie.encode_raw(&Node::Branch(branch));

        // Build the branch circuit input.
        let input = if self.is_simple_slot() {
            values_extraction::CircuitInput::new_single_variable_branch(node, child_proofs)
        } else {
            values_extraction::CircuitInput::new_mapping_variable_branch(node, child_proofs)
        };
        let input = CircuitInput::ValuesExtraction(input);

        // Generate the proof.
        generate_proof(params, input).unwrap()
    }

    /// Recover and prove an intermidiate hash node.
    fn prove_hash(&mut self, params: &PublicParameters, hash: Arc<HashNode>) -> SerializedProof {
        // The node should be recovered by hash and not empty.
        let node = self.trie.recover_from_db(hash.hash).unwrap().unwrap();

        self.prove_node(params, node).unwrap()
    }

    /// Get the type of the storage slots in this trie.
    fn is_simple_slot(&self) -> bool {
        self.slot_map.iter().next().unwrap().1.is_simple_slot()
    }
}
