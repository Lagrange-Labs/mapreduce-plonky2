//! Storage trie for proving tests

use ethers::{
    prelude::Address,
    utils::rlp::{Prototype, Rlp},
};
use mp2_common::{
    eth::StorageSlot,
    utils::{keccak256, Endianness, Packer},
};
use mp2_v1::{
    api::{generate_proof, CircuitInput, ProofWithVK, PublicParameters},
    values_extraction,
};
use std::collections::HashMap;

/// RLP item size for the extension node
const EXTENSION_RLP_SIZE: usize = 2;

/// RLP item size for the branch node
const BRANCH_RLP_SIZE: usize = 17;

/// Maximum child number of a branch node
const MAX_BRANCH_CHILDREN: usize = 16;

/// Raw node of the storage proof
type RawNode = Vec<u8>;

/// Serialized plonky2 proof
type SerializedProof = Vec<u8>;

/// The context during proving
#[derive(Clone, Copy)]
struct ProvingContext<'a> {
    contract_address: &'a Address,
    params: &'a PublicParameters,
    slots: &'a HashMap<RawNode, StorageSlot>,
}

impl<'a> ProvingContext<'a> {
    /// Initialize the proving context.
    fn new(
        contract_address: &'a Address,
        params: &'a PublicParameters,
        slots: &'a HashMap<RawNode, StorageSlot>,
    ) -> Self {
        Self {
            contract_address,
            params,
            slots,
        }
    }

    /// Check if it's the simple slot type during proving.
    fn is_simple_slot(&self) -> bool {
        // Has 1 slot to prove at least.
        let slot = self.slots.iter().next().unwrap().1;

        slot.is_simple_slot()
    }
}

/// Trie node type
#[derive(Debug)]
enum TrieNodeType {
    Branch,
    Extension,
    Leaf,
}

/// Test trie node
#[derive(Debug)]
struct TrieNode {
    /// Raw node of the storage proof
    raw: RawNode,
    /// Child nodes
    children: Vec<TrieNode>,
}

impl TrieNode {
    /// Initialize a node.
    fn new(raw: RawNode) -> Self {
        Self {
            raw,
            children: vec![],
        }
    }

    /// Get the node type.
    fn node_type(&self) -> TrieNodeType {
        if self.children.is_empty() {
            return TrieNodeType::Leaf;
        }

        let rlp = Rlp::new(&self.raw);
        match rlp.prototype().unwrap() {
            Prototype::List(EXTENSION_RLP_SIZE) => TrieNodeType::Extension,
            Prototype::List(BRANCH_RLP_SIZE) => TrieNodeType::Branch,
            _ => panic!("Invalid RLP size for the storage proof"),
        }
    }

    /// Calculate the hash of this node.
    fn hash(&self) -> Vec<u32> {
        keccak256(&self.raw).pack(Endianness::Little)
    }

    /// Find or add the child node path recursively. The path is arranged in the reverse order,
    /// from leaf to the root, the last node is popped from the path in each rescusive round.
    /// Reuse the all nodes same as the specified node path, only add the non-existing ones.
    fn find_or_add_child(&mut self, mut nodes: Vec<RawNode>) {
        if nodes.is_empty() {
            return;
        }

        // Pop the new node to find in the current children.
        let new_node = nodes.pop().unwrap();

        // Iterate to find the new child node in the children of the current node.
        // Reuse the child if found, otherwise add a new one. Then add the next
        // node of the path recursively.
        match self.children.iter_mut().find(|child| child.raw == new_node) {
            Some(child) => child.find_or_add_child(nodes),
            None => {
                let mut child = TrieNode::new(new_node);
                child.find_or_add_child(nodes);

                self.children.push(child);
            }
        }
    }

    /// Prove a trie node recursively.
    fn prove(&self, ctx: ProvingContext) -> SerializedProof {
        match self.node_type() {
            TrieNodeType::Branch => self.prove_branch(ctx),
            TrieNodeType::Extension => self.prove_extension(ctx),
            TrieNodeType::Leaf => self.prove_leaf(ctx),
        }
    }

    /// Prove a branch node.
    fn prove_branch(&self, ctx: ProvingContext) -> SerializedProof {
        // Has one child at least and 16 at maximum.
        assert!(self.children.len() > 0);
        assert!(self.children.len() <= MAX_BRANCH_CHILDREN);

        let node = self.raw.clone();

        // Generate the proofs of the child nodes.
        let child_proofs: Vec<_> = self.children.iter().map(|node| node.prove(ctx)).collect();

        // Build the branch circuit input.
        let input = if ctx.is_simple_slot() {
            values_extraction::CircuitInput::new_single_variable_branch(node, child_proofs)
        } else {
            values_extraction::CircuitInput::new_mapping_variable_branch(node, child_proofs)
        };
        let input = CircuitInput::ValuesExtraction(input);

        // Generate the proof.
        generate_proof(ctx.params, input).unwrap()
    }

    /// Prove an extension node.
    fn prove_extension(&self, ctx: ProvingContext) -> SerializedProof {
        // Has one child for the extension node.
        assert_eq!(self.children.len(), 1);

        let node = self.raw.clone();

        // Generate the proof of child node.
        let child_proof = self.children[0].prove(ctx);

        // Build the extension circuit input.
        let input = values_extraction::CircuitInput::new_extension(node, child_proof);
        let input = CircuitInput::ValuesExtraction(input);

        // Generate the proof.
        generate_proof(ctx.params, input).unwrap()
    }

    /// Prove a leaf node.
    fn prove_leaf(&self, ctx: ProvingContext) -> SerializedProof {
        // Has no child for the leaf node.
        assert_eq!(self.children.len(), 0);

        let node = self.raw.clone();

        // Find the storage slot for this leaf node.
        let slot = ctx.slots.get(&node).unwrap();

        // Build the leaf circuit input.
        let input = match slot {
            StorageSlot::Simple(slot) => values_extraction::CircuitInput::new_single_variable_leaf(
                node,
                *slot as u8,
                ctx.contract_address,
            ),
            StorageSlot::Mapping(mapping_key, slot) => {
                values_extraction::CircuitInput::new_mapping_variable_leaf(
                    node,
                    *slot as u8,
                    mapping_key.clone(),
                    ctx.contract_address,
                )
            }
        };
        let input = CircuitInput::ValuesExtraction(input);

        // Generate the proof.
        generate_proof(ctx.params, input).unwrap()
    }
}

/// Test storage trie
#[derive(Debug)]
pub(crate) struct TestStorageTrie {
    /// Root of this trie
    root: Option<TrieNode>,
    /// Storage slot map indexed by the raw node
    slots: HashMap<RawNode, StorageSlot>,
}

impl TestStorageTrie {
    /// Initialize a test storage trie.
    pub(crate) fn new() -> Self {
        Self {
            root: None,
            slots: HashMap::new(),
        }
    }

    /// Get the root hash of this trie.
    pub(crate) fn root_hash(&self) -> Vec<u32> {
        self.root.as_ref().unwrap().hash()
    }

    /// Add a storage slot with a proof path of raw nodes which sequence is from leaf to root.
    /// If the current trie already has a root (initialized by a slot before), the new slot must satisfy:
    /// - It's the same type of storage slot as previous ones (simple or mapping).
    /// - The node path has the same root of the current trie.
    pub(crate) fn add_slot(&mut self, slot: StorageSlot, mut nodes: Vec<RawNode>) {
        self.check_new_slot(&slot, &nodes);

        // Save the slot to a map and index by the leaf node.
        let insert_result = self.slots.insert(nodes[0].clone(), slot);
        assert!(insert_result.is_none());

        // Set the root if this is the first slot.
        let root_node = nodes.pop().unwrap();
        if self.root.is_none() {
            self.root = Some(TrieNode::new(root_node));
        }

        // Find or add the child nodes.
        self.root.as_mut().unwrap().find_or_add_child(nodes);
    }

    /// Generate the proof for the trie.
    pub(crate) fn prove_all(
        &self,
        contract_address: &Address,
        params: &PublicParameters,
    ) -> ProofWithVK {
        let ctx = ProvingContext::new(contract_address, params, &self.slots);

        // Must prove with 1 slot at least.
        let proof = self.root.as_ref().unwrap().prove(ctx);

        ProofWithVK::deserialize(&proof).unwrap()
    }

    /// Check the new slot if it's the same type slot and the node path has the same root.
    fn check_new_slot(&self, new_slot: &StorageSlot, new_nodes: &[RawNode]) {
        if let Some((_, slot)) = self.slots.iter().next() {
            // The new slot must be the same type.
            match (slot, new_slot) {
                (&StorageSlot::Simple(_), &StorageSlot::Simple(_)) => (),
                (&StorageSlot::Mapping(_, slot), &StorageSlot::Mapping(_, new_slot)) => {
                    // Must have the same slot number for the mapping type.
                    assert_eq!(slot, new_slot);
                }
                _ => panic!("Add the different type of storage slots: {slot:?}, {new_slot:?}"),
            }
        }

        // The storage proofs must include 1 branch and 1 leaf as least.
        assert!(new_nodes.len() > 1);

        if let Some(root) = &self.root {
            // The new path must have the same root of the current trie.
            assert_eq!(&root.raw, new_nodes.last().unwrap());
        }
    }
}
