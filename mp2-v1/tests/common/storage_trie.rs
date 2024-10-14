//! Storage trie for proving tests

use super::{benchmarker::Benchmarker, StorageSlotInfo, TestContext};
use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, U256},
};
use log::debug;
use mp2_common::{
    eth::{ProofQuery, StorageSlot, StorageSlotNode},
    mpt_sequential::{MPT_BRANCH_RLP_SIZE, MPT_EXTENSION_RLP_SIZE},
    proof::ProofWithVK,
    utils::{keccak256, Endianness, Packer},
};
use mp2_v1::{
    api::{generate_proof, CircuitInput, PublicParameters},
    length_extraction, values_extraction,
};
use rlp::{Prototype, Rlp};
use std::collections::HashMap;

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
    chain_id: u64,
    params: &'a PublicParameters,
    slots: &'a HashMap<RawNode, StorageSlotInfo>,
    b: &'a Benchmarker,
    variable_slot: Option<u8>,
}

impl<'a> ProvingContext<'a> {
    /// Initialize the proving context.
    fn new(
        contract_address: &'a Address,
        chain_id: u64,
        params: &'a PublicParameters,
        slots: &'a HashMap<RawNode, StorageSlotInfo>,
        variable_slot: Option<u8>,
        bench: &'a Benchmarker,
    ) -> Self {
        Self {
            contract_address,
            params,
            slots,
            variable_slot,
            b: bench,
            chain_id,
        }
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
            Prototype::List(MPT_EXTENSION_RLP_SIZE) => TrieNodeType::Extension,
            Prototype::List(MPT_BRANCH_RLP_SIZE) => TrieNodeType::Branch,
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
    fn prove_value(&self, ctx: ProvingContext) -> SerializedProof {
        match self.node_type() {
            TrieNodeType::Branch => self.prove_value_branch(ctx),
            TrieNodeType::Extension => self.prove_value_extension(ctx),
            TrieNodeType::Leaf => self.prove_value_leaf(ctx),
        }
    }

    /// Prove a branch node.
    fn prove_value_branch(&self, ctx: ProvingContext) -> SerializedProof {
        // Has one child at least and 16 at maximum.
        assert!(self.children.len() > 0);
        assert!(self.children.len() <= MAX_BRANCH_CHILDREN);

        let node = self.raw.clone();

        // Generate the proofs of the child nodes.
        let child_proofs: Vec<_> = self
            .children
            .iter()
            .map(|node| node.prove_value(ctx))
            .collect();

        // Build the branch circuit input.
        let input = CircuitInput::ValuesExtraction(values_extraction::CircuitInput::new_branch(
            node,
            child_proofs,
        ));

        // Generate the proof.
        ctx.b
            .bench("indexing::extraction::mpt::branch", || {
                generate_proof(ctx.params, input)
            })
            .unwrap()
    }

    /// Prove an extension node.
    fn prove_value_extension(&self, ctx: ProvingContext) -> SerializedProof {
        // Has one child for the extension node.
        assert_eq!(self.children.len(), 1);

        let node = self.raw.clone();

        // Generate the proof of child node.
        let child_proof = self.children[0].prove_value(ctx);

        // Build the extension circuit input.
        let input = values_extraction::CircuitInput::new_extension(node, child_proof);
        let input = CircuitInput::ValuesExtraction(input);

        // Generate the proof.
        ctx.b
            .bench("indexing::extraction::mpt::extension", || {
                generate_proof(ctx.params, input)
            })
            .unwrap()
    }

    /// Prove a leaf node.
    fn prove_value_leaf(&self, ctx: ProvingContext) -> SerializedProof {
        // Has no child for the leaf node.
        assert_eq!(self.children.len(), 0);

        let node = self.raw.clone();

        // Find the storage slot information for this leaf node.
        let slot_info = ctx.slots.get(&node).unwrap();
        let metadata = slot_info.metadata();

        // Build the leaf circuit input.
        let (name, input) = match slot_info.slot() {
            // Simple variable slot
            StorageSlot::Simple(slot) => (
                "indexing::extraction::mpt::leaf::single_var",
                values_extraction::CircuitInput::new_single_variable_leaf(
                    node.clone(),
                    *slot as u8,
                    metadata.evm_word(),
                    metadata.num_actual_columns(),
                    metadata.num_extracted_columns(),
                    metadata.table_info().to_vec(),
                ),
            ),
            // Mapping variable
            StorageSlot::Mapping(mapping_key, slot) => (
                "indexing::extraction::mpt::leaf::mapping_var",
                values_extraction::CircuitInput::new_mapping_variable_leaf(
                    node.clone(),
                    *slot as u8,
                    mapping_key.clone(),
                    slot_info.outer_key_id(),
                    metadata.evm_word(),
                    metadata.num_actual_columns(),
                    metadata.num_extracted_columns(),
                    metadata.table_info().to_vec(),
                ),
            ),
            StorageSlot::Node(StorageSlotNode::Struct(parent, evm_word)) => match &**parent {
                // Simple Struct
                StorageSlot::Simple(slot) => (
                    "indexing::extraction::mpt::leaf::single_struct",
                    values_extraction::CircuitInput::new_single_variable_leaf(
                        node.clone(),
                        *slot as u8,
                        *evm_word,
                        metadata.num_actual_columns(),
                        metadata.num_extracted_columns(),
                        metadata.table_info().to_vec(),
                    ),
                ),
                // Mapping Struct
                StorageSlot::Mapping(mapping_key, slot) => (
                    "indexing::extraction::mpt::leaf::mapping_struct",
                    values_extraction::CircuitInput::new_mapping_variable_leaf(
                        node.clone(),
                        *slot as u8,
                        mapping_key.clone(),
                        slot_info.outer_key_id(),
                        metadata.evm_word(),
                        metadata.num_actual_columns(),
                        metadata.num_extracted_columns(),
                        metadata.table_info().to_vec(),
                    ),
                ),
                // Mapping of mappings Struct
                StorageSlot::Node(StorageSlotNode::Mapping(grand, inner_mapping_key)) => {
                    match &**grand {
                        StorageSlot::Mapping(outer_mapping_key, slot) => (
                            "indexing::extraction::mpt::leaf::mapping_of_mappings",
                            values_extraction::CircuitInput::new_mapping_of_mappings_leaf(
                                node.clone(),
                                *slot as u8,
                                outer_mapping_key.clone(),
                                inner_mapping_key.clone(),
                                slot_info.outer_key_id(),
                                slot_info.inner_key_id(),
                                metadata.evm_word(),
                                metadata.num_actual_columns(),
                                metadata.num_extracted_columns(),
                                metadata.table_info().to_vec(),
                            ),
                        ),
                        _ => unreachable!(),
                    }
                }
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };
        let input = CircuitInput::ValuesExtraction(input);

        // Generate the proof.
        let proof = ctx
            .b
            .bench(name, || generate_proof(ctx.params, input))
            .unwrap();
        let pproof = ProofWithVK::deserialize(&proof).unwrap();
        let pi = mp2_v1::values_extraction::PublicInputs::new(&pproof.proof().public_inputs);
        let list: Vec<Vec<u8>> = rlp::decode_list(&node);
        let value: Vec<u8> = rlp::decode(&list[1]).unwrap();
        debug!(
            "[+] [+] MPT SLOT {:?} -> value {:?} value.digest() = {:?}",
            slot_info.slot().slot(),
            U256::from_be_slice(&value),
            pi.values_digest()
        );
        proof
    }

    /// Prove a trie node recursively for length extraction.
    fn prove_length(&self, ctx: ProvingContext) -> SerializedProof {
        // gupeng
        match self.node_type() {
            TrieNodeType::Branch => self.prove_length_branch(ctx),
            TrieNodeType::Extension => self.prove_length_extension(ctx),
            TrieNodeType::Leaf => self.prove_length_leaf(ctx),
        }
    }

    /// Prove a length extraction leaf node.
    fn prove_length_leaf(&self, ctx: ProvingContext) -> SerializedProof {
        // Has no child for the leaf node.
        assert_eq!(self.children.len(), 0);

        let node = self.raw.clone();
        let variable_slot = ctx.variable_slot.unwrap();

        // Find the storage slot for this leaf node.
        let slot = ctx.slots.get(&node).unwrap();

        // Build the leaf circuit input.
        let input = match slot.slot() {
            StorageSlot::Simple(slot) => {
                length_extraction::LengthCircuitInput::new_leaf(*slot as u8, node, variable_slot)
            }
            StorageSlot::Mapping(_, slot) => {
                length_extraction::LengthCircuitInput::new_leaf(*slot as u8, node, variable_slot)
            }
            // TODO: Fix when updating the length circuit.
            _ => unimplemented!(),
        };
        let input = CircuitInput::LengthExtraction(input);

        // Generate the proof.
        ctx.b
            .bench("indexing::extraction::length::leaf", || {
                generate_proof(ctx.params, input)
            })
            .unwrap()
    }

    /// Prove a branch node.
    fn prove_length_branch(&self, ctx: ProvingContext) -> SerializedProof {
        // Has one child at least and 16 at maximum.
        assert!(self.children.len() > 0);
        assert!(self.children.len() <= MAX_BRANCH_CHILDREN);

        let node = self.raw.clone();

        // Fetch the child proof of the node.
        let child_proof = self.children[0].prove_length(ctx);

        // Build the branch circuit input.
        let input = length_extraction::LengthCircuitInput::new_branch(node, child_proof);
        let input = CircuitInput::LengthExtraction(input);

        // Generate the proof.
        ctx.b
            .bench("indexing::extraction::length::branch", || {
                generate_proof(ctx.params, input)
            })
            .unwrap()
    }

    /// Prove an extension node.
    fn prove_length_extension(&self, ctx: ProvingContext) -> SerializedProof {
        // Has one child at least and 16 at maximum.
        assert!(self.children.len() > 0);
        assert!(self.children.len() <= MAX_BRANCH_CHILDREN);

        let node = self.raw.clone();

        // Fetch the child proof of the node.
        let child_proof = self.children[0].prove_length(ctx);

        // Build the branch circuit input.
        let input = length_extraction::LengthCircuitInput::new_extension(node, child_proof);
        let input = CircuitInput::LengthExtraction(input);

        // Generate the proof.
        ctx.b
            .bench("indexing::extraction::length::extension", || {
                generate_proof(ctx.params, input)
            })
            .unwrap()
    }
}

/// Test storage trie
#[derive(Debug)]
pub(crate) struct TestStorageTrie {
    /// Root of this trie
    root: Option<TrieNode>,
    /// Storage slot map indexed by the raw node
    slots: HashMap<RawNode, StorageSlotInfo>,
}

impl TestStorageTrie {
    /// Initialize a test storage trie.
    pub(crate) fn new() -> Self {
        log::info!("Initializing the test storage trie...");

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
    pub(crate) fn add_slot(&mut self, slot: StorageSlotInfo, mut nodes: Vec<RawNode>) {
        self.check_new_slot(slot.slot(), &nodes);

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

    /// Query the contract at the provided address, fetch a proof using the context, and add it to
    /// the trie's slot.
    pub(crate) async fn query_proof_and_add_slot(
        &mut self,
        ctx: &TestContext,
        contract_address: &Address,
        slot_info: StorageSlotInfo,
    ) {
        let slot = slot_info.slot().slot() as usize;
        log::debug!("Querying the simple slot `{slot:?}` of the contract `{contract_address}` from the test context's RPC");

        let query = ProofQuery::new_simple_slot(*contract_address, slot);
        let response = ctx
            .query_mpt_proof(&query, BlockNumberOrTag::Number(ctx.block_number().await))
            .await;

        // Get the nodes to prove. Reverse to the sequence from leaf to root.
        let nodes: Vec<_> = response.storage_proof[0]
            .proof
            .iter()
            .rev()
            .map(|node| node.to_vec())
            .collect();

        let slot = StorageSlot::Simple(slot);

        log::debug!(
            "Simple slot {slot:?} queried, appending `{}` proof nodes to the trie",
            nodes.len()
        );

        self.add_slot(slot_info, nodes);
    }

    /// Generate the proof for the trie.
    pub(crate) fn prove_length(
        &self,
        contract_address: &Address,
        chain_id: u64,
        variable_slot: u8,
        params: &PublicParameters,
        b: &Benchmarker,
    ) -> ProofWithVK {
        let ctx = ProvingContext::new(
            contract_address,
            chain_id,
            params,
            &self.slots,
            Some(variable_slot),
            b,
        );

        // Must prove with 1 slot at least.
        let proof = self.root.as_ref().unwrap().prove_length(ctx);

        ProofWithVK::deserialize(&proof).unwrap()
    }

    /// Generate the proof for the trie.
    pub(crate) fn prove_value(
        &self,
        contract_address: &Address,
        chain_id: u64,
        params: &PublicParameters,
        b: &Benchmarker,
    ) -> ProofWithVK {
        let ctx = ProvingContext::new(contract_address, chain_id, params, &self.slots, None, b);

        // Must prove with 1 slot at least.
        let proof = self.root.as_ref().unwrap().prove_value(ctx);

        ProofWithVK::deserialize(&proof).unwrap()
    }

    /// Check the new slot if it's the same type slot and the node path has the same root.
    fn check_new_slot(&self, new_slot: &StorageSlot, new_nodes: &[RawNode]) {
        if let Some((_, slot)) = self.slots.iter().next() {
            // The new slot must be the same type.
            match (slot.slot(), new_slot) {
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
