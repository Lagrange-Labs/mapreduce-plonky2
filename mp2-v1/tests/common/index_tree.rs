use anyhow::{Context, Result};
use mp2_v1::api;
use std::iter::once;

use ethers::types::{BlockNumber, U256};
use mp2_common::{poseidon::empty_poseidon_hash, utils::ToFields, CHasher, F};
use plonky2::{
    hash::{
        hash_types::HashOut,
        hashing::{hash_n_to_hash_no_pad, hash_n_to_m_no_pad},
    },
    plonk::config::Hasher,
};
use ryhope::{
    storage::{
        memory::InMemory,
        updatetree::{Next, UpdateTree},
        EpochKvStorage, RoEpochKvStorage, TreeTransactionalStorage,
    },
    tree::{sbbst, TreeTopology},
    MerkleTreeKvDb, NodePayload,
};
use serde::{Deserialize, Serialize};

use crate::common::proof_storage::{IndexProofIdentifier, ProofKey};

use super::{
    proof_storage::{BlockPrimaryIndex, ProofStorage, RowProofIdentifier, TableID},
    TestContext,
};

/// Hardcoded to use blocks but the spirit for any primary index is the same
#[derive(Clone, Serialize, Deserialize)]
pub struct IndexNode {
    pub identifier: F,
    pub value: U256,
    pub node_hash: HashOut<F>,
    pub row_tree_root_proof_id: RowProofIdentifier<BlockPrimaryIndex>,
    pub row_tree_hash: HashOut<F>,
    pub min: U256,
    pub max: U256,
}

impl NodePayload for IndexNode {
    fn aggregate<I: Iterator<Item = Option<Self>>>(&mut self, children: I) {
        // curently always return the expected number of children which
        // is two.
        let children = children.into_iter().collect::<Vec<_>>();
        assert_eq!(children.len(), 2);
        let null_hash = empty_poseidon_hash();

        let (left, right) = match [&children[0], &children[1]] {
            // no children
            [None, None] => {
                self.min = self.value;
                self.max = self.value;
                (null_hash, null_hash)
            }
            [Some(left), None] => {
                self.min = left.min;
                self.max = self.value;
                (&left.node_hash, null_hash)
            }
            [Some(left), Some(right)] => {
                self.min = left.min;
                self.max = right.max;
                (&left.node_hash, &right.node_hash)
            }
            [None, Some(_)] => panic!("ryhope sbbst is wrong"),
        };
        let inputs = left
            .to_fields()
            .into_iter()
            .chain(right.to_fields())
            .chain(self.min.to_fields())
            .chain(self.max.to_fields())
            .chain(once(self.identifier))
            .chain(self.value.to_fields())
            .chain(self.row_tree_hash.to_fields())
            .collect::<Vec<_>>();
        self.node_hash = hash_n_to_hash_no_pad::<F, <CHasher as Hasher<F>>::Permutation>(&inputs);
    }
}

pub fn u256_as_usize(u: &U256) -> usize {
    u.as_u64() as usize
}

pub type IndexTree = sbbst::Tree;
pub type IndexTreeKey = <IndexTree as TreeTopology>::Key;
type IndexStorage = InMemory<IndexTree, IndexNode>;
pub type MerkleIndexTree = MerkleTreeKvDb<IndexTree, IndexNode, IndexStorage>;

pub async fn build_initial_index_tree(
    block_number: BlockNumber,
    index: &IndexNode,
) -> Result<(MerkleIndexTree, UpdateTree<IndexTreeKey>)> {
    let block_usize: BlockPrimaryIndex = block_number.as_number().unwrap().try_into().unwrap();

    // should always be one anyway since we iterate over blocks one by one
    // but in the case of general index we might create multiple nodes
    // at the same time
    let mut index_tree = MerkleIndexTree::create((block_usize, 1), ()).unwrap();
    let update_tree = index_tree
        .in_transaction(|t| {
            t.store(u256_as_usize(&index.value), index.clone())?;
            Ok(())
        })
        .context("while filling up index tree")?;
    Ok((index_tree, update_tree))
}

impl TestContext {
    /// NOTE: we require the added_index information because we need to distinguish if a new node
    /// added has a leaf or a as parent. The rest of the nodes in the update tree are to be proven
    /// by the "membership" circuit. So we need to differentiate between the two cases.
    pub async fn prove_index_tree<P: ProofStorage>(
        &self,
        table_id: &TableID,
        t: &MerkleIndexTree,
        ut: UpdateTree<IndexTreeKey>,
        added_index: &BlockPrimaryIndex,
        storage: &mut P,
    ) -> IndexProofIdentifier<BlockPrimaryIndex> {
        let mut workplan = ut.into_workplan();
        while let Some(Next::Ready(k)) = workplan.next() {
            let (context, node) = t.fetch_with_context(&k);
            let row_tree_proof = storage
                .get_proof(&ProofKey::Row(node.row_tree_root_proof_id.clone()))
                .expect("should find row proof");
            let extraction_proof = storage
                .get_proof(&ProofKey::Extraction(node.row_tree_root_proof_id.primary))
                .expect("should find extraction proof");
            let proof = if context.is_leaf() {
                let inputs = api::CircuitInput::BlockTree(
                    verifiable_db::block_tree::CircuitInput::new_leaf(
                        node.identifier,
                        extraction_proof,
                        row_tree_proof,
                    ),
                );
                api::generate_proof(self.params(), inputs)
                    .expect("error while leaf index proof generation")
            } else if context.is_partial() {
                // a node that was already there before and is in the path of the added node to the
                // root should always have two children
                assert_eq!(
                    added_index, &node.row_tree_root_proof_id.primary,
                    "a changed node should never be a partial node"
                );
                // we know it's a new node, and a new node becomes the parent of a previous
                // node, and this previous node is always the left children.
                let previous_key = context
                    .iter_children()
                    .next()
                    .expect("should find1 a children")
                    .expect("should be one at least");
                // It's ok to fetch the node at the same epoch because for the block tree
                // we know it's the left children now so the min and max didn't change, we
                // didn't insert anything new below
                let previous_node = t.fetch(previous_key);
                let inputs = api::CircuitInput::BlockTree(
                    verifiable_db::block_tree::CircuitInput::new_parent(
                        node.identifier,
                        previous_node.value,
                        previous_node.min,
                        previous_node.max,
                        previous_node.node_hash,
                        *empty_poseidon_hash(),
                        previous_node.row_tree_hash,
                        extraction_proof,
                        row_tree_proof,
                    ),
                );
                api::generate_proof(self.params(), inputs)
                    .expect("error while leaf index proof generation")
            } else {
                // here we are simply proving the new updated nodes from the new node to
                // the root. We fetch the same node but at the previous version of the
                // tree to prove the update.
                let previous_node = t.fetch_at(&k, t.current_epoch() - 1);
                let left_key = context.left.expect("should always be a left child");
                let left_node = t.fetch(&left_key);
                // this should be one of the nodes we just proved in this loop before
                let right_key = context.right.expect("should always be a right child");
                let right_proof = storage
                    .get_proof(&ProofKey::Index(IndexProofIdentifier {
                        table: table_id.clone(),
                        tree_key: right_key,
                    }))
                    .expect("previous index proof not found");
                let inputs = api::CircuitInput::BlockTree(
                    verifiable_db::block_tree::CircuitInput::new_membership(
                        node.identifier,
                        node.value,
                        previous_node.min,
                        previous_node.max,
                        left_node.node_hash,
                        node.row_tree_hash,
                        right_proof,
                    ),
                );
                api::generate_proof(self.params(), inputs)
                    .expect("error while membership index proof generation")
            };
            let proof_key = IndexProofIdentifier {
                table: table_id.clone(),
                tree_key: k,
            };
            storage
                .store_proof(ProofKey::Index(proof_key), proof)
                .expect("unable to store index tree proof");

            workplan.done(&k).unwrap();
        }
        let root = t.tree().root().unwrap();
        let root_proof_key = IndexProofIdentifier {
            table: table_id.clone(),
            tree_key: root,
        };

        // just checking the storage is there
        let _ = storage
            .get_proof(&ProofKey::Index(root_proof_key.clone()))
            .unwrap();
        root_proof_key
    }
}
