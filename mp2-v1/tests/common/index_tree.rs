use alloy::primitives::U256;
use log::{debug, info};
use mp2_common::{poseidon::empty_poseidon_hash, proof::ProofWithVK};
use mp2_v1::{
    api,
    indexing::{
        block::{BlockPrimaryIndex, BlockTree, BlockTreeKey},
        index::IndexNode,
    },
    values_extraction::identifier_block_column,
};
use plonky2::plonk::config::GenericHashOut;
use ryhope::{
    storage::{
        pgsql::PgsqlStorage,
        updatetree::{Next, UpdateTree},
        RoEpochKvStorage,
    },
    MerkleTreeKvDb,
};
use verifiable_db::block_tree::compute_final_digest;

use crate::common::proof_storage::{IndexProofIdentifier, ProofKey};

use super::{
    proof_storage::{ProofStorage, RowProofIdentifier},
    table::{Table, TableID},
    TestContext,
};

pub type IndexStorage = PgsqlStorage<BlockTree, IndexNode<BlockPrimaryIndex>>;
pub type MerkleIndexTree = MerkleTreeKvDb<BlockTree, IndexNode<BlockPrimaryIndex>, IndexStorage>;

impl TestContext {
    /// NOTE: we require the added_index information because we need to distinguish if a new node
    /// added has a leaf or a as parent. The rest of the nodes in the update tree are to be proven
    /// by the "membership" circuit. So we need to differentiate between the two cases.
    pub async fn prove_index_tree(
        &mut self,
        table_id: &TableID,
        t: &MerkleIndexTree,
        ut: UpdateTree<BlockTreeKey>,
        added_index: &IndexNode<BlockPrimaryIndex>,
    ) -> IndexProofIdentifier<BlockPrimaryIndex> {
        let mut workplan = ut.into_workplan();
        while let Some(Next::Ready(wk)) = workplan.next() {
            let k = wk.k();
            let (context, node) = t.fetch_with_context(&k).await;
            let row_proof_key = RowProofIdentifier {
                table: table_id.clone(),
                tree_key: node.row_tree_root_key,
                primary: node.row_tree_root_primary,
            };
            let row_tree_proof = self
                .storage
                .get_proof_exact(&ProofKey::Row(row_proof_key))
                .expect("should find row proof");
            // extraction proof is done once per block, so its key can just be block based
            debug!(
                "trying to LOAD the extraction proof from {table_id:?} - index value {}",
                node.value.0.to::<U256>()
            );
            let extraction_proof = self
                .storage
                .get_proof_exact(&ProofKey::FinalExtraction((
                    table_id.clone(),
                    // NOTE: important to take the final extraction corresponding to the index
                    // being proven which is not the latest one always. In update tree, many nodes
                    // may need to be proven again, historical nodes, since their children might
                    // have changed.
                    node.value.0.to(),
                )))
                .expect("should find extraction proof");
            {
                // debug sanity checks
                let row_proof =
                    ProofWithVK::deserialize(&row_tree_proof).expect("can't deserialize row proof");
                let row_pi = verifiable_db::row_tree::PublicInputs::from_slice(
                    &row_proof.proof().public_inputs,
                );
                let ext_proof = ProofWithVK::deserialize(&extraction_proof)
                    .expect("can't deserialize extraction proof");
                let ext_pi = mp2_v1::final_extraction::PublicInputs::from_slice(
                    &ext_proof.proof().public_inputs,
                );
                let is_merge = ext_pi.merge_flag();
                let final_db_digest = compute_final_digest(is_merge, &row_pi).to_weierstrass();
                assert_eq!(
                    final_db_digest,
                    ext_pi.value_point(),
                    "Block (DB) values digest and values extraction don't match (left DB, right MPT, is_merge {} block {})",
                    is_merge,
                    node.value.0.to::<u64>()
                );
                debug!(
                    "NodeIndex Proving - multiplier digest: {:?}",
                    row_pi.multiplier_digest_point(),
                );
            }
            let proof = if context.is_leaf() {
                info!(
                    "NodeIndex Proving --> LEAF (node {})",
                    node.value.0.to::<U256>()
                );

                let inputs = api::CircuitInput::BlockTree(
                    verifiable_db::block_tree::CircuitInput::new_leaf(
                        node.identifier,
                        extraction_proof,
                        row_tree_proof,
                    ),
                );
                self.b
                    .bench("indexing::index_tree::leaf", || {
                        api::generate_proof(self.params(), inputs)
                    })
                    .expect("unable to generate index tree leaf")
            } else if context.is_partial() {
                info!(
                    "NodeIndex Proving --> PARTIAL (node {})",
                    node.value.0.to::<U256>()
                );
                // a node that was already there before and is in the path of the added node to the
                // root should always have two children
                assert_eq!(
                    added_index.value, node.value,
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
                let (prev_ctx, previous_node) = t.fetch_with_context(previous_key).await;
                let prev_left_hash = match prev_ctx.left {
                    Some(kk) => t.fetch(&kk).await.node_hash,
                    None => empty_poseidon_hash().to_bytes().try_into().unwrap(),
                };

                let prev_right_hash = match prev_ctx.right {
                    Some(kk) => t.fetch(&kk).await.node_hash,
                    None => empty_poseidon_hash().to_bytes().try_into().unwrap(),
                };

                let inputs = api::CircuitInput::BlockTree(
                    verifiable_db::block_tree::CircuitInput::new_parent(
                        // TODO: change API to use u64 only
                        node.identifier,
                        previous_node.value.0,
                        previous_node.min,
                        previous_node.max,
                        &prev_left_hash,
                        &prev_right_hash,
                        &previous_node.row_tree_hash,
                        extraction_proof,
                        row_tree_proof,
                    ),
                );
                self.b
                    .bench("indexing::index_tree::parent", || {
                        api::generate_proof(self.params(), inputs)
                    })
                    .expect("error while leaf index proof generation")
            } else {
                // here we are simply proving the new updated nodes from the new node to
                // the root. We fetch the same node but at the previous version of the
                // tree to prove the update.
                let previous_node = t.fetch_at(&k, t.current_epoch() - 1).await;
                let left_key = context.left.expect("should always be a left child");
                let left_node = t.fetch(&left_key).await;
                // this should be one of the nodes we just proved in this loop before
                let right_key = context.right.expect("should always be a right child");
                let right_proof = self
                    .storage
                    .get_proof_exact(&ProofKey::Index(IndexProofIdentifier {
                        table: table_id.clone(),
                        tree_key: right_key,
                    }))
                    .expect("previous index proof not found");
                let inputs = api::CircuitInput::BlockTree(
                    verifiable_db::block_tree::CircuitInput::new_membership(
                        node.identifier,
                        node.value.0,
                        previous_node.min,
                        previous_node.max,
                        &left_node.node_hash,
                        &node.row_tree_hash,
                        right_proof,
                    ),
                );
                self.b
                    .bench("indexing::index_tree::membership", || {
                        api::generate_proof(self.params(), inputs)
                    })
                    .expect("error while membership index proof generation")
            };
            let proof_key = IndexProofIdentifier {
                table: table_id.clone(),
                tree_key: k.clone(),
            };
            self.storage
                .store_proof(ProofKey::Index(proof_key), proof)
                .expect("unable to store index tree proof");

            workplan.done(&wk).unwrap();
        }
        let root = t.root().await.unwrap();
        let root_proof_key = IndexProofIdentifier {
            table: table_id.clone(),
            tree_key: root,
        };

        // just checking the storage is there
        let _ = self
            .storage
            .get_proof_exact(&ProofKey::Index(root_proof_key.clone()))
            .unwrap();
        root_proof_key
    }

    pub(crate) async fn prove_update_index_tree(
        &mut self,
        bn: BlockPrimaryIndex,
        table: &Table,
        ut: UpdateTree<BlockTreeKey>,
    ) -> IndexProofIdentifier<BlockPrimaryIndex> {
        let row_tree_root = table.row.root().await.unwrap();
        let row_payload = table.row.fetch(&row_tree_root).await;
        let row_root_proof_key = RowProofIdentifier {
            table: table.public_name.clone(),
            tree_key: row_tree_root,
            primary: row_payload.primary_index_value(),
        };

        let row_tree_proof = self
            .storage
            .get_proof_exact(&ProofKey::Row(row_root_proof_key.clone()))
            .unwrap();
        let row_tree_hash = verifiable_db::row_tree::extract_hash_from_proof(&row_tree_proof)
            .expect("can't find hash?");
        let node = IndexNode {
            identifier: identifier_block_column(),
            value: U256::from(bn).into(),
            // NOTE: here we put the latest key found, since it may have been generated at a
            // previous block than the current one.
            row_tree_hash: row_tree_hash.to_bytes().try_into().unwrap(),
            ..Default::default()
        };
        info!("Generated index tree");
        self.prove_index_tree(&table.public_name.clone(), &table.index, ut, &node)
            .await
    }
}
