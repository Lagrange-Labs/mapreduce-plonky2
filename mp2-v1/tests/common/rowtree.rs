use std::collections::HashSet;

use alloy::{primitives::U256, rpc::types::Block};
use anyhow::*;
use log::debug;
use mp2_common::{
    poseidon::empty_poseidon_hash,
    proof::ProofWithVK,
    serialization::{deserialize, serialize, FromBytes, ToBytes},
    types::HashOutput,
    utils::ToFields,
    CHasher, F,
};
use mp2_v1::{
    api::{self, CircuitInput},
    indexing::{
        cell_tree::Cell,
        row_tree::{Row, RowPayload, RowTreeKey, ToNonce},
    },
};
use plonky2::{
    field::types::Field,
    hash::{hash_types::HashOut, hashing::hash_n_to_hash_no_pad},
    plonk::config::Hasher,
};
use ryhope::{
    storage::{
        memory::InMemory,
        updatetree::{Next, UpdateTree},
        EpochKvStorage, TreeTransactionalStorage,
    },
    tree::{
        scapegoat::{self, Alpha},
        TreeTopology,
    },
    InitSettings, MerkleTreeKvDb, NodePayload,
};
use serde::{Deserialize, Serialize};

use crate::common::{index_tree::IndexNode, row_tree_proof_to_hash};

use super::{
    proof_storage::{
        BlockPrimaryIndex, CellProofIdentifier, ProofKey, ProofStorage, RowProofIdentifier,
    },
    table::{RowUpdateResult, Table},
    TestContext,
};
use derive_more::{From, Into};

pub type RowTreeKeyNonce = Vec<u8>;

/// Simply a struct useful to transmit around when dealing with the secondary index value, since
/// the unique nonce must be kept around as well. It is not saved anywhere nor proven.
#[derive(PartialEq, Eq, Default, Debug, Clone)]
pub struct SecondaryIndexCell(Cell, RowTreeKeyNonce);
impl SecondaryIndexCell {
    pub fn new_from<T: ToNonce>(c: Cell, nonce: T) -> Self {
        Self(c, nonce.to_nonce())
    }

    pub fn cell(&self) -> Cell {
        self.0.clone()
    }
    pub fn rest(&self) -> RowTreeKeyNonce {
        self.1.clone()
    }
}

impl From<SecondaryIndexCell> for RowTreeKey {
    fn from(value: SecondaryIndexCell) -> Self {
        RowTreeKey {
            value: value.0.value.into(),
            rest: value.1,
        }
    }
}

impl From<&SecondaryIndexCell> for RowTreeKey {
    fn from(value: &SecondaryIndexCell) -> Self {
        RowTreeKey {
            value: value.0.value.into(),
            rest: value.1.clone(),
        }
    }
}

pub type RowTree = scapegoat::Tree<RowTreeKey>;
type RowStorage = InMemory<RowTree, RowPayload>;
pub type MerkleRowTree = MerkleTreeKvDb<RowTree, RowPayload, RowStorage>;

/// Given a list of row, build the Merkle tree of the secondary index and
/// returns it along its update tree.
pub async fn build_row_tree(rows: &[Row]) -> Result<(MerkleRowTree, UpdateTree<RowTreeKey>)> {
    let mut row_tree = MerkleRowTree::new(
        InitSettings::Reset(scapegoat::Tree::empty(Alpha::new(0.8))),
        (),
    )
    .context("while creating row tree instance")?;

    let update_tree = row_tree
        .in_transaction(|t| {
            for row in rows.iter() {
                t.store(row.k.to_owned(), row.payload.to_owned())?;
            }
            Ok(())
        })
        .context("while filling row tree initial state")?;

    Ok((row_tree, update_tree))
}

impl<P: ProofStorage> TestContext<P> {
    /// Given a row tree (i.e. secondary index tree) and its update tree, prove
    /// it.
    pub fn prove_row_tree(
        &mut self,
        // required to fetch the right row tree proofs during the update, since the key
        // itself is not enough, since there might be multiple proofs with the same key but not
        // for the same block (i.e. not the same data)
        primary: BlockPrimaryIndex,
        table: &Table,
        ut: UpdateTree<<RowTree as TreeTopology>::Key>,
    ) -> Result<RowProofIdentifier<BlockPrimaryIndex>> {
        let t = &table.row;
        println!(" --- BEFORE WORKPLAN ---");
        ut.print();
        println!(" --- AFTER WORKPLAN ---");
        let mut workplan = ut.into_workplan();
        while let Some(Next::Ready(k)) = workplan.next() {
            let (context, row) = t.fetch_with_context(&k);
            let id = row.secondary_index;
            // Sec. index value
            let value = row.secondary_index_value();

            let cell_tree_proof = self
                .storage
                .get_proof_exact(&ProofKey::Cell(row.cell_tree_root_proof_id.clone()))
                .expect("should find cell root proof");
            debug!("After fetching cell proof for row key {:?}", k);
            let proof = if context.is_leaf() {
                // Prove a leaf
                let inputs = CircuitInput::RowsTree(
                    verifiable_db::row_tree::CircuitInput::leaf(id, value, cell_tree_proof)
                        .unwrap(),
                );
                debug!("Before proving leaf node row tree key {:?}", k);
                api::generate_proof(self.params(), inputs).expect("while proving leaf")
            } else if context.is_partial() {
                let proof_key = RowProofIdentifier {
                    table: table.id.clone(),
                    primary,
                    tree_key: context
                        .left
                        .as_ref()
                        .or(context.right.as_ref())
                        .cloned()
                        .unwrap(),
                };
                // Prove a partial node
                // NOTE: we need to find the latest one generated for that rowtreekey
                // and we don't know which block is it, it is not necessarily the current block!
                debug!(
                    "BEFORE fetching child proof of node {:?} for partial node {:?}",
                    proof_key, k,
                );
                let (child_proof, obn) = self
                    .storage
                    .get_proof_latest(&proof_key)
                    .expect("UT guarantees proving in order");
                debug!(
                    "AFTER fetching child proof for partial node - found at block {:?}",
                    obn.primary
                );

                debug!("AFTER fetching cell tree proof for partial node");
                let inputs = CircuitInput::RowsTree(
                    verifiable_db::row_tree::CircuitInput::partial(
                        id,
                        value,
                        context.left.is_some(),
                        child_proof,
                        cell_tree_proof,
                    )
                    .unwrap(),
                );

                debug!("Before proving partial node row tree key");
                api::generate_proof(self.params(), inputs).expect("while proving partial node")
            } else {
                let left_proof_key = RowProofIdentifier {
                    table: table.id.clone(),
                    primary,
                    tree_key: context.left.unwrap(),
                };
                let right_proof_key = RowProofIdentifier {
                    table: table.id.clone(),
                    primary,
                    tree_key: context.right.unwrap(),
                };

                // Prove a full node: fetch the row proofs of the children
                // NOTE: these row proofs may have been generated at any block in the past.
                // Therefore we need to search for the _latest_ one since that is the one of
                // interest to us.
                debug!(
                    "BEFORE fetching LEFT row tree {:?} proof for full node {:?}",
                    left_proof_key, k
                );
                let (left_proof, lbn) = self
                    .storage
                    .get_proof_latest(&left_proof_key)
                    .expect("UT guarantees proving in order");
                debug!(
                    "AFTER fetching LEFT row tree proof for full node - FOUND block {}",
                    lbn.primary
                );
                debug!(
                    "BEFORE fetching RIGHT row tree {:?} for full node {:?}",
                    right_proof_key, k
                );
                let (right_proof, rbn) = self
                    .storage
                    .get_proof_latest(&right_proof_key)
                    .expect("UT guarantees proving in order");
                debug!(
                    "AFTER fetching RIGHT row tree proof for full node - FOUND block {}",
                    rbn.primary
                );
                let inputs = CircuitInput::RowsTree(
                    verifiable_db::row_tree::CircuitInput::full(
                        id,
                        value,
                        left_proof,
                        right_proof,
                        cell_tree_proof,
                    )
                    .unwrap(),
                );
                debug!("Before proving full node row tree key {:?}", k);
                api::generate_proof(self.params(), inputs).expect("while proving full node")
            };
            let new_proof_key = RowProofIdentifier {
                table: table.id.clone(),
                primary,
                tree_key: k.clone(),
            };

            self.storage
                .store_proof(ProofKey::Row(new_proof_key), proof)
                .expect("storing should work");

            debug!("Finished row tree key proving {k:?}");
            workplan.done(&k).unwrap();
        }
        let root = t.root().unwrap();
        let root_proof_key = RowProofIdentifier {
            table: table.id.clone(),
            primary,
            tree_key: root,
        };

        let (p, key_found) = self
            .storage
            .get_proof_latest(&root_proof_key)
            .expect("row tree root proof absent");

        if key_found == root_proof_key {
            let pproof = ProofWithVK::deserialize(&p).unwrap();
            let pi =
                verifiable_db::row_tree::PublicInputs::from_slice(&pproof.proof().public_inputs);
            debug!(
                "[--] FINAL MERKLE DIGEST VALUE --> {:?} ",
                pi.rows_digest_field()
            );
        } else {
            debug!(
                "[--] No updates to compute! (last root on block {}",
                key_found.primary
            );
        }
        Ok(key_found)
    }

    /// Build and prove the row tree from the [`Row`]s and the secondary index
    /// data (which **must be absent** from the rows).
    /// Returns the identifier of the root proof and the hash of the updated row tree
    /// NOTE:we are simplifying a bit here as we assume the construction of the index tree
    /// is from (a) the block and (b) only one by one, i.e. there is only one IndexNode to return
    /// that have to be inserted. For CSV case, it should return a vector of new inserted nodes.
    pub fn prove_update_row_tree(
        &mut self,
        primary: BlockPrimaryIndex,
        table: &Table,
        update: RowUpdateResult,
    ) -> Result<IndexNode> {
        let root_proof_key = self.prove_row_tree(primary, table, update.updates)?;
        let row_tree_proof = self
            .storage
            .get_proof_exact(&ProofKey::Row(root_proof_key.clone()))
            .unwrap();

        let tree_hash = table.row.root_data().unwrap().hash;
        let proved_hash = row_tree_proof_to_hash(&row_tree_proof);

        assert_eq!(
            tree_hash, proved_hash,
            "mismatch between row tree root hash as computed by ryhope and mp2",
        );
        Ok(IndexNode {
            identifier: table.columns.primary_column().identifier,
            value: U256::from(primary),
            row_tree_proof_id: root_proof_key,
            row_tree_hash: table.row.root_data().unwrap().hash,
            ..Default::default()
        })
    }
}

impl ToNonce for usize {
    fn to_nonce(&self) -> RowTreeKeyNonce {
        self.to_be_bytes().to_vec()
    }
}

impl ToNonce for Vec<u8> {
    fn to_nonce(&self) -> RowTreeKeyNonce {
        self.to_owned()
    }
}

impl ToNonce for U256 {
    fn to_nonce(&self) -> RowTreeKeyNonce {
        // we don't need to keep all the bytes, only the ones that matter.
        // Since we are storing this inside psql, any storage saving is good to take !
        self.to_be_bytes_trimmed_vec()
    }
}

#[derive(Clone, Hash, Debug, PartialOrd, PartialEq, Ord, Eq, Default, From)]
pub struct VectorU256(pub U256);

impl ToBytes for VectorU256 {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes_trimmed_vec()
    }
}

impl FromBytes for VectorU256 {
    fn from_bytes(
        bytes: &[u8],
    ) -> std::result::Result<Self, mp2_common::serialization::SerializationError> {
        std::result::Result::Ok(VectorU256(U256::from_be_slice(bytes)))
    }
}
