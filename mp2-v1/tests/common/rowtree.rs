use anyhow::*;
use ethers::types::U256;
use mp2_common::{poseidon::empty_poseidon_hash, utils::ToFields, CHasher, F};
use mp2_test::cells_tree::TestCell as Cell;
use mp2_v1::api::{self, CircuitInput};
use plonky2::{
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
    MerkleTreeKvDb, NodePayload,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::common::row_tree_proof_to_hash;

use super::{
    cell_tree_proof_to_hash,
    proof_storage::{
        BlockPrimaryIndex, CellProofIdentifier, ProofKey, ProofStorage, RowProofIdentifier, TableID,
    },
    TestContext,
};

/// A unique identifier in a row tree
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RowTreeKey {
    /// Value of the secondary index of the row
    pub value: U256,
    /// Enumerated index of the row in the virtual table
    pub id: usize,
}

/// Represent a row in one of the virtual tables stored in the zkDB; which
/// encapsulates its cells and the tree they form.
#[derive(Clone, Serialize, Deserialize)]
pub struct Row {
    /// A key *uniquely* representing this row in the row tree.
    ///
    /// NOTE: this key is **not** the index as understood in the crypto
    /// formalization.
    pub k: RowTreeKey,
    pub cells: Vec<Cell>,
    /// Storing the full identifier of the cells proof of the root of the cells tree.
    /// Note this identifier can refer to a proof for older blocks if the cells tree didn't change
    pub cell_tree_root_proof_id: CellProofIdentifier<BlockPrimaryIndex>,
    /// Storing the hash of the root of the cells tree. Once could get it as well from the proof
    /// but it requires loading the proof, so when building the hashing structure it's best
    /// to keep it at hand directly.
    pub cell_tree_root_hash: HashOut<F>,
    /// Min sec. index value of the subtree below this node
    pub min: U256,
    /// Max sec. index value "  "   "       "     "    "
    pub max: U256,
    /// Hash of this node
    pub hash: HashOut<F>,
}
impl Row {
    /// Return the [`Cell`] containing the sec. index of this row.
    pub fn secondary_index(&self) -> &Cell {
        &self.cells[0]
    }
}
impl NodePayload for Row {
    fn aggregate<'a, I: Iterator<Item = Option<Self>>>(&mut self, children: I) {
        let children = children.into_iter().collect::<Vec<_>>();
        assert_eq!(children.len(), 2);

        self.hash = match [&children[0], &children[1]] {
            [None, None] => {
                self.min = self.secondary_index().value.clone();
                self.max = self.secondary_index().value.clone();
                let to_hash =
                    // 2 × P("")
                    empty_poseidon_hash()
                    .to_fields()
                    .into_iter()
                    .chain(empty_poseidon_hash().to_fields().into_iter())
                    // P(min) = P(max) = P(value)
                    .chain(self.min.to_fields().into_iter())
                    .chain(self.max.to_fields().into_iter())
                    // P(id)
                    .chain(std::iter::once(self.secondary_index().id))
                    // P(value)
                    .chain(self.secondary_index().value.to_fields().into_iter())
                    // P(cell_tree_hash)
                    .chain(self.cell_tree_root_hash.to_fields().into_iter())
                    .collect::<Vec<_>>();
                hash_n_to_hash_no_pad::<F, <CHasher as Hasher<F>>::Permutation>(&to_hash)
            }
            [None, Some(right)] => {
                self.min = self.secondary_index().value.clone();
                self.max = right.max.clone();
                let to_hash =
                    // P(leftH) = ""
                    empty_poseidon_hash()
                    .to_fields()
                    .into_iter()
                    // P(rightH)
                    .chain(right.hash.elements.into_iter())
                    // P(min)
                    .chain(self.min.to_fields().into_iter())
                    // P(max)
                    .chain(self.max.to_fields().into_iter())
                    // P(id)
                    .chain(std::iter::once(self.secondary_index().id))
                    // P(value)
                    .chain(self.secondary_index().value.to_fields().into_iter())
                    // P(cell_tree_hash)
                    .chain(self.cell_tree_root_hash.to_fields().into_iter())
                    .collect::<Vec<_>>();
                hash_n_to_hash_no_pad::<F, <CHasher as Hasher<F>>::Permutation>(&to_hash)
            }
            [Some(left), None] => {
                self.min = left.min.clone();
                self.max = self.secondary_index().value.clone();
                let to_hash =
                    // P(leftH")
                    left.hash.elements.into_iter()
                    // P(rightH) = ""
                    .chain(empty_poseidon_hash()
                    .to_fields()
                    .into_iter())
                    // P(min)
                    .chain(self.min.to_fields().into_iter())
                    // P(max)
                    .chain(self.max.to_fields().into_iter())
                    // P(id)
                    .chain(std::iter::once(self.secondary_index().id))
                    // P(value)
                    .chain(self.secondary_index().value.to_fields().into_iter())
                    // P(cell_tree_hash)
                    .chain(self.cell_tree_root_hash.to_fields().into_iter())
                    .collect::<Vec<_>>();
                hash_n_to_hash_no_pad::<F, <CHasher as Hasher<F>>::Permutation>(&to_hash)
            }
            [Some(left), Some(right)] => {
                self.min = left.min.clone();
                self.max = right.max.clone();
                let to_hash =
                    // P(leftH)
                    left.hash.elements.into_iter()
                    // P(rightH)
                    .chain(right.hash.elements.into_iter())
                    // P(min)
                    .chain(self.min.to_fields().into_iter())
                    // P(max)
                    .chain(self.max.to_fields().into_iter())
                    // P(id)
                    .chain(std::iter::once(self.secondary_index().id))
                    // P(value)
                    .chain(self.secondary_index().value.to_fields().into_iter())
                    // P(cell_tree_hash)
                    .chain(self.cell_tree_root_hash.to_fields().into_iter())
                    .collect::<Vec<_>>();
                hash_n_to_hash_no_pad::<F, <CHasher as Hasher<F>>::Permutation>(&to_hash)
            }
        };
    }
}

pub type RowTree = scapegoat::Tree<RowTreeKey>;
type RowStorage = InMemory<RowTree, Row>;
pub type MerkleRowTree = MerkleTreeKvDb<RowTree, Row, RowStorage>;

/// Given a list of row, build the Merkle tree of the secondary index and
/// returns it along its update tree.
pub async fn build_row_tree(rows: &[Row]) -> Result<(MerkleRowTree, UpdateTree<RowTreeKey>)> {
    let mut row_tree =
        MerkleRowTree::create(Alpha::new(0.8), ()).context("while creating row tree instance")?;

    let update_tree = row_tree
        .in_transaction(|t| {
            for row in rows.iter() {
                t.store(row.k.to_owned(), row.to_owned())?;
            }
            Ok(())
        })
        .context("while filling row tree initial state")?;

    Ok((row_tree, update_tree))
}

impl TestContext {
    /// Given a row tree (i.e. secondary index tree) and its update tree, prove
    /// it.
    pub async fn prove_row_tree<P: ProofStorage>(
        &self,
        table_id: &TableID,
        t: &MerkleRowTree,
        ut: UpdateTree<<RowTree as TreeTopology>::Key>,
        storage: &mut P,
    ) -> Vec<u8> {
        let mut workplan = ut.into_workplan();
        // THIS can panic but for block number it should be fine on 64bit platforms...
        // unwrap is safe since we know it is really a block number and not set to Latest or stg
        let block_key: BlockPrimaryIndex =
            self.block_number.as_number().unwrap().try_into().unwrap();

        while let Some(Next::Ready(k)) = workplan.next() {
            let (context, row) = t.fetch_with_context(&k);
            // NOTE: the sec. index. is assumed to be in the first position
            // Sec. index identifier
            let id = row.secondary_index().id;
            // Sec. index value
            let value = row.secondary_index().value;

            let cell_tree_proof = storage
                .get_proof(&ProofKey::Cell(row.cell_tree_root_proof_id.clone()))
                .expect("should find cell root proof");
            let proof = if context.is_leaf() {
                // Prove a leaf
                let inputs = CircuitInput::RowsTree(
                    verifiable_db::row_tree::CircuitInput::leaf(id, value, cell_tree_proof)
                        .unwrap(),
                );
                api::generate_proof(self.params(), inputs).expect("while proving leaf")
            } else if context.is_partial() {
                let proof_key = RowProofIdentifier {
                    table: table_id.clone(),
                    primary: block_key,
                    tree_key: context
                        .left
                        .as_ref()
                        .or(context.right.as_ref())
                        .cloned()
                        .unwrap(),
                };
                // Prove a partial node
                let child_proof = storage
                    .get_proof(&ProofKey::Row(proof_key))
                    .expect("UT guarantees proving in order");

                let cell_tree_proof = storage
                    .get_proof(&ProofKey::Cell(row.cell_tree_root_proof_id))
                    .expect("should find cells tree root proof");
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

                api::generate_proof(self.params(), inputs).expect("while proving partial node")
            } else {
                let left_proof_key = RowProofIdentifier {
                    table: table_id.clone(),
                    primary: block_key,
                    tree_key: context.left.unwrap(),
                };
                let right_proof_key = RowProofIdentifier {
                    table: table_id.clone(),
                    primary: block_key,
                    tree_key: context.right.unwrap(),
                };
                let cell_tree_proof = storage
                    .get_proof(&ProofKey::Cell(row.cell_tree_root_proof_id.clone()))
                    .expect("should find cells tree root proof");

                // Prove a full node.
                let left_proof = storage
                    .get_proof(&ProofKey::Row(left_proof_key))
                    .expect("UT guarantees proving in order");
                let right_proof = storage
                    .get_proof(&ProofKey::Row(right_proof_key))
                    .expect("UT guarantees proving in order");
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
                api::generate_proof(self.params(), inputs).expect("while proving full node")
            };
            let new_proof_key = RowProofIdentifier {
                table: table_id.clone(),
                primary: block_key,
                tree_key: k.clone(),
            };

            storage
                .store_proof(ProofKey::Row(new_proof_key), proof)
                .expect("storing should work");

            workplan.done(&k).unwrap();
        }
        let root = t.tree().root().unwrap();
        let root_proof_key = RowProofIdentifier {
            table: table_id.clone(),
            primary: block_key,
            tree_key: root,
        };

        storage.get_proof(&ProofKey::Row(root_proof_key)).unwrap()
    }

    /// Build and prove the row tree from the [`Row`]s and the secondary index
    /// data (which **must be absent** from the rows), returning its proof.
    pub async fn build_and_prove_rowtree<P: ProofStorage>(
        &self,
        table_id: &TableID,
        rows: &[Row],
        storage: &mut P,
    ) -> Vec<u8> {
        let (row_tree, row_tree_ut) = build_row_tree(rows)
            .await
            .expect("failed to create row tree");
        let row_tree_proof = self
            .prove_row_tree(table_id, &row_tree, row_tree_ut, storage)
            .await;

        let tree_hash = row_tree.root_data().unwrap().hash;
        let proved_hash = row_tree_proof_to_hash(&row_tree_proof);

        assert_eq!(
            tree_hash, proved_hash,
            "mismatch between row tree root hash as computed by ryhope and mp2",
        );

        row_tree_proof
    }
}