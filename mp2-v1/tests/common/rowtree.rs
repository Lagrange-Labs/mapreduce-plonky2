use alloy::{primitives::U256, rpc::types::Block};
use anyhow::*;
use mp2_common::{poseidon::empty_poseidon_hash, types::HashOutput, utils::ToFields, CHasher, F};
use mp2_v1::api::{self, CircuitInput};
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
    table::{RowUpdateResult, Table, TableID},
    TestContext,
};
use derive_more::{From, Into};

/// A unique identifier in a row tree
#[derive(Clone, Default, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RowTreeKey {
    /// Value of the secondary index of the row
    pub value: U256,
    /// Enumerated index of the row in the virtual table
    pub id: usize,
}

use super::celltree::Cell;
#[derive(From, Into, Default, Debug, Clone, Serialize, Deserialize)]
pub struct CellCollection(pub Vec<Cell>);
impl CellCollection {
    /// Return the [`Cell`] containing the sec. index of this row.
    pub fn secondary_index(&self) -> Result<&Cell> {
        ensure!(
            self.0.len() > 0,
            "secondary_index() called on empty CellCollection"
        );
        Ok(&self.0[0])
    }

    pub fn non_indexed_cells(&self) -> Result<&[Cell]> {
        ensure!(
            self.0.len() > 0,
            "non_indexed_cells called on empty  CellCollection"
        );
        Ok(&self.0[1..])
    }
    // take all the cells in &self, and replace the ones with same identifier from other
    pub fn replace_by(&self, other: &Self) -> Self {
        Self(
            self.0
                .iter()
                .map(|c| other.0.iter().find(|c2| c.id == c2.id).unwrap_or(c))
                .cloned()
                .collect(),
        )
    }
}
/// Represent a row in one of the virtual tables stored in the zkDB; which
/// encapsulates its cells and the tree they form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    /// A key *uniquely* representing this row in the row tree.
    ///
    /// NOTE: this key is **not** the index as understood in the crypto
    /// formalization.
    pub k: RowTreeKey,
    pub cells: CellCollection,
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

impl NodePayload for Row {
    fn aggregate<'a, I: Iterator<Item = Option<Self>>>(&mut self, children: I) {
        let children = children.into_iter().collect::<Vec<_>>();
        assert_eq!(children.len(), 2);

        let (left_hash, right_hash) = match [&children[0], &children[1]] {
            [None, None] => {
                self.min = self.cells.secondary_index().unwrap().value;
                self.max = self.cells.secondary_index().unwrap().value;
                (*empty_poseidon_hash(), *empty_poseidon_hash())
            }
            [None, Some(right)] => {
                self.min = self.cells.secondary_index().unwrap().value;
                self.max = right.max;
                (*empty_poseidon_hash(), right.hash)
            }
            [Some(left), None] => {
                self.min = left.min;
                self.max = self.cells.secondary_index().unwrap().value;
                (left.hash, *empty_poseidon_hash())
            }
            [Some(left), Some(right)] => {
                self.min = left.min;
                self.max = right.max;
                (left.hash, right.hash)
            }
        };
        let to_hash = // P(leftH)
                    left_hash.elements.into_iter()
                    // P(rightH)
                    .chain(right_hash.elements)
                    // P(min)
                    .chain(self.min.to_fields())
                    // P(max)
                    .chain(self.max.to_fields())
                    // P(id)
                    .chain(std::iter::once(F::from_canonical_u64(self.cells.secondary_index().unwrap().id)))
                    // P(value)
                    .chain(self.cells.secondary_index().unwrap().value.to_fields())
                    // P(cell_tree_hash)
                    .chain(self.cell_tree_root_hash.to_fields())
                    .collect::<Vec<_>>();
        self.hash = hash_n_to_hash_no_pad::<F, <CHasher as Hasher<F>>::Permutation>(&to_hash)
    }
}

pub type RowTree = scapegoat::Tree<RowTreeKey>;
type RowStorage = InMemory<RowTree, Row>;
pub type MerkleRowTree = MerkleTreeKvDb<RowTree, Row, RowStorage>;

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
                t.store(row.k.to_owned(), row.to_owned())?;
            }
            Ok(())
        })
        .context("while filling row tree initial state")?;

    Ok((row_tree, update_tree))
}

impl<P: ProofStorage> TestContext<P> {
    /// Given a row tree (i.e. secondary index tree) and its update tree, prove
    /// it.
    pub async fn prove_row_tree(
        &mut self,
        table: &Table,
        ut: UpdateTree<<RowTree as TreeTopology>::Key>,
    ) -> RowProofIdentifier<BlockPrimaryIndex> {
        let t = &table.row;
        let mut workplan = ut.into_workplan();
        // THIS can panic but for block number it should be fine on 64bit platforms...
        // unwrap is safe since we know it is really a block number and not set to Latest or stg
        let block_key = self.block_number().await as BlockPrimaryIndex;

        while let Some(Next::Ready(k)) = workplan.next() {
            let (context, row) = t.fetch_with_context(&k);
            let id = F::from_canonical_u64(row.cells.secondary_index().unwrap().id);
            // Sec. index value
            let value = row.cells.secondary_index().unwrap().value;

            let cell_tree_proof = self
                .storage
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
                    table: table.id.clone(),
                    primary: block_key,
                    tree_key: context
                        .left
                        .as_ref()
                        .or(context.right.as_ref())
                        .cloned()
                        .unwrap(),
                };
                // Prove a partial node
                let child_proof = self
                    .storage
                    .get_proof(&ProofKey::Row(proof_key))
                    .expect("UT guarantees proving in order");

                let cell_tree_proof = self
                    .storage
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
                    table: table.id.clone(),
                    primary: block_key,
                    tree_key: context.left.unwrap(),
                };
                let right_proof_key = RowProofIdentifier {
                    table: table.id.clone(),
                    primary: block_key,
                    tree_key: context.right.unwrap(),
                };
                let cell_tree_proof = self
                    .storage
                    .get_proof(&ProofKey::Cell(row.cell_tree_root_proof_id.clone()))
                    .expect("should find cells tree root proof");

                // Prove a full node.
                let left_proof = self
                    .storage
                    .get_proof(&ProofKey::Row(left_proof_key))
                    .expect("UT guarantees proving in order");
                let right_proof = self
                    .storage
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
                table: table.id.clone(),
                primary: block_key,
                tree_key: k.clone(),
            };

            self.storage
                .store_proof(ProofKey::Row(new_proof_key), proof)
                .expect("storing should work");

            workplan.done(&k).unwrap();
        }
        let root = t.root().unwrap();
        let root_proof_key = RowProofIdentifier {
            table: table.id.clone(),
            primary: block_key,
            tree_key: root,
        };

        self.storage
            .get_proof(&ProofKey::Row(root_proof_key.clone()))
            .expect("row tree root proof absent");
        root_proof_key
    }

    /// Build and prove the row tree from the [`Row`]s and the secondary index
    /// data (which **must be absent** from the rows).
    /// Returns the identifier of the root proof and the hash of the updated row tree
    /// NOTE:we are simplifying a bit here as we assume the construction of the index tree
    /// is from (a) the block and (b) only one by one, i.e. there is only one IndexNode to return
    /// that have to be inserted. For CSV case, it should return a vector of new inserted nodes.
    pub async fn prove_update_row_tree(
        &mut self,
        table: &Table,
        update: RowUpdateResult,
    ) -> IndexNode {
        let root_proof_key = self.prove_row_tree(table, update.updates).await;
        let row_tree_proof = self
            .storage
            .get_proof(&ProofKey::Row(root_proof_key.clone()))
            .unwrap();

        let tree_hash = table.row.root_data().unwrap().hash;
        let proved_hash = row_tree_proof_to_hash(&row_tree_proof);

        assert_eq!(
            tree_hash, proved_hash,
            "mismatch between row tree root hash as computed by ryhope and mp2",
        );
        IndexNode {
            identifier: table.columns.primary_column().identifier,
            value: U256::from(self.block_number().await),
            row_tree_proof_id: root_proof_key,
            row_tree_hash: table.row.root_data().unwrap().hash,
            ..Default::default()
        }
    }
}
