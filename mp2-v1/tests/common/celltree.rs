use std::iter;

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, U256},
};
use anyhow::*;
use log::{debug, info};
use mp2_common::{
    eth::ProofQuery,
    poseidon::{empty_poseidon_hash, H},
    proof::ProofWithVK,
    types::HashOutput,
    utils::ToFields,
    CHasher, F,
};
use mp2_v1::{api, api::CircuitInput, values_extraction::identifier_single_var_column};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::HashOut,
    plonk::config::Hasher,
};
use ryhope::{
    storage::{
        memory::InMemory,
        updatetree::{Next, UpdateTree},
    },
    tree::{sbbst, TreeTopology},
    MerkleTreeKvDb, NodePayload,
};
use serde::{Deserialize, Serialize};

use crate::common::{cell_tree_proof_to_hash, TestContext};

use super::{
    proof_storage::{BlockPrimaryIndex, CellProofIdentifier, ProofKey, ProofStorage},
    rowtree::{CellCollection, RowPayload, RowTree, RowTreeKey},
    table::{CellsUpdateResult, Table, TableID},
};

use derive_more::Deref;

pub type CellTree = sbbst::Tree;
pub type CellTreeKey = <CellTree as TreeTopology>::Key;
type CellStorage = InMemory<CellTree, TreeCell>;
pub type MerkleCellTree = MerkleTreeKvDb<CellTree, TreeCell, CellStorage>;

/// Cell is the information stored in a specific cell of a specific row.
/// A row node in the row tree contains a vector of such cells.
#[derive(Clone, Default, Debug, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cell {
    /// The unique identifier of the cell, derived from the contract it comes
    /// from and its slot in its storage.
    pub id: u64,
    /// The value stored in the cell
    pub value: U256,
}

/// TreeCell is the node stored in the cells tree. It contains a cell and a hash of the subtree
/// rooted at the cell in the cells tree.
#[derive(Clone, Debug, Default, Serialize, Deserialize, Deref)]
pub struct TreeCell {
    #[deref]
    cell: Cell,
    /// The hash of this node in the cells tree
    pub hash: HashOut<F>,
}

impl From<Cell> for TreeCell {
    fn from(value: Cell) -> Self {
        TreeCell {
            cell: value,
            hash: Default::default(),
        }
    }
}

impl From<&Cell> for TreeCell {
    fn from(value: &Cell) -> Self {
        TreeCell {
            cell: value.clone(),
            hash: Default::default(),
        }
    }
}
impl NodePayload for TreeCell {
    fn aggregate<'a, I: Iterator<Item = Option<Self>>>(&mut self, children: I) {
        // H(H(left_child) || H(right_child) || id || value)
        let inputs: Vec<_> = children
            .into_iter()
            .map(|c| c.map(|x| x.hash).unwrap_or_else(|| *empty_poseidon_hash()))
            .flat_map(|x| x.elements.into_iter())
            // ID
            .chain(iter::once(F::from_canonical_u64(self.id)))
            // Value
            .chain(self.value.to_fields())
            .collect();

        self.hash = H::hash_no_pad(&inputs);
    }
}

impl<P: ProofStorage> TestContext<P> {
    /// Given a [`MerkleCellTree`], recursively prove its hash and returns the storage key
    /// associated to the root proof
    /// The row key is used for (a) saving the new proofs to the storage (b) loading the previous
    /// proofs.
    /// Note that since all previous proofs have been moved to this new key (in case of secondary
    /// index update), then we can search previous proofs under this key.
    fn prove_cell_tree(
        &mut self,
        row_key: RowTreeKey,
        table_id: &TableID,
        tree: MerkleCellTree,
        ut: UpdateTree<CellTreeKey>,
    ) -> CellProofIdentifier {
        // Store the proofs here for the tests; will probably be done in S3 for
        // prod.
        let mut workplan = ut.into_workplan();

        while let Some(Next::Ready(k)) = workplan.next() {
            let (context, cell) = tree.fetch_with_context(&k);

            let proof = if context.is_leaf() {
                // Prove a leaf
                let inputs = CircuitInput::CellsTree(
                    verifiable_db::cells_tree::CircuitInput::leaf(cell.id, cell.value),
                );
                api::generate_proof(self.params(), inputs).expect("while proving leaf")
            } else if context.right.is_none() {
                // Prove a partial node
                let proof_key = CellProofIdentifier {
                    table: table_id.clone(),
                    secondary: row_key.clone(),
                    tree_key: context.left.unwrap(),
                };
                let left_proof = self
                    .storage
                    .get_proof(&ProofKey::Cell(proof_key))
                    .expect("UT guarantees proving in order");
                let inputs =
                    CircuitInput::CellsTree(verifiable_db::cells_tree::CircuitInput::partial(
                        cell.id, cell.value, left_proof,
                    ));
                api::generate_proof(self.params(), inputs).expect("while proving partial node")
            } else {
                // Prove a full node.
                let left_proof_key = CellProofIdentifier {
                    table: table_id.clone(),
                    secondary: row_key.clone(),
                    tree_key: context.left.unwrap(),
                };
                let right_proof_key = CellProofIdentifier {
                    table: table_id.clone(),
                    secondary: row_key.clone(),
                    tree_key: context.right.unwrap(),
                };

                let left_proof = self
                    .storage
                    .get_proof(&ProofKey::Cell(left_proof_key))
                    .expect("UT guarantees proving in order");
                let right_proof = self
                    .storage
                    .get_proof(&ProofKey::Cell(right_proof_key))
                    .expect("UT guarantees proving in order");
                let inputs =
                    CircuitInput::CellsTree(verifiable_db::cells_tree::CircuitInput::full(
                        cell.id,
                        cell.value,
                        [left_proof, right_proof],
                    ));
                api::generate_proof(self.params(), inputs).expect("while proving full node")
            };
            let generated_proof_key = CellProofIdentifier {
                table: table_id.clone(),
                secondary: row_key.clone(),
                tree_key: k,
            };

            let pproof = ProofWithVK::deserialize(&proof).unwrap();
            let pi =
                verifiable_db::cells_tree::PublicInputs::from_slice(&pproof.proof().public_inputs);
            debug!(
                "[+] [+] Merkle SLOT identifier {:?} -> value {} value.digest() = {:?}",
                cell.id,
                cell.value,
                pi.digest_point()
            );

            self.storage
                .store_proof(ProofKey::Cell(generated_proof_key), proof)
                .expect("storing should work");

            workplan.done(&k).unwrap();
        }
        let root = tree.root().unwrap();
        let root_proof_key = CellProofIdentifier {
            table: table_id.clone(),
            secondary: row_key.clone(),
            tree_key: root,
        };

        // just checking the storage is there
        let _ = self
            .storage
            .get_proof(&ProofKey::Cell(root_proof_key.clone()))
            .unwrap();
        root_proof_key
    }

    /// Generate and prove a [`MerkleCellTree`] encoding the content of the
    /// given slots for the contract located at `contract_address`.
    // NOTE: the 0th column is assumed to be the secondary index.
    pub fn prove_cells_tree(
        &mut self,
        table: &Table,
        // All the new cells expected in the row, INCLUDING the secondary index
        // Note this is just needed to put inside the returned JSON Row payload, it's not
        // processed
        all_cells: CellCollection,
        cells_update: CellsUpdateResult,
    ) -> RowPayload {
        self.move_cells_proof_to_new_row(&table.id, &cells_update)
            .expect("unable to move cells tree proof:");
        let tree_hash = cells_update.latest.root_data().unwrap().hash;
        let root_key = self.prove_cell_tree(
            cells_update.new_row_key,
            &table.id,
            cells_update.latest,
            cells_update.to_update,
        );
        let cell_root_proof = self
            .storage
            .get_proof(&ProofKey::Cell(root_key.clone()))
            .unwrap();
        let proved_hash = cell_tree_proof_to_hash(&cell_root_proof);
        assert_eq!(
            tree_hash, proved_hash,
            "mismatch between cell tree root hash as computed by ryhope and mp2",
        );

        RowPayload {
            cell_tree_root_proof_id: root_key,
            cell_tree_root_hash: tree_hash,
            cells: all_cells,
            // these values are set during the tree update
            // so we fill by default
            min: U256::default(),
            max: U256::default(),
            hash: Default::default(),
        }
    }

    /// Traverse the new cells tree, look at all the proofs already existing and move them to the
    /// new row tree key. If the new row tree key is the same as the old one (i.e. there has been
    /// no secondary index update), then this is a no-op.
    fn move_cells_proof_to_new_row(
        &mut self,
        table_id: &TableID,
        cells_update: &CellsUpdateResult,
    ) -> Result<()> {
        if cells_update.previous_row_key == cells_update.new_row_key {
            // nothing to do here, all proofs are already under the correct row
            return Ok(());
        }

        let mut to_move = vec![cells_update
            .latest
            .root()
            .expect("can't get root of new cells tree")];
        // traverse key in DFS style
        while !to_move.is_empty() {
            let new_nodes = to_move
                .into_iter()
                .flat_map(|key| {
                    let previous_proof_key = ProofKey::Cell(CellProofIdentifier {
                        table: table_id.clone(),
                        secondary: cells_update.previous_row_key.clone(),
                        tree_key: key,
                    });
                    let new_proof_key = ProofKey::Cell(CellProofIdentifier {
                        table: table_id.clone(),
                        secondary: cells_update.new_row_key.clone(),
                        tree_key: key,
                    });
                    self.storage
                        .move_proof(&previous_proof_key, &new_proof_key)
                        .expect("unable to move proof from one row key to another");
                    // look at the children to move _all_ the cell tree proofs for all the proofs
                    // that exist
                    match cells_update.latest.node_context(&key) {
                        Some(ctx) => {
                            let mut children = vec![];
                            if let Some(left_key) = ctx.left {
                                children.push(left_key);
                            }
                            if let Some(right_key) = ctx.right {
                                children.push(right_key);
                            }
                            children
                        }
                        None => vec![],
                    }
                })
                .collect::<Vec<_>>();
            to_move = new_nodes;
        }
        info!("Moved all cells tree proof to new row key");
        Ok(())
    }
}
