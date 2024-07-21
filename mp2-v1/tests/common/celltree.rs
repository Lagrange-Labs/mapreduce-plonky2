use std::iter;

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, U256},
};
use anyhow::*;
use mp2_common::{
    eth::ProofQuery,
    poseidon::{empty_poseidon_hash, H},
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

use crate::common::{cell_tree_proof_to_hash, rowtree::RowTreeKey, TestContext};

use super::{
    cases::TableSourceSlot,
    proof_storage::{BlockPrimaryIndex, CellProofIdentifier, ProofKey, ProofStorage},
    rowtree::{CellCollection, Row},
    table::{CellsUpdateResult, Table, TableID},
};

pub type CellTree = sbbst::Tree;
pub type CellTreeKey = <CellTree as TreeTopology>::Key;
type CellStorage = InMemory<CellTree, Cell>;
pub type MerkleCellTree = MerkleTreeKvDb<CellTree, Cell, CellStorage>;

// Just a clone of mp2-test cell tree but "public facing" without any plonky2 related values
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Cell {
    /// The unique identifier of the cell, derived from the contract it comes
    /// from and its slot in its storage.
    pub id: u64,
    /// The value stored in the cell
    pub value: U256,
    /// The hash of this node in the tree
    pub hash: HashOut<F>,
}

impl NodePayload for Cell {
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
    async fn prove_cell_tree(
        &mut self,
        table_id: &TableID,
        tree: MerkleCellTree,
        ut: UpdateTree<CellTreeKey>,
    ) -> CellProofIdentifier<BlockPrimaryIndex> {
        // THIS can panic but for block number it should be fine on 64bit platforms...
        // unwrap is safe since we know it is really a block number and not set to Latest or stg
        let block_key = self.block_number().await as BlockPrimaryIndex;
        // Store the proofs here for the tests; will probably be done in S3 for
        // prod.
        let mut workplan = ut.into_workplan();

        while let Some(Next::Ready(k)) = workplan.next() {
            let (context, cell) = tree.fetch_with_context(&k);

            let proof = if context.is_leaf() {
                // Prove a leaf
                let inputs =
                    CircuitInput::CellsTree(verifiable_db::cells_tree::CircuitInput::leaf(
                        F::from_canonical_u64(cell.id),
                        cell.value,
                    ));
                api::generate_proof(self.params(), inputs).expect("while proving leaf")
            } else if context.right.is_none() {
                // Prove a partial node
                let proof_key = CellProofIdentifier {
                    table: table_id.clone(),
                    primary: block_key,
                    tree_key: context.left.unwrap(),
                };
                let left_proof = self
                    .storage
                    .get_proof(&ProofKey::Cell(proof_key))
                    .expect("UT guarantees proving in order");
                let inputs =
                    CircuitInput::CellsTree(verifiable_db::cells_tree::CircuitInput::partial(
                        F::from_canonical_u64(cell.id),
                        cell.value,
                        left_proof,
                    ));
                api::generate_proof(self.params(), inputs).expect("while proving partial node")
            } else {
                // Prove a full node.
                let left_proof_key = CellProofIdentifier {
                    table: table_id.clone(),
                    primary: block_key,
                    tree_key: context.left.unwrap(),
                };
                let right_proof_key = CellProofIdentifier {
                    table: table_id.clone(),
                    primary: block_key,
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
                        F::from_canonical_u64(cell.id),
                        cell.value,
                        [left_proof, right_proof],
                    ));
                api::generate_proof(self.params(), inputs).expect("while proving full node")
            };
            let generated_proof_key = CellProofIdentifier {
                table: table_id.clone(),
                primary: block_key,
                tree_key: k,
            };

            self.storage
                .store_proof(ProofKey::Cell(generated_proof_key), proof)
                .expect("storing should work");

            workplan.done(&k).unwrap();
        }
        let root = tree.root().unwrap();
        let root_proof_key = CellProofIdentifier {
            table: table_id.clone(),
            primary: block_key,
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
    pub async fn prove_cells_tree(
        &mut self,
        table: &Table,
        all_cells: CellCollection,
        cells_update: CellsUpdateResult,
    ) -> Row {
        let tree_hash = cells_update.latest.root_data().unwrap().hash;
        let root_key = self
            .prove_cell_tree(&table.id, cells_update.latest, cells_update.to_update)
            .await;
        let cell_root_proof = self
            .storage
            .get_proof(&ProofKey::Cell(root_key.clone()))
            .unwrap();
        let proved_hash = cell_tree_proof_to_hash(&cell_root_proof);
        assert_eq!(
            tree_hash, proved_hash,
            "mismatch between cell tree root hash as computed by ryhope and mp2",
        );

        Row {
            k: cells_update.key,
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
}
