use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, U256},
};
use anyhow::*;
use mp2_common::{eth::ProofQuery, poseidon::empty_poseidon_hash, utils::ToFields, CHasher, F};
use mp2_test::cells_tree::{build_cell_tree, CellTree, MerkleCellTree, TestCell as Cell};
use mp2_v1::{api, api::CircuitInput, values_extraction::compute_leaf_single_id};
use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
use ryhope::{
    storage::updatetree::{Next, UpdateTree},
    tree::TreeTopology,
};

use crate::common::{cell_tree_proof_to_hash, rowtree::RowTreeKey, TestContext};

use super::{
    cases::TableSourceSlot,
    proof_storage::{BlockPrimaryIndex, CellProofIdentifier, ProofKey, ProofStorage},
    rowtree::Row,
    table::TableID,
};

impl<P: ProofStorage> TestContext<P> {
    /// Given a [`MerkleCellTree`], recursively prove its hash and returns the storage key
    /// associated to the root proof
    async fn prove_cell_tree(
        &mut self,
        table_id: &TableID,
        t: &MerkleCellTree,
        ut: UpdateTree<<CellTree as TreeTopology>::Key>,
    ) -> CellProofIdentifier<BlockPrimaryIndex> {
        // THIS can panic but for block number it should be fine on 64bit platforms...
        // unwrap is safe since we know it is really a block number and not set to Latest or stg
        let block_key = self.block_number().await as BlockPrimaryIndex;
        // Store the proofs here for the tests; will probably be done in S3 for
        // prod.
        let mut workplan = ut.into_workplan();

        while let Some(Next::Ready(k)) = workplan.next() {
            let (context, cell) = t.fetch_with_context(&k);

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
                    primary: block_key,
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
                        cell.id,
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
        let root = t.root().unwrap();
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
        table_id: &TableID,
        cells: Vec<Cell>,
    ) -> (MerkleCellTree, Row) {
        // NOTE: the sec. index slot is assumed to be the first.
        let (cell_tree, cell_tree_ut) =
            build_cell_tree(&cells[1..]).expect("failed to create cell tree");
        let root_key = self
            .prove_cell_tree(table_id, &cell_tree, cell_tree_ut)
            .await;
        let cell_root_proof = self
            .storage
            .get_proof(&ProofKey::Cell(root_key.clone()))
            .unwrap();
        let tree_hash = cell_tree.root_data().unwrap().hash;
        let proved_hash = cell_tree_proof_to_hash(&cell_root_proof);
        assert_eq!(
            tree_hash, proved_hash,
            "mismatch between cell tree root hash as computed by ryhope and mp2",
        );

        (
            cell_tree,
            Row {
                k: RowTreeKey {
                    // the 0th cell value is the secondary index
                    value: cells[0].value,
                    // there is always only one row in the scalar slots table
                    id: 0,
                },
                cell_tree_root_proof_id: root_key,
                cell_tree_root_hash: tree_hash,
                min: cells[0].value,
                max: cells[0].value,
                cells,
                hash: Default::default(),
            },
        )
    }
}
