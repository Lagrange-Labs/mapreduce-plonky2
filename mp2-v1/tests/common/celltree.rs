use anyhow::*;
use ethers::types::{Address, U256};
use mp2_common::{eth::ProofQuery, poseidon::empty_poseidon_hash, utils::ToFields, CHasher, F};
use mp2_test::cells_tree::{build_cell_tree, CellTree, MerkleCellTree, TestCell as Cell};
use mp2_v1::{api, api::CircuitInput, values_extraction::compute_leaf_single_id};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::HashOut, hashing::hash_n_to_hash_no_pad},
    plonk::config::Hasher,
};
use ryhope::{
    storage::{
        memory::InMemory,
        updatetree::{Next, UpdateTree},
        EpochKvStorage, TreeTransactionalStorage,
    },
    tree::{sbbst, TreeTopology},
    MerkleTreeKvDb, NodePayload,
};
use serde::{Deserialize, Serialize};

use crate::common::{cell_tree_proof_to_hash, rowtree::RowTreeKey, TestContext};

use super::{
    proof_storage::{BlockPrimaryIndex, CellProofIdentifier, ProofKey, ProofStorage, TableID},
    rowtree::Row,
};

impl TestContext {
    /// Fetch the values and build the identifiers from a list of slots to
    /// generate [`Cell`]s that will then be encoded as a [`MerkleCellTree`].
    pub async fn build_cells(&self, contract_address: &Address, slots: &[u8]) -> Vec<Cell> {
        let mut cells = Vec::new();
        for slot in slots {
            let query = ProofQuery::new_simple_slot(*contract_address, *slot as usize);
            let id = GoldilocksField::from_canonical_u64(compute_leaf_single_id(
                *slot,
                contract_address,
            ));
            let value = self
                .query_mpt_proof(&query, self.get_block_number())
                .await
                .storage_proof[0]
                .value;
            cells.push(Cell {
                id,
                value,
                // we don't know yet its hash because the tree is not constructed
                // this will be done by the Aggregate trait
                hash: Default::default(),
            });
        }

        cells
    }

    /// Given a [`MerkleCellTree`], recursively prove its hash and returns the storage key
    /// associated to the root proof
    pub async fn prove_cell_tree<P: ProofStorage>(
        &self,
        table_id: &TableID,
        t: &MerkleCellTree,
        ut: UpdateTree<<CellTree as TreeTopology>::Key>,
        storage: &mut P,
    ) -> CellProofIdentifier<BlockPrimaryIndex> {
        // THIS can panic but for block number it should be fine on 64bit platforms...
        // unwrap is safe since we know it is really a block number and not set to Latest or stg
        let block_key: BlockPrimaryIndex =
            self.block_number.as_number().unwrap().try_into().unwrap();
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
                let left_proof = storage
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

                let left_proof = storage
                    .get_proof(&ProofKey::Cell(left_proof_key))
                    .expect("UT guarantees proving in order");
                let right_proof = storage
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

            storage
                .store_proof(ProofKey::Cell(generated_proof_key), proof)
                .expect("storing should work");

            workplan.done(&k).unwrap();
        }
        let root = t.tree().root().unwrap();
        let root_proof_key = CellProofIdentifier {
            table: table_id.clone(),
            primary: block_key,
            tree_key: root,
        };

        // just checking the storage is there
        let _ = storage
            .get_proof(&ProofKey::Cell(root_proof_key.clone()))
            .unwrap();
        root_proof_key
    }

    /// Generate and prove a [`MerkleCellTree`] encoding the content of the
    /// given slots for the contract located at `contract_address`.
    pub async fn build_and_prove_celltree<P: ProofStorage>(
        &self,
        table_id: &TableID,
        contract_address: &Address,
        slots: &[u8],
        storage: &mut P,
    ) -> Row {
        let cells = self.build_cells(contract_address, slots).await;
        // NOTE: the sec. index slot is assumed to be the first.
        let (cell_tree, cell_tree_ut) = build_cell_tree(&cells[1..])
            .expect("failed to create cell tree");
        let root_key = self
            .prove_cell_tree(&table_id, &cell_tree, cell_tree_ut, storage)
            .await;
        let cell_root_proof = storage
            .get_proof(&ProofKey::Cell(root_key.clone()))
            .unwrap();
        let tree_hash = cell_tree.root_data().unwrap().hash;
        let proved_hash = cell_tree_proof_to_hash(&cell_root_proof);
        assert_eq!(
            tree_hash, proved_hash,
            "mismatch between cell tree root hash as computed by ryhope and mp2",
        );

        Row {
            k: RowTreeKey {
                // the 0th cell value is the secondary index
                value: cells[0].value.clone(),
                // there is always only one row in the scalar slots table
                id: 0,
            },
            cell_tree_root_proof_id: root_key,
            cell_tree_root_hash: tree_hash,
            min: cells[0].value.clone(),
            max: cells[0].value.clone(),
            cells,
            hash: Default::default(),
        }
    }
}
