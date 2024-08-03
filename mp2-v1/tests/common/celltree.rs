use std::hash::Hash;

use alloy::primitives::{Address, U256};
use anyhow::*;
use log::{debug, info};
use mp2_common::proof::ProofWithVK;
use mp2_v1::{
    api::{self, CircuitInput},
    indexing::{
        block::BlockPrimaryIndex,
        cell::{CellTreeKey, MerkleCellTree},
        row::{CellCollection, Row, RowPayload, RowTreeKey},
    },
    values_extraction::identifier_single_var_column,
};
use ryhope::{
    storage::updatetree::{Next, UpdateTree},
    tree::{sbbst, TreeTopology},
};
use serde::{Deserialize, Serialize};

use crate::common::{cell_tree_proof_to_hash, TestContext};

use super::{
    proof_storage::{CellProofIdentifier, ProofKey, ProofStorage},
    table::{CellsUpdateResult, Table, TableColumns, TableID},
};

impl<P: ProofStorage> TestContext<P> {
    /// Given a [`MerkleCellTree`], recursively prove its hash and returns the storage key
    /// associated to the root proof
    /// The row key is used for (a) saving the new proofs to the storage (b) loading the previous
    /// proofs.
    /// Note that since all previous proofs have been moved to this new key (in case of secondary
    /// index update), then we can search previous proofs under this key.
    fn prove_cell_tree(
        &mut self,
        table: &Table,
        primary: BlockPrimaryIndex,
        // The row at which the previous cells tree was attached to
        previous_row: Row<BlockPrimaryIndex>,
        // the new row key for this new cells tree. It can be the same as the key of the previous
        // row if there has been no change in the secondary index value.
        new_row_key: RowTreeKey,
        tree: MerkleCellTree,
        ut: UpdateTree<CellTreeKey>,
    ) -> CellTreeKey {
        let table_id = &table.id;
        let table_columns = &table.columns;
        // Store the proofs here for the tests; will probably be done in S3 for
        // prod.
        let mut workplan = ut.into_workplan();

        let find_primary = |k: CellTreeKey| -> BlockPrimaryIndex {
            if previous_row == Default::default() {
                return primary;
            }
            // Here, we need to find the primary index over which this children proof have
            // been generated. To do this, we need to determine the column ID corresponding to
            // the index of the child key. We do this by looking up the table definition.
            // Then from this column ID, we can look in the previous row payload, the
            // corresponding primary index stored for this child cell.
            let child_column_id = table_columns
                .column_id_of_cells_index(k)
                .expect("invalid table index <-> id definition");
            previous_row
                .payload
                .cells
                .find_by_column(child_column_id)
                .map(|c| c.primary)
                .expect("unable to find cell with given column id")
        };

        while let Some(Next::Ready(k)) = workplan.next() {
            let (context, cell) = tree.fetch_with_context(&k);

            let proof = if context.is_leaf() {
                // Prove a leaf
                let inputs = CircuitInput::CellsTree(
                    verifiable_db::cells_tree::CircuitInput::leaf(cell.id, cell.value),
                );
                api::generate_proof(self.params(), inputs).expect("while proving leaf")
            } else if context.right.is_none() {
                // Prove a partial node - only care about the left side since sbbst has this nice
                // property
                let child_primary = find_primary(context.left.unwrap());
                let proof_key = CellProofIdentifier {
                    table: table_id.clone(),
                    secondary: previous_row.k.clone(),
                    primary: child_primary,
                    tree_key: context.left.unwrap(),
                };
                let left_proof = self
                    .storage
                    .get_proof_exact(&ProofKey::Cell(proof_key))
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
                    secondary: previous_row.k.clone(),
                    primary: find_primary(context.left.unwrap()),
                    tree_key: context.left.unwrap(),
                };
                let right_proof_key = CellProofIdentifier {
                    table: table_id.clone(),
                    secondary: previous_row.k.clone(),
                    primary: find_primary(context.right.unwrap()),
                    tree_key: context.right.unwrap(),
                };

                let left_proof = self
                    .storage
                    .get_proof_exact(&ProofKey::Cell(left_proof_key))
                    .expect("UT guarantees proving in order");
                let right_proof = self
                    .storage
                    .get_proof_exact(&ProofKey::Cell(right_proof_key))
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
                secondary: new_row_key.clone(),
                primary,
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
            secondary: new_row_key.clone(),
            primary,
            tree_key: root,
        };

        // just checking the storage is there
        let _ = self
            .storage
            .get_proof_exact(&ProofKey::Cell(root_proof_key.clone()))
            .unwrap();
        root
    }

    /// Generate and prove a [`MerkleCellTree`] encoding the content of the
    /// given slots for the contract located at `contract_address`.
    // NOTE: the 0th column is assumed to be the secondary index.
    pub fn prove_cells_tree(
        &mut self,
        table: &Table,
        primary: BlockPrimaryIndex,
        // The row that held the cell tree before it is updated. This is necessary to fetch information related to
        // the location of the cells proofs.
        previous_row: Row<BlockPrimaryIndex>,
        // All the new cells expected in the row, INCLUDING the secondary index
        // Note this is just needed to put inside the returned JSON Row payload, it's not
        // processed
        all_cells: CellCollection<BlockPrimaryIndex>,
        cells_update: CellsUpdateResult,
    ) -> RowPayload<BlockPrimaryIndex> {
        // sanity check
        assert!(previous_row.k == cells_update.previous_row_key);
        self.move_cells_proof_to_new_row(&table.id, primary, &cells_update)
            .expect("unable to move cells tree proof:");
        let tree_hash = cells_update.latest.root_data().unwrap().hash;
        let root_key = self.prove_cell_tree(
            &table,
            primary,
            previous_row,
            cells_update.new_row_key.clone(),
            cells_update.latest,
            cells_update.to_update,
        );
        let root_proof_key = CellProofIdentifier {
            primary,
            table: table.id.clone(),
            secondary: cells_update.new_row_key,
            tree_key: root_key,
        };
        let cell_root_proof = self
            .storage
            .get_proof_exact(&ProofKey::Cell(root_proof_key.clone()))
            .unwrap();
        let proved_hash = cell_tree_proof_to_hash(&cell_root_proof);
        assert_eq!(
            tree_hash, proved_hash,
            "mismatch between cell tree root hash as computed by ryhope and mp2",
        );

        RowPayload {
            secondary_index_column: table.columns.secondary_column().identifier,
            cell_root_key: root_key,
            cell_root_hash: tree_hash,
            cell_root_column: table
                .columns
                .column_id_of_cells_index(root_key)
                .expect("unable to find column id of root cells"),
            cells: all_cells,
            ..Default::default()
        }
    }

    /// Traverse the new cells tree, look at all the proofs already existing and move them to the
    /// new row tree key. If the new row tree key is the same as the old one (i.e. there has been
    /// no secondary index update), then this is a no-op.
    fn move_cells_proof_to_new_row(
        &mut self,
        table_id: &TableID,
        primary: BlockPrimaryIndex,
        cells_update: &CellsUpdateResult,
    ) -> Result<()> {
        if cells_update.previous_row_key == cells_update.new_row_key {
            info!("NOT moving cells tree since previous row key does not change");
            return Ok(());
        }
        if cells_update.previous_row_key == Default::default() {
            info!("NOT moving cells tree since it is a first time insertion");
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
                        primary,
                        tree_key: key,
                    });
                    let new_proof_key = ProofKey::Cell(CellProofIdentifier {
                        table: table_id.clone(),
                        secondary: cells_update.new_row_key.clone(),
                        primary,
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
        info!(
            "Moved all cells tree proof from old {:?} to new {:?}",
            cells_update.previous_row_key, cells_update.new_row_key
        );
        Ok(())
    }
}
