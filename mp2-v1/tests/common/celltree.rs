use anyhow::*;
use futures::{stream, StreamExt};
use log::{debug, info};
use mp2_common::proof::ProofWithVK;
use mp2_v1::{
    api::{self, CircuitInput},
    indexing::{
        block::BlockPrimaryIndex,
        cell::{CellTreeKey, MerkleCellTree},
        row::{CellCollection, Row, RowPayload, RowTreeKey},
    },
};
use plonky2::plonk::config::GenericHashOut;
use ryhope::storage::{
    updatetree::{Next, UpdateTree},
    RoEpochKvStorage,
};
use verifiable_db::cells_tree;

use crate::common::{cell_tree_proof_to_hash, TestContext};

use super::{
    proof_storage::{CellProofIdentifier, ProofKey, ProofStorage},
    table::{CellsUpdateResult, Table, TableID},
};

impl TestContext {
    /// Given a [`MerkleCellTree`], recursively prove its hash and returns the storage key
    /// associated to the root proof
    /// The row key is used for (a) saving the new proofs to the storage (b) loading the previous
    /// proofs.
    /// Note that since all previous proofs have been moved to this new key (in case of secondary
    /// index update), then we can search previous proofs under this key.
    async fn prove_cell_tree(
        &mut self,
        table: &Table,
        primary: BlockPrimaryIndex,
        // The row at which the previous cells tree was attached to
        previous_row: Row<BlockPrimaryIndex>,
        // the new row key for this new cells tree. It can be the same as the key of the previous
        // row if there has been no change in the secondary index value.
        new_row_key: RowTreeKey,
        tree: MerkleCellTree<BlockPrimaryIndex>,
        ut: UpdateTree<CellTreeKey>,
    ) -> CellTreeKey {
        let previous_row_key = match previous_row == Default::default() {
            true => new_row_key.clone(),
            false => previous_row.k.clone(),
        };
        let table_id = &table.public_name;
        // Store the proofs here for the tests; will probably be done in S3 for
        // prod.
        let mut workplan = ut.into_workplan();

        while let Some(Next::Ready(wk)) = workplan.next() {
            let k = &wk.k;
            let (context, cell) = tree.fetch_with_context(&k).await;

            let proof = if context.is_leaf() {
                debug!(
                    "MP2 Proving Cell Tree hash for id {:?} - value {:?} -> {:?}",
                    cell.identifier(),
                    cell.value(),
                    hex::encode(cell.hash.0)
                );
                let inputs = CircuitInput::CellsTree(
                    verifiable_db::cells_tree::CircuitInput::leaf(cell.identifier(), cell.value()),
                );
                self.b.bench("indexing::cell_tree::leaf", || {
                    api::generate_proof(self.params(), inputs)
                })
            } else if context.right.is_none() {
                // Prove a partial node - only care about the left side since sbbst has this nice
                // property
                let left_key = context.left.unwrap();
                let left_node = tree.fetch(&left_key).await;
                let proof_key = CellProofIdentifier {
                    table: table_id.clone(),
                    secondary: previous_row_key.clone(),
                    primary: left_node.primary,
                    tree_key: left_key,
                };
                let left_proof = self
                    .storage
                    .get_proof_exact(&ProofKey::Cell(proof_key))
                    .expect("UT guarantees proving in order");
                let inputs =
                    CircuitInput::CellsTree(verifiable_db::cells_tree::CircuitInput::partial(
                        cell.identifier(),
                        cell.value(),
                        left_proof.clone(),
                    ));
                debug!(
                    "MP2 Proving Cell Tree PARTIAL for id {:?} - value {:?} -> {:?} --> LEFT CHILD HASH {:?}",
                    cell.identifier(),
                    cell.value(),
                    hex::encode(cell.hash.0),
                    hex::encode(cells_tree::extract_hash_from_proof(&left_proof).map(|c|c.to_bytes()).unwrap())
                );

                self.b.bench("indexing::cell_tree::partial", || {
                    api::generate_proof(self.params(), inputs).context("cell tree partial node")
                })
            } else {
                // Prove a full node.
                let left_key = context.left.unwrap();
                let left_node = tree.fetch(&left_key).await;
                let left_proof_key = CellProofIdentifier {
                    table: table_id.clone(),
                    secondary: previous_row_key.clone(),
                    primary: left_node.primary,
                    tree_key: context.left.unwrap(),
                };
                let right_key = context.right.unwrap();
                let right_node = tree.fetch(&right_key).await;
                let right_proof_key = CellProofIdentifier {
                    table: table_id.clone(),
                    secondary: previous_row_key.clone(),
                    primary: right_node.primary,
                    tree_key: right_key,
                };

                let left_proof = self
                    .storage
                    .get_proof_exact(&ProofKey::Cell(left_proof_key))
                    .expect("UT guarantees proving in order");
                let right_proof = self
                    .storage
                    .get_proof_exact(&ProofKey::Cell(right_proof_key))
                    .expect("UT guarantees proving in order");
                debug!(
                    "MP2 Proving Cell Tree FULL for id {:?} - value {:?} -> {:?} --> LEFT HASH {:?}, RIGHT HASH {:?}",
                    cell.identifier(),
                    cell.value(),
                    hex::encode(cell.hash.0),
                    hex::encode(cells_tree::extract_hash_from_proof(&left_proof).map(|c|c.to_bytes()).unwrap()),
                    hex::encode(cells_tree::extract_hash_from_proof(&right_proof).map(|c|c.to_bytes()).unwrap())
                );

                let inputs =
                    CircuitInput::CellsTree(verifiable_db::cells_tree::CircuitInput::full(
                        cell.identifier(),
                        cell.value(),
                        [left_proof, right_proof],
                    ));

                self.b.bench("indexing::cell_tree::full", || {
                    api::generate_proof(self.params(), inputs).context("while proving full node")
                })
            };
            let generated_proof_key = CellProofIdentifier {
                table: table_id.clone(),
                secondary: new_row_key.clone(),
                primary,
                tree_key: *k,
            };
            let proof = proof.expect("error generating proof");
            let pproof = ProofWithVK::deserialize(&proof).unwrap();
            let pi =
                verifiable_db::cells_tree::PublicInputs::from_slice(&pproof.proof().public_inputs);
            debug!(
                "[+] [+] Merkle SLOT identifier {:?} -> value {} value.digest() = {:?}",
                cell.identifier(),
                cell.value(),
                pi.individual_digest_point()
            );

            self.storage
                .store_proof(ProofKey::Cell(generated_proof_key.clone()), proof.clone())
                .expect("storing should work");

            debug!(
                "STORING CELL PROOF at  {:?} -- hash {:?}",
                generated_proof_key,
                hex::encode(
                    cells_tree::extract_hash_from_proof(&proof)
                        .map(|c| c.to_bytes())
                        .unwrap()
                )
            );
            workplan.done(&wk).unwrap();
        }
        let root = tree.root().await.unwrap();
        let root_data = tree.root_data().await.unwrap();
        let root_proof_key = CellProofIdentifier {
            table: table_id.clone(),
            secondary: new_row_key.clone(),
            primary: root_data.primary,
            tree_key: root,
        };

        if root_data.primary != primary {
            debug!("Cells Tree UNTOUCHED for row  {new_row_key:?} at block {primary} (root_data.primary{:?})",root_data.primary);
        }

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
    pub async fn prove_cells_tree(
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
        cells_update: CellsUpdateResult<BlockPrimaryIndex>,
    ) -> RowPayload<BlockPrimaryIndex> {
        // sanity check
        assert!(previous_row.k == cells_update.previous_row_key);
        // We need to (a) move the proofs to the new (new_row_key, primary) identifier
        // then (b) update all the impacted cells to also have this new information about the new
        // primary index
        self.move_cells_proof_to_new_row(&table.public_name.clone(), primary, &cells_update)
            .await
            .expect("unable to move cells tree proof:");
        // set the primary index for all cells that are in the update plan to the new primary
        // index, since all of them will be reproven
        // We have to do this after updating cell tree because we don't know yet what are the
        // updated nodes before we update the tree.
        // NOTE: might be good to know this before doing the update, like a "blank run", feature on
        // ryhope
        let must_move_all_proofs = !(cells_update.previous_row_key == cells_update.new_row_key
            || cells_update.previous_row_key == Default::default());
        // impacted keys by the update
        let impacted_keys = cells_update.to_update.impacted_keys();
        println!(
            "  -- -CELL TREE impacted keys in new update: {:?}",
            cells_update.to_update.impacted_keys()
        );
        let updated_cells = CellCollection(
            all_cells
                .0
                .iter()
                .map(|(id, cell_info)| {
                    let mut new_cell = cell_info.clone();
                    // only move the cells tree proof of the actual cells, not the secondary index !
                    // CellsCollection is a bit weird because it has to contain as well the secondary
                    // index to be able to search in it in JSON
                    if *id == table.columns.secondary_column().identifier {
                        return (*id, new_cell);
                    }

                    let tree_key = table.columns.cells_tree_index_of(*id);
                    println!(
                        " --- CELL TREE key {} index of {id} vs secondary id {} vs table.secondary_id {}",
                        tree_key,
                        previous_row.payload.secondary_index_column,
                        table.columns.secondary.identifier
                    );
                    // we need to update the primary on the impacted cells at least, OR on all the cells if
                    // we are moving all the proofs to a new row key which happens when doing an DELETE +
                    // INSERT
                    if must_move_all_proofs || impacted_keys.contains(&tree_key) {
                        new_cell.primary = primary;
                        debug!("CELL INFO: Updated key {tree_key} to new block {primary}")
                    }
                    (*id, new_cell)
                })
                .collect(),
        );
        // (c) reconstruct key with those new updated cell info
        let updated_cell_tree = table.construct_cell_tree(&updated_cells).await;
        let tree_hash = cells_update.latest.root_data().await.unwrap().hash;
        let root_key = self
            .prove_cell_tree(
                table,
                primary,
                previous_row,
                cells_update.new_row_key.clone(),
                updated_cell_tree,
                cells_update.to_update,
            )
            .await;
        let root_proof_key = CellProofIdentifier {
            primary,
            table: table.public_name.clone(),
            secondary: cells_update.new_row_key,
            tree_key: root_key,
        };
        let cell_root_proof = self
            .storage
            .get_proof_exact(&ProofKey::Cell(root_proof_key.clone()))
            .unwrap();
        let proved_hash = cell_tree_proof_to_hash(&cell_root_proof);
        assert_eq!(
            hex::encode(tree_hash.0),
            hex::encode(proved_hash.0),
            "mismatch between cell tree root hash as computed by ryhope and mp2",
        );

        RowPayload {
            secondary_index_column: table.columns.secondary_column().identifier,
            cell_root_key: Some(root_key),
            cell_root_hash: Some(tree_hash),
            cell_root_column: Some(
                table
                    .columns
                    .column_id_of_cells_index(root_key)
                    .expect("unable to find column id of root cells"),
            ),
            cells: updated_cells,
            ..Default::default()
        }
    }

    /// Traverse the new cells tree, look at all the proofs already existing and move them to the
    /// new row tree key. If the new row tree key is the same as the old one (i.e. there has been
    /// no secondary index update), then this is a no-op.
    async fn move_cells_proof_to_new_row(
        &mut self,
        table_id: &TableID,
        primary: BlockPrimaryIndex,
        cells_update: &CellsUpdateResult<BlockPrimaryIndex>,
    ) -> Result<()> {
        if cells_update.is_same_row() {
            info!("NOT moving cells tree since previous row key does not change");
            return Ok(());
        }
        if cells_update.is_new_row() {
            info!("NOT moving cells tree since it is a first time insertion");
            return Ok(());
        }

        let mut to_move = vec![cells_update
            .latest
            .root()
            .await
            .expect("can't get root of new cells tree")];
        // traverse key in DFS style
        struct Return {
            before: ProofKey,
            after: ProofKey,
            children: Vec<CellTreeKey>,
        }
        while !to_move.is_empty() {
            let new_nodes = stream::iter(to_move.clone())
                .then(|key| async move {
                    let previous_node = cells_update.latest.fetch(&key).await;
                    let previous_proof_key = CellProofIdentifier {
                        table: table_id.clone(),
                        secondary: cells_update.previous_row_key.clone(),
                        // take from where it has been proven (previous_row, any_block_in_the_past)
                        primary: previous_node.primary,
                        tree_key: key,
                    };
                    let new_proof_key = CellProofIdentifier {
                        table: table_id.clone(),
                        secondary: cells_update.new_row_key.clone(),
                        // and put it to (new_row,new_block) as if it was a a new proving from
                        // scratch
                        primary,
                        tree_key: key,
                    };
                    debug!("CELL PROOFS MOVING: cell key {key} from (block {:?} - row_key {:?} to --> (block {:?}, row_key {:?})",previous_proof_key.primary,previous_proof_key.secondary,new_proof_key.primary,new_proof_key.secondary);
                    // look at the children to move _all_ the cell tree proofs for all the proofs
                    // that exist
                    let children = stream::iter(match cells_update.latest.node_context(&key).await {
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
                    }).collect::<Vec<_>>().await;
                    Return {
                       before: ProofKey::Cell(previous_proof_key),
                        after: ProofKey::Cell(new_proof_key),
                        children,
                    }
                })
                .collect::<Vec<_>>().await;
            // move all the proofs. Need to be done separately before of lifetime issues with
            // self.storage that can not be captured in async
            // Should be refactored to have async first storage
            to_move = new_nodes
                .into_iter()
                .flat_map(|r| {
                    self.storage
                        .move_proof(&r.before, &r.after)
                        .expect("can't move proof");
                    r.children
                })
                .collect();
        }
        info!(
            "Moved all cells tree proof from old {:?} to new {:?}",
            cells_update.previous_row_key, cells_update.new_row_key
        );
        Ok(())
    }
}
