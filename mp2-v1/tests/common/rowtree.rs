use alloy::primitives::U256;
use anyhow::*;
use log::debug;
use mp2_common::proof::ProofWithVK;
use mp2_v1::{
    api::{self, CircuitInput},
    indexing::{
        block::BlockPrimaryIndex,
        cell::Cell,
        index::IndexNode,
        row::{RowPayload, RowTree, RowTreeKey, ToNonce},
    },
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
use verifiable_db::{cells_tree, row_tree::extract_hash_from_proof};

use crate::common::row_tree_proof_to_hash;

use super::{
    proof_storage::{CellProofIdentifier, ProofKey, ProofStorage, RowProofIdentifier},
    table::{RowUpdateResult, Table},
    TestContext,
};

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
            value: value.0.value(),
            rest: value.1,
        }
    }
}

impl From<&SecondaryIndexCell> for RowTreeKey {
    fn from(value: &SecondaryIndexCell) -> Self {
        RowTreeKey {
            value: value.0.value(),
            rest: value.1.clone(),
        }
    }
}

pub type RowStorage = PgsqlStorage<RowTree, RowPayload<BlockPrimaryIndex>>;
pub type MerkleRowTree = MerkleTreeKvDb<RowTree, RowPayload<BlockPrimaryIndex>, RowStorage>;

impl TestContext {
    /// Given a row tree (i.e. secondary index tree) and its update tree, prove
    /// it.
    pub async fn prove_row_tree(
        &mut self,
        // required to fetch the right row tree proofs during the update, since the key
        // itself is not enough, since there might be multiple proofs with the same key but not
        // for the same block (i.e. not the same data)
        primary: BlockPrimaryIndex,
        table: &Table,
        ut: UpdateTree<RowTreeKey>,
    ) -> Result<RowProofIdentifier<BlockPrimaryIndex>> {
        debug!("PROVE_ROW_TREE -- BEGIN for block {}", primary);
        let t = &table.row;
        let mut workplan = ut.into_workplan();
        while let Some(Next::Ready(wk)) = workplan.next() {
            let k = &wk.k;
            let (context, row) = t.fetch_with_context(&k).await;
            let id = row.secondary_index_column;
            // Sec. index value
            let value = row.secondary_index_value();
            // find where the root cells proof has been stored. This comes from looking up the
            // column id, then searching for the cell info in the row payload about this
            // identifier. We now have the primary index for which the cells proof have been
            // generated.
            let cell_root_primary = row.fetch_cell_root_info().unwrap().primary;
            let cell_proof_key = CellProofIdentifier {
                table: table.name.clone(),
                primary: cell_root_primary,
                tree_key: row.cell_root_key.unwrap(),
                secondary: k.clone(), // the cells proofs is already stored under the new key, even in the
                                      // case of a fresh row, see celltree.rs for more info, see
                                      // celltree.rs for more info
            };
            let cell_tree_proof = self
                .storage
                .get_proof_exact(&ProofKey::Cell(cell_proof_key))
                .expect("should find cell root proof");
            debug!(
                "After fetching cell proof for row key {:?} & primary {}",
                k, primary
            );
            let cell_root_hash_from_proof = cells_tree::extract_hash_from_proof(&cell_tree_proof)
                .unwrap()
                .to_bytes();
            let cell_root_hash_from_row = row.cell_root_hash.clone();
            assert_eq!(
                hex::encode(cell_root_hash_from_proof.clone()),
                hex::encode(cell_root_hash_from_row.unwrap().0),
                "cell root proof from proof vs row is different - cell root info = {:?}, row {:?}",
                row.fetch_cell_root_info(),
                row.cells,
            );

            let proof = if context.is_leaf() {
                // Prove a leaf
                println!(
                    " \n PROVING ROW --> id {:?}, value {:?}, cell_tree_proof hash {:?} - vs row.cell_root_hash {:?}",
                    id,
                    value,
                    hex::encode(cell_root_hash_from_proof.clone()),
                    hex::encode(row.cell_root_hash.unwrap().0)
                );
                let inputs = CircuitInput::RowsTree(
                    verifiable_db::row_tree::CircuitInput::leaf(id, value, cell_tree_proof)
                        .unwrap(),
                );
                debug!("Before proving leaf node row tree key {:?}", k);
                api::generate_proof(self.params(), inputs).expect("while proving leaf")
            } else if context.is_partial() {
                let child_key = context
                    .left
                    .as_ref()
                    .or(context.right.as_ref())
                    .cloned()
                    .unwrap();
                let child_row = table.row.fetch(&child_key).await;

                let proof_key = RowProofIdentifier {
                    table: table.name.clone(),
                    primary: child_row.primary_index_value(),
                    tree_key: child_key,
                };
                // Prove a partial node
                let child_proof = self
                    .storage
                    .get_proof_exact(&ProofKey::Row(proof_key.clone()))
                    .expect("UT guarantees proving in order");

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
                let left_key = context.left.unwrap();
                let left_row = table.row.fetch(&left_key).await;
                let left_proof_key = RowProofIdentifier {
                    table: table.name.clone(),
                    primary: left_row.primary_index_value(),
                    tree_key: left_key,
                };
                let right_key = context.right.unwrap();
                let right_row = table.row.fetch(&right_key).await;
                let right_proof_key = RowProofIdentifier {
                    table: table.name.clone(),
                    primary: right_row.primary_index_value(),
                    tree_key: right_key,
                };

                // Prove a full node: fetch the row proofs of the children
                let left_proof = self
                    .storage
                    .get_proof_exact(&ProofKey::Row(left_proof_key.clone()))
                    .expect("UT guarantees proving in order");
                let right_proof = self
                    .storage
                    .get_proof_exact(&ProofKey::Row(right_proof_key.clone()))
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
                debug!("Before proving full node row tree key {:?}", k);
                api::generate_proof(self.params(), inputs).expect("while proving full node")
            };
            let new_proof_key = RowProofIdentifier {
                table: table.name.clone(),
                // we save the new proof under the new row key
                primary,
                tree_key: k.clone(),
            };

            self.storage
                .store_proof(ProofKey::Row(new_proof_key.clone()), proof.clone())
                .expect("storing should work");

            debug!(
                "Finished row tree key proving {k:?} - stored under proof key {:?} with hash {:?}",
                new_proof_key,
                hex::encode(extract_hash_from_proof(&proof).unwrap().to_bytes())
            );
            workplan.done(&wk).unwrap();
        }
        let root = t.root().await.unwrap();
        let row = table.row.fetch(&root).await;
        let root_proof_key = RowProofIdentifier {
            table: table.name.clone(),
            primary: row.primary_index_value(),
            tree_key: root,
        };

        let p = self
            .storage
            .get_proof_exact(&ProofKey::Row(root_proof_key.clone()))
            .expect("row tree root proof absent");

        let pproof = ProofWithVK::deserialize(&p).unwrap();
        let pi = verifiable_db::row_tree::PublicInputs::from_slice(&pproof.proof().public_inputs);
        debug!(
            "[--] FINAL MERKLE DIGEST VALUE --> {:?} ",
            pi.rows_digest_field()
        );
        if root_proof_key.primary != primary {
            debug!("[--] NO UPDATES on row this turn? row.root().primary = {} vs new primary proving step {}",root_proof_key.primary,primary);
        };

        debug!("PROVE_ROW_TREE -- END for block {}", primary);
        Ok(root_proof_key)
    }

    /// Build and prove the row tree from the [`Row`]s and the secondary index
    /// data (which **must be absent** from the rows).
    /// Returns the identifier of the root proof and the hash of the updated row tree
    /// NOTE:we are simplifying a bit here as we assume the construction of the index tree
    /// is from (a) the block and (b) only one by one, i.e. there is only one IndexNode to return
    /// that have to be inserted. For CSV case, it should return a vector of new inserted nodes.
    pub async fn prove_update_row_tree(
        &mut self,
        primary: BlockPrimaryIndex,
        table: &Table,
        update: RowUpdateResult,
    ) -> Result<IndexNode<BlockPrimaryIndex>> {
        let root_proof_key = self.prove_row_tree(primary, table, update.updates).await?;
        let row_tree_proof = self
            .storage
            .get_proof_exact(&ProofKey::Row(root_proof_key.clone()))
            .unwrap();
        let root_row = table.row.root_data().await.unwrap();
        let tree_hash = root_row.hash.clone();
        let proved_hash = row_tree_proof_to_hash(&row_tree_proof);

        assert_eq!(
            hex::encode(tree_hash.0), hex::encode(proved_hash.0),
            "mismatch between row tree root hash as computed by ryhope and mp2 (row.id {:?}, value {:?} , row.cell_hash {:?})",
            root_row.secondary_index_column, root_row.secondary_index_value(),hex::encode(root_row.cell_root_hash.unwrap().0)

        );
        Ok(IndexNode {
            identifier: table.columns.primary_column().identifier,
            value: U256::from(primary).into(),
            row_tree_root_key: root_proof_key.tree_key,
            row_tree_hash: table.row.root_data().await.unwrap().hash,
            row_tree_root_primary: primary,
            ..Default::default()
        })
    }
}
