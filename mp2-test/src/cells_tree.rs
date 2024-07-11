//! Cells tree test helper functions

use ethers::types::U256;
use mp2_common::poseidon::empty_poseidon_hash;
use mp2_common::{poseidon::H, utils::ToFields, F};
use plonky2::{hash::hash_types::HashOut, plonk::config::Hasher};
use ryhope::{
    storage::{memory::InMemory, EpochKvStorage, TreeTransactionalStorage},
    tree::sbbst,
    MerkleTreeKvDb, NodePayload,
};
use serde::{Deserialize, Serialize};
use std::iter;

type CellTree = sbbst::Tree;
type CellStorage = InMemory<CellTree, TestCell>;
type MerkleCellTree = MerkleTreeKvDb<CellTree, TestCell, CellStorage>;

/// Test node of the cells tree
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestCell {
    /// The unique identifier of the cell, derived from the contract it comes
    /// from and its slot in its storage.
    pub id: F,
    /// The value stored in the cell
    pub value: U256,
    /// The hash of this node in the tree
    pub hash: HashOut<F>,
}

impl NodePayload for TestCell {
    fn aggregate<'a, I: Iterator<Item = Option<Self>>>(&mut self, children: I) {
        // H(H(left_child) || H(right_child) || id || value)
        let inputs: Vec<_> = children
            .into_iter()
            .map(|c| c.map(|x| x.hash).unwrap_or_else(|| *empty_poseidon_hash()))
            .flat_map(|x| x.elements.into_iter())
            // ID
            .chain(iter::once(self.id))
            // Value
            .chain(self.value.to_fields().into_iter())
            .collect();

        self.hash = H::hash_no_pad(&inputs);
    }
}

/// Compute the expected root hash of constructed cell tree.
pub fn compute_cells_tree_hash(cells: &[TestCell]) -> HashOut<F> {
    let mut cell_tree = MerkleCellTree::create((0, 0), ()).unwrap();

    cell_tree
        .in_transaction(|t| {
            for (i, cell) in cells.iter().enumerate() {
                // SBBST starts at 1, not 0. Note though this index is not important
                // since at no point we are looking up value per index in the cells
                // tree we always look at the entire row at the row tree level.
                t.store(i + 1, cell.to_owned())?;
            }
            Ok(())
        })
        .unwrap();

    cell_tree.root_data().unwrap().hash
}
