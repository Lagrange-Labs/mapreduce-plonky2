//! Cells tree test helper functions

use alloy::primitives::U256;
use anyhow::{Context, Result};
use mp2_common::{
    poseidon::empty_poseidon_hash,
    poseidon::H,
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::ToFields,
    F,
};
use plonky2::field::types::Sample;
use plonky2::{
    hash::hash_types::HashOut,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::config::Hasher,
};
use rand::{thread_rng, Rng};
use ryhope::{
    storage::{memory::InMemory, updatetree::UpdateTree, EpochKvStorage, TreeTransactionalStorage},
    tree::{sbbst, TreeTopology},
    InitSettings, MerkleTreeKvDb, NodePayload,
};
use serde::{Deserialize, Serialize};
use std::iter;

pub type CellTree = sbbst::Tree;
pub type CellTreeKey = <CellTree as TreeTopology>::Key;
type CellStorage = InMemory<CellTree, TestCell>;
pub type MerkleCellTree = MerkleTreeKvDb<CellTree, TestCell, CellStorage>;

/// Test node of the cells tree
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct TestCell {
    /// The unique identifier of the cell, derived from the contract it comes
    /// from and its slot in its storage.
    pub id: F,
    /// The value stored in the cell
    pub value: U256,
    /// The hash of this node in the tree
    pub hash: HashOut<F>,
}

/// The corresponding test cell target
#[derive(Clone, Debug)]
pub struct TestCellTarget {
    pub id: Target,
    pub value: UInt256Target,
}

impl std::fmt::Debug for TestCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "C:{} := {}", self.id, self.value)
    }
}

impl TestCell {
    /// Create a random test cell.
    pub fn random() -> Self {
        let mut rng = thread_rng();

        Self {
            id: F::rand(),
            value: U256::from_limbs(rng.gen::<[u64; 4]>()),
            hash: Default::default(),
        }
    }

    /// Build new `TestCell` from `value` and `id`
    pub fn new(value: U256, id: F) -> Self {
        Self {
            id,
            value,
            hash: HashOut::default(),
        }
    }

    /// Build the test cell target.
    pub fn build(b: &mut CBuilder) -> TestCellTarget {
        let id = b.add_virtual_target();
        let value = b.add_virtual_u256();

        TestCellTarget { id, value }
    }

    /// Assign the test cell target.
    pub fn assign(&self, pw: &mut PartialWitness<F>, t: &TestCellTarget) {
        pw.set_target(t.id, self.id);
        pw.set_u256_target(&t.value, self.value);
    }
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
            .chain(self.value.to_fields())
            .collect();

        self.hash = H::hash_no_pad(&inputs);
    }
}

// NOTE: this is not really aync for now, but will be in the future when Ryhope
// turns async.
pub async fn build_cell_tree(
    row: Vec<TestCell>,
) -> Result<(MerkleCellTree, UpdateTree<<CellTree as TreeTopology>::Key>)> {
    let mut cell_tree = MerkleCellTree::new(InitSettings::Reset(sbbst::Tree::empty()), ())
        .await
        .unwrap();
    let update_tree = cell_tree
        .in_transaction(|t| {
            Box::pin(async move {
                for (i, cell) in row.into_iter().enumerate() {
                    // SBBST starts at 1, not 0. Note though this index is not important
                    // since at no point we are looking up value per index in the cells
                    // tree we always look at the entire row at the row tree level.
                    t.store(i + 1, cell.to_owned()).await?;
                }
                Ok(())
            })
        })
        .await
        .context("while building tree")?;

    Ok((cell_tree, update_tree))
}

/// Compute the expected root hash of constructed cell tree.
pub async fn compute_cells_tree_hash(cells: Vec<TestCell>) -> HashOut<F> {
    if cells.len() == 0 {
        return *empty_poseidon_hash();
    }
    let cell_tree = build_cell_tree(cells).await.unwrap().0;

    cell_tree.root_data().await.unwrap().hash
}
