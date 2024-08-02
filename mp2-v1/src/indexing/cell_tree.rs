use std::iter;

use alloy::primitives::U256;
use derive_more::Deref;
use mp2_common::{
    poseidon::{empty_poseidon_hash, H},
    types::HashOutput,
    utils::ToFields,
    F,
};
use plonky2::{
    field::types::Field,
    hash::hash_types::HashOut,
    plonk::config::{GenericHashOut, Hasher},
};
use ryhope::{
    tree::{sbbst, TreeTopology},
    NodePayload,
};
use serde::{Deserialize, Serialize};

pub type CellTree = sbbst::Tree;
pub type CellTreeKey = <CellTree as TreeTopology>::Key;

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

impl Cell {
    /// Returns a new cell from the column identifier and the value.
    /// NOTE: The value MUST be encoded as big endian.
    pub fn new(id: u64, value: &[u8]) -> Self {
        Self {
            id,
            value: U256::from_be_slice(value),
        }
    }
}

/// TreeCell is the node stored in the cells tree. It contains a cell and a hash of the subtree
/// rooted at the cell in the cells tree.
#[derive(Clone, Debug, Default, Serialize, Deserialize, Deref)]
pub struct TreeCell {
    #[deref]
    cell: Cell,
    /// The hash of this node in the cells tree
    pub hash: HashOutput,
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
            .map(|c| {
                c.map(|x| HashOut::from_bytes(&x.hash.0))
                    .unwrap_or_else(|| *empty_poseidon_hash())
            })
            .flat_map(|x| x.elements.into_iter())
            // ID
            .chain(iter::once(F::from_canonical_u64(self.id)))
            // Value
            .chain(self.value.to_fields())
            .collect();

        self.hash = HashOutput(H::hash_no_pad(&inputs).to_bytes().try_into().unwrap());
    }
}
