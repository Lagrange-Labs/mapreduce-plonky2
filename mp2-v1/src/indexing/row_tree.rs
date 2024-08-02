use alloy::primitives::U256;
use anyhow::{ensure, Result};
use derive_more::From;
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
use ryhope::{storage::memory::InMemory, tree::scapegoat, MerkleTreeKvDb, NodePayload};
use serde::{Deserialize, Serialize};

use super::cell_tree::{Cell, CellTreeKey};

pub type RowTree = scapegoat::Tree<RowTreeKey>;
type RowStorage = InMemory<RowTree, RowPayload>;
pub type MerkleRowTree = MerkleTreeKvDb<RowTree, RowPayload, RowStorage>;

pub type RowTreeKeyNonce = Vec<u8>;

pub trait ToNonce {
    fn to_nonce(&self) -> RowTreeKeyNonce;
}

/// A unique identifier of a secondary-indexed row, from the secondary index value and an unique
/// index since secondary index does not have to be unique.
/// THis struct is kept in the JSON row as the "tree key".
#[derive(Clone, Default, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RowTreeKey {
    /// Value of the secondary index of the row
    pub value: U256,
    /// An value such that the pair (value,rest) is unique accross all rows
    pub rest: RowTreeKeyNonce,
}

impl RowTreeKey {
    // Returns a row key from a value and the "nonce". Since in the row tree, multiple rows/nodes
    // can have the same value, we need an additional information such that both combine make an
    // unique identifier for the row.
    // NOTE: the value MUST be encoded as big endian.
    pub fn new(value: &[u8], rest: &[u8]) -> Self {
        Self {
            value: U256::from_be_slice(value),
            rest: rest.to_vec(),
        }
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let b = bincode::serialize(self)?;
        Ok(b)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let s = bincode::deserialize(bytes)?;
        Ok(s)
    }
}

// A collection of cells inserted in the JSON.
// IMPORTANT: This collection MUST CONTAIN the secondary index value, as first element, to easily search
// in JSONB from the SQL.
#[derive(Eq, PartialEq, From, Default, Debug, Clone, Serialize, Deserialize)]
pub struct CellCollection(pub Vec<Cell>);
impl CellCollection {
    /// Return the [`Cell`] containing the sec. index of this row.
    pub fn secondary_index(&self) -> Result<&Cell> {
        ensure!(
            !self.0.is_empty(),
            "secondary_index() called on empty CellCollection"
        );
        Ok(&self.0[0])
    }

    pub fn non_indexed_cells(&self) -> Result<&[Cell]> {
        ensure!(
            !self.0.is_empty(),
            "non_indexed_cells called on empty  CellCollection"
        );
        Ok(&self.0[1..])
    }
    // take all the cells ids on both collections, take the value present in the updated one
    // if it exists, otherwise take from self.
    pub fn merge_with_update(&self, updated_cells: &[Cell]) -> Self {
        if self == &Self::default() {
            return Self(updated_cells.to_vec());
        }
        Self(
            self.0
                .iter()
                .map(|previous_cell| {
                    updated_cells
                        .iter()
                        .find(|new_cell| previous_cell.id == new_cell.id)
                        .unwrap_or(previous_cell)
                })
                .cloned()
                .collect(),
        )
    }
}

/// An utility wrapper to pass around that connects what we put in the JSON description and
/// the actual row key used to insert in the tree
#[derive(Clone, Debug, Default)]
pub struct Row {
    /// A key *uniquely* representing this row in the row tree.
    /// NOTE: this key is **not** the index as understood in the crypto
    /// formalization.
    pub k: RowTreeKey,
    // What is being included in the row JSON
    pub payload: RowPayload,
}
/// Represent a row in one of the virtual tables stored in the zkDB; which
/// encapsulates its cells and the tree they form.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RowPayload {
    pub cells: CellCollection,
    /// Storing the hash of the root of the cells tree. One could get it as well from the proof
    /// but it requires loading the proof, so when building the hashing structure it's best
    /// to keep it at hand directly.
    pub cell_tree_root_hash: HashOutput,
    /// Information needed to retrieve the cells root proof belonging to this row
    pub cells_root_proof_primary: U256,
    /// Information needed to retrieve the cells root proof belonging to this row
    pub cells_root_proof_key: CellTreeKey,
    /// Min sec. index value of the subtree below this node
    pub min: U256,
    /// Max sec. index value "  "   "       "     "    "
    pub max: U256,
    /// Hash of this node
    pub hash: HashOutput,
}

impl NodePayload for RowPayload {
    fn aggregate<'a, I: Iterator<Item = Option<Self>>>(&mut self, children: I) {
        let children = children.into_iter().collect::<Vec<_>>();
        assert_eq!(children.len(), 2);

        let (left_hash, right_hash) = match [&children[0], &children[1]] {
            [None, None] => {
                self.min = self.cells.secondary_index().unwrap().value;
                self.max = self.cells.secondary_index().unwrap().value;
                (*empty_poseidon_hash(), *empty_poseidon_hash())
            }
            [None, Some(right)] => {
                self.min = self.cells.secondary_index().unwrap().value;
                self.max = right.max;
                (*empty_poseidon_hash(), HashOut::from_bytes(&right.hash.0))
            }
            [Some(left), None] => {
                self.min = left.min;
                self.max = self.cells.secondary_index().unwrap().value;
                (HashOut::from_bytes(&left.hash.0), *empty_poseidon_hash())
            }
            [Some(left), Some(right)] => {
                self.min = left.min;
                self.max = right.max;
                (
                    HashOut::from_bytes(&left.hash.0),
                    HashOut::from_bytes(&right.hash.0),
                )
            }
        };
        let to_hash = // P(leftH)
                    left_hash.elements.into_iter()
                    // P(rightH)
                    .chain(right_hash.elements)
                    // P(min)
                    .chain(self.min.to_fields())
                    // P(max)
                    .chain(self.max.to_fields())
                    // P(id)
                    .chain(std::iter::once(F::from_canonical_u64(self.cells.secondary_index().unwrap().id)))
                    // P(value)
                    .chain(self.cells.secondary_index().unwrap().value.to_fields())
                    // P(cell_tree_hash)
                    .chain(self.cell_tree_root_hash.0.to_fields())
                    .collect::<Vec<_>>();
        self.hash = HashOutput(H::hash_no_pad(&to_hash).to_bytes().try_into().unwrap());
    }
}

impl ToNonce for usize {
    fn to_nonce(&self) -> RowTreeKeyNonce {
        self.to_be_bytes().to_vec()
    }
}

impl ToNonce for Vec<u8> {
    fn to_nonce(&self) -> RowTreeKeyNonce {
        self.to_owned()
    }
}

impl ToNonce for U256 {
    fn to_nonce(&self) -> RowTreeKeyNonce {
        // we don't need to keep all the bytes, only the ones that matter.
        // Since we are storing this inside psql, any storage saving is good to take !
        self.to_be_bytes_trimmed_vec()
    }
}
