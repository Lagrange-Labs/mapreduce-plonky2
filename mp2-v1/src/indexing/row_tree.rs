use alloy::primitives::U256;
use anyhow::Result;
use derive_more::{Deref, From};
use hashbrown::HashMap;
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

use super::{
    cell_tree::{Cell, CellTreeKey},
    ColumnID,
};

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
#[derive(Eq, PartialEq, Deref, From, Default, Debug, Clone, Serialize, Deserialize)]
pub struct CellCollection(pub HashMap<ColumnID, U256>);
impl CellCollection {
    pub fn from_cells(cells: &[Cell]) -> Self {
        Self(cells.iter().map(|c| (c.id, c.value)).collect())
    }
    // take all the cells ids on both collections, take the value present in the updated one
    // if it exists, otherwise take from self.
    pub fn merge_with_update(&self, updated_cells: &[Cell]) -> Self {
        if self == &Self::default() {
            return Self::from_cells(updated_cells);
        }
        Self(
            self.0
                .iter()
                .map(|(id, previous_value)| {
                    updated_cells
                        .iter()
                        .find(|new_cell| *id == new_cell.id)
                        .map(|c| (c.id, c.value))
                        .unwrap_or_else(|| (*id, *previous_value))
                })
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
    /// Map from column id to value
    /// This includes the
    pub cells: HashMap<ColumnID, U256>,
    /// The ID of the secondary index column.
    /// NOTE: the reason we have this here is because when computing the hash, we need to know
    /// which value to lookup in the hashmap. The reason we have a hashmap is to be easily
    /// searchable from JSONB in PSQL.
    /// TODO: The real nice solution could be to allow a "context" in the ryhope NodePayload trait
    /// such that we can extract that information from the context. Currently this info needs to be
    /// stored in the JSONB because we have no other source of information.
    pub secondary_index: ColumnID,
    /// Storing the hash of the root of the cells tree. One could get it as well from the proof
    /// but it requires loading the proof, so when building the hashing structure it's best
    /// to keep it at hand directly.
    pub cell_tree_root_hash: HashOutput,
    /// Information needed to retrieve the cells root proof belonging to this row
    pub cell_root_proof_primary: U256,
    /// Information needed to retrieve the cells root proof belonging to this row
    pub cell_root_proof_key: CellTreeKey,
    /// Min sec. index value of the subtree below this node
    pub min: U256,
    /// Max sec. index value "  "   "       "     "    "
    pub max: U256,
    /// Hash of this node
    pub hash: HashOutput,
}

impl RowPayload {
    /// Construct a row payload from
    /// * the collection of cells, which MUST include the value of the secondary index
    /// * the hash of the cells tree associated to that row
    /// * the primary index value when that cells tree root proof was generated. In most cases, the
    ///     primary value is the block index. The block would refer to the last time the cells tree
    ///     changed for that row.
    /// * The key of the root of the cells tree.
    pub fn new(
        cells: Vec<Cell>,
        secondary_index: ColumnID,
        cell_tree_hash: HashOutput,
        cells_proof_primary: &[u8],
        cells_root_key: CellTreeKey,
    ) -> Self {
        RowPayload {
            cells: cells.iter().map(|c| (c.id, c.value)).collect(),
            secondary_index,
            cell_tree_root_hash: cell_tree_hash,
            cell_root_proof_primary: U256::from_be_slice(cells_proof_primary),
            cell_root_proof_key: cells_root_key,
            ..Default::default()
        }
    }

    pub fn secondary_index_value(&self) -> U256 {
        self.cells[&self.secondary_index]
    }
}

impl NodePayload for RowPayload {
    fn aggregate<'a, I: Iterator<Item = Option<Self>>>(&mut self, children: I) {
        let children = children.into_iter().collect::<Vec<_>>();
        assert_eq!(children.len(), 2);

        let (left_hash, right_hash) = match [&children[0], &children[1]] {
            [None, None] => {
                self.min = self.secondary_index_value();
                self.max = self.secondary_index_value();
                (*empty_poseidon_hash(), *empty_poseidon_hash())
            }
            [None, Some(right)] => {
                self.min = self.secondary_index_value();
                self.max = right.max;
                (*empty_poseidon_hash(), HashOut::from_bytes(&right.hash.0))
            }
            [Some(left), None] => {
                self.min = left.min;
                self.max = self.secondary_index_value();
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
                    .chain(std::iter::once(F::from_canonical_u64(self.secondary_index)))
                    // P(value)
                    .chain(self.secondary_index_value().to_fields())
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
