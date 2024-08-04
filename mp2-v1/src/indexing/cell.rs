use std::iter;

use alloy::primitives::U256;
use derive_more::Deref;
use log::debug;
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
    storage::memory::InMemory,
    tree::{sbbst, TreeTopology},
    InitSettings, MerkleTreeKvDb, NodePayload,
};
use serde::{Deserialize, Serialize};

/// By default the cells tree is a sbbst tree since it is fixed for a given table and this is the
/// simplest/fastest tree.
pub type CellTree = sbbst::Tree;
/// The key used to refer to a cell in the tree
pub type CellTreeKey = <CellTree as TreeTopology>::Key;
/// The storage of cell tree is "in memory" since it is never really saved on disk. Rather, it is
/// always reconstructed on the fly given it is very small. Moreover, storing it on disk would
/// require as many sql tables as there would be rows, making this solution highly unpracticable.
pub type CellStorage = InMemory<CellTree, MerkleCell>;
/// The cells tree is a Merkle tree with cryptographically secure hash function committing to its
/// content.
pub type MerkleCellTree = MerkleTreeKvDb<CellTree, MerkleCell, CellStorage>;

/// Returns a new empty Merkle cells tree.
pub fn new_tree() -> MerkleCellTree {
    MerkleCellTree::new(InitSettings::Reset(sbbst::Tree::empty()), ()).unwrap()
}

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

/// MerkleCell is the data stored in the cells tree. It contains a cell and a hash of the subtree
/// rooted at the cell in the cells tree.
#[derive(Clone, Debug, Default, Serialize, Deserialize, Deref)]
pub struct MerkleCell {
    #[deref]
    cell: Cell,
    /// The hash of this node in the cells tree
    pub hash: HashOutput,
}

impl From<Cell> for MerkleCell {
    fn from(value: Cell) -> Self {
        MerkleCell {
            cell: value,
            hash: Default::default(),
        }
    }
}

impl From<&Cell> for MerkleCell {
    fn from(value: &Cell) -> Self {
        MerkleCell {
            cell: value.clone(),
            hash: Default::default(),
        }
    }
}
impl NodePayload for MerkleCell {
    fn aggregate<'a, I: Iterator<Item = Option<Self>>>(&mut self, children: I) {
        let children = children.into_iter().collect::<Vec<_>>();
        assert_eq!(children.len(), 2);

        let (left_hash, right_hash) = match [&children[0], &children[1]] {
            [None, None] => (*empty_poseidon_hash(), *empty_poseidon_hash()),
            [None, Some(right)] => (*empty_poseidon_hash(), HashOut::from_bytes(&right.hash.0)),
            [Some(left), None] => (HashOut::from_bytes(&left.hash.0), *empty_poseidon_hash()),
            [Some(left), Some(right)] => (
                HashOut::from_bytes(&left.hash.0),
                HashOut::from_bytes(&right.hash.0),
            ),
        };

        // H(H(left_child) || H(right_child) || id || value)
        let inputs: Vec<_> = left_hash
            .to_fields()
            .into_iter()
            .chain(right_hash.to_fields())
            // ID
            .chain(iter::once(F::from_canonical_u64(self.id)))
            // Value
            .chain(self.value.to_fields())
            .collect();

        self.hash = HashOutput(H::hash_no_pad(&inputs).to_bytes().try_into().unwrap());
        debug!(
            "Ryhope Cell Tree hash for id {:?} - value {:?} -> {:?}: LEFT HASH: {:?}, RIGHT HASH {:?}",
            self.cell.id,
            self.cell.value,
            hex::encode(self.hash.0),
            hex::encode(left_hash.to_bytes()),
            hex::encode(right_hash.to_bytes()),
        );
    }
}
