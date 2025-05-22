use std::iter;

use crate::{F, H};
use alloy::primitives::U256;
use derive_more::Deref;
use log::debug;
use mp2_common::{poseidon::empty_poseidon_hash, types::HashOutput, utils::ToFields};
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

use super::ColumnID;

/// By default the cells tree is a sbbst tree since it is fixed for a given table and this is the
/// simplest/fastest tree.
pub type CellTree = sbbst::IncrementalTree;
/// The key used to refer to a cell in the tree
pub type CellTreeKey = <CellTree as TreeTopology>::Key;
/// The storage of cell tree is "in memory" since it is never really saved on disk. Rather, it is
/// always reconstructed on the fly given it is very small. Moreover, storing it on disk would
/// require as many sql tables as there would be rows, making this solution highly unpracticable.
pub type CellStorage<PrimaryIndex> = InMemory<CellTree, MerkleCell<PrimaryIndex>, false>;
/// The cells tree is a Merkle tree with cryptographically secure hash function committing to its
/// content.
pub type MerkleCellTree<PrimaryIndex> =
    MerkleTreeKvDb<CellTree, MerkleCell<PrimaryIndex>, CellStorage<PrimaryIndex>>;

/// Returns a new empty Merkle cells tree.
pub async fn new_tree<
    PrimaryIndex: std::fmt::Debug
        + Sync
        + Send
        + PartialEq
        + Eq
        + Default
        + Clone
        + Sized
        + Serialize
        + for<'a> Deserialize<'a>,
>() -> MerkleCellTree<PrimaryIndex> {
    MerkleCellTree::new(InitSettings::Reset(sbbst::IncrementalTree::empty()), ())
        .await
        .unwrap()
}

/// Cell is the information stored in a specific cell of a specific row.
/// A row node in the row tree contains a vector of such cells.
#[derive(Clone, Default, Debug, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cell {
    /// The unique identifier of the cell, derived from the contract it comes
    /// from and its slot in its storage.
    id: u64,
    /// The value stored in the cell
    value: U256,
}

impl Cell {
    /// Returns a new cell from the column identifier and the value.
    pub fn new(id: u64, value: U256) -> Self {
        Self { id, value }
    }
    /// Returns the identifier associed to that cell
    pub fn identifier(&self) -> ColumnID {
        self.id
    }

    /// Returns the value associated to that cell
    pub fn value(&self) -> U256 {
        self.value
    }
}

/// MerkleCell is the data stored in the cells tree. It contains a cell and a hash of the subtree
/// rooted at the cell in the cells tree.
#[derive(Clone, Debug, Default, Serialize, Deserialize, Deref)]
pub struct MerkleCell<PrimaryIndex> {
    #[deref]
    pub cell: Cell,
    pub primary: PrimaryIndex,
    /// The hash of this node in the cells tree
    pub hash: HashOutput,
}

impl<PrimaryIndex: Default> MerkleCell<PrimaryIndex> {
    pub fn new(id: ColumnID, value: U256, primary: PrimaryIndex) -> Self {
        Self {
            cell: Cell { id, value },
            primary,
            ..Default::default()
        }
    }

    pub fn new_empty() -> Self {
        Self {
            hash: HashOutput::from(*empty_poseidon_hash()),
            ..Default::default()
        }
    }
}

impl<
        PrimaryIndex: std::fmt::Debug
            + PartialEq
            + Eq
            + Default
            + Clone
            + Sized
            + Serialize
            + for<'a> Deserialize<'a>,
    > NodePayload for MerkleCell<PrimaryIndex>
{
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
