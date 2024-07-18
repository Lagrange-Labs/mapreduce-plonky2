use alloy::primitives::Address;
use mp2_test::cells_tree::{CellTree, MerkleCellTree};
use serde::{Deserialize, Serialize};

use super::{index_tree::MerkleIndexTree, rowtree::MerkleRowTree};

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TableID(String);

impl TableID {
    /// TODO: should contain more info probablyalike which index are selected
    pub fn new(contract: &Address, slots: &[u8]) -> Self {
        TableID(format!(
            "{}-{}",
            contract,
            slots
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join("+"),
        ))
    }
}

pub struct Table {
    pub(crate) id: TableID,
    pub(crate) cell: MerkleCellTree,
    pub(crate) row: MerkleRowTree,
    pub(crate) index: MerkleIndexTree,
}
