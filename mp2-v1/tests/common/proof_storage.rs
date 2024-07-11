use super::{celltree::CellTree, rowtree::RowTree};
use anyhow::{Context, Result};
use ethers::types::{Address, U256};
use hashbrown::HashMap;
use rand::{
    distributions::{Alphanumeric, DistString},
    thread_rng,
};
use ryhope::tree::{sbbst, TreeTopology};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

type CellTreeKey = <CellTree as TreeTopology>::Key;
type RowTreeKey = <RowTree as TreeTopology>::Key;

#[derive(Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TableID(String);

impl TableID {
    /// Contains a random component to allow multiple tables for the same slots
    /// TODO: should contain more info probablyalike which index are selected
    pub fn new(contract: &Address, slots: &[u8]) -> Self {
        TableID(format!(
            "{}-{}-{}",
            contract.to_string(),
            slots
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join("+"),
            Alphanumeric.sample_string(&mut rand::thread_rng(), 8),
        ))
    }
}

/// This is the identifier we are storing proof in storage under. This identifier needs
/// to be unique accross all tables and all blocks. Remember the identifier that the tree uses
/// is not global, so two nodes in the row tree with different value could have the same tree
/// identifier since they are not shared, they are isolated trees.
/// TODO: make it nice with lifetimes, and easier constructor
#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub(crate) struct CellProofIdentifier<PrimaryIndex>
where
    PrimaryIndex: std::hash::Hash + PartialEq + Eq,
{
    pub(crate) table: TableID,
    pub(crate) primary: PrimaryIndex,
    pub(crate) tree_key: CellTreeKey,
}

#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub(crate) struct RowProofIdentifier<PrimaryIndex>
where
    PrimaryIndex: std::hash::Hash + PartialEq + Eq,
{
    pub(crate) table: TableID,
    pub(crate) primary: PrimaryIndex,
    pub(crate) tree_key: RowTreeKey,
}

/// block number by default but can be different since we want to support primary index of any
/// kinds in results tree and in general to build a table.
/// This is usize in this case for the moment since right now we deal with sbbst tree as index
/// tree.
pub(crate) type BlockPrimaryIndex = <sbbst::Tree as TreeTopology>::Key;

/// Uniquely identifies a proof in the proof storage backend.
#[derive(Clone, Hash, PartialEq, Eq)]
pub enum ProofKey {
    Cell(CellProofIdentifier<BlockPrimaryIndex>),
    Row(RowProofIdentifier<BlockPrimaryIndex>),
    // Not implemented yet but doesn't need to contain block number / primary index because
    // the tree key is already the primary index
    // Block((TableID,BlockTreeKey)),
}
pub trait ProofStorage {
    fn store_proof(&mut self, key: ProofKey, proof: Vec<u8>) -> Result<()>;
    fn get_proof(&self, key: &ProofKey) -> Result<Vec<u8>>;
}

/// This is simply a suggestion but this should be stored on a proper backend of course.
#[derive(Default)]
pub struct MemoryProofStorage {
    cells: HashMap<CellProofIdentifier<BlockPrimaryIndex>, Vec<u8>>,
    rows: HashMap<RowProofIdentifier<BlockPrimaryIndex>, Vec<u8>>,
}

impl ProofStorage for MemoryProofStorage {
    fn store_proof(&mut self, key: ProofKey, proof: Vec<u8>) -> Result<()> {
        match key {
            ProofKey::Cell(k) => self.cells.insert(k, proof),
            ProofKey::Row(k) => self.rows.insert(k, proof),
        };
        Ok(())
    }

    fn get_proof(&self, key: &ProofKey) -> Result<Vec<u8>> {
        match key {
            ProofKey::Cell(k) => self.cells.get(k),
            ProofKey::Row(k) => self.rows.get(k),
        }
        .context("unable to get proof from storage")
        .cloned()
    }
}
