use super::{index_tree::IndexTree, rowtree::RowTree};
use alloy::primitives::Address;
use anyhow::{Context, Result};
use hashbrown::HashMap;
use mp2_test::cells_tree::CellTree;
use rand::distributions::{Alphanumeric, DistString};
use ryhope::tree::{sbbst, TreeTopology};
use serde::{Deserialize, Serialize};

type CellTreeKey = <CellTree as TreeTopology>::Key;
type RowTreeKey = <RowTree as TreeTopology>::Key;
type IndexTreeKey = <IndexTree as TreeTopology>::Key;

#[derive(Debug, Clone, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub(crate) struct CellProofIdentifier<PrimaryIndex>
where
    PrimaryIndex: std::hash::Hash + PartialEq + Eq,
{
    pub(crate) table: TableID,
    pub(crate) primary: PrimaryIndex,
    pub(crate) tree_key: CellTreeKey,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub(crate) struct RowProofIdentifier<PrimaryIndex>
where
    PrimaryIndex: std::hash::Hash + PartialEq + Eq,
{
    pub(crate) table: TableID,
    pub(crate) primary: PrimaryIndex,
    pub(crate) tree_key: RowTreeKey,
}

#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub(crate) struct IndexProofIdentifier<PrimaryIndex> {
    pub(crate) table: TableID,
    pub(crate) tree_key: PrimaryIndex,
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
    Index(IndexProofIdentifier<BlockPrimaryIndex>),
    Extraction(BlockPrimaryIndex),
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
    index: HashMap<IndexProofIdentifier<BlockPrimaryIndex>, Vec<u8>>,
    extraction: HashMap<BlockPrimaryIndex, Vec<u8>>,
}

impl ProofStorage for MemoryProofStorage {
    fn store_proof(&mut self, key: ProofKey, proof: Vec<u8>) -> Result<()> {
        match key {
            ProofKey::Cell(k) => self.cells.insert(k, proof),
            ProofKey::Row(k) => self.rows.insert(k, proof),
            ProofKey::Index(k) => self.index.insert(k, proof),
            ProofKey::Extraction(k) => self.extraction.insert(k, proof),
        };
        Ok(())
    }

    fn get_proof(&self, key: &ProofKey) -> Result<Vec<u8>> {
        match key {
            ProofKey::Cell(k) => self.cells.get(k),
            ProofKey::Row(k) => self.rows.get(k),
            ProofKey::Index(k) => self.index.get(k),
            ProofKey::Extraction(k) => self.extraction.get(k),
        }
        .context("unable to get proof from storage")
        .cloned()
    }
}
