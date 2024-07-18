use std::{
    hash::{DefaultHasher, Hash, Hasher},
    path::Path,
};

use super::{index_tree::IndexTree, rowtree::RowTree, table::TableID};
use alloy::primitives::Address;
use anyhow::{bail, Context, Result};
use mp2_test::cells_tree::CellTree;
use ryhope::tree::{sbbst, TreeTopology};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

type CellTreeKey = <CellTree as TreeTopology>::Key;
type RowTreeKey = <RowTree as TreeTopology>::Key;
type IndexTreeKey = <IndexTree as TreeTopology>::Key;

type ContractKey = (Address, BlockPrimaryIndex);

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
#[derive(Clone, PartialEq, Eq)]
pub enum ProofKey {
    Cell(CellProofIdentifier<BlockPrimaryIndex>),
    Row(RowProofIdentifier<BlockPrimaryIndex>),
    Index(IndexProofIdentifier<BlockPrimaryIndex>),
    FinalExtraction((TableID, BlockPrimaryIndex)),
    ContractExtraction(ContractKey),
    BlockExtraction(BlockPrimaryIndex),
    ValueExtraction((TableID, BlockPrimaryIndex)),
    IVC(BlockPrimaryIndex),
}

impl ProofKey {
    // For the moment, using simple hash scheme from Rust. probably should move to something
    // stronger for collision resistance but given the low amount of proofs we generate in this
    // test, it should not be a problem
    pub fn compute_hash(&self) -> u64 {
        let mut s = DefaultHasher::new();
        self.hash(&mut s);
        s.finish()
    }
}

//  manually insert a prefix to make sure all keys are unique
impl Hash for ProofKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            ProofKey::Cell(c) => {
                "cell_tree".hash(state);
                c.hash(state);
            }
            ProofKey::Row(c) => {
                "row_tree".hash(state);
                c.hash(state);
            }
            ProofKey::Index(c) => {
                "index_tree".hash(state);
                c.hash(state);
            }
            ProofKey::FinalExtraction(e) => {
                "final_extract".hash(state);
                e.hash(state);
            }
            ProofKey::ContractExtraction(e) => {
                "contract_extract".hash(state);
                e.hash(state);
            }
            ProofKey::BlockExtraction(b) => {
                "block_proof".hash(state);
                b.hash(state);
            }
            ProofKey::ValueExtraction(s) => {
                "value_extract".hash(state);
                s.hash(state);
            }
            ProofKey::IVC(n) => {
                "ivc".hash(state);
                n.hash(state);
            }
        }
    }
}
pub trait ProofStorage {
    fn store_proof(&mut self, key: ProofKey, proof: Vec<u8>) -> Result<()>;
    fn get_proof(&self, key: &ProofKey) -> Result<Vec<u8>>;
}

/// This is simply a suggestion but this should be stored on a proper backend of course.
#[derive(Default)]
pub struct MemoryProofStorage(HashMap<ProofKey, Vec<u8>>);

impl ProofStorage for MemoryProofStorage {
    fn store_proof(&mut self, key: ProofKey, proof: Vec<u8>) -> Result<()> {
        self.0.insert(key, proof);
        Ok(())
    }

    fn get_proof(&self, key: &ProofKey) -> Result<Vec<u8>> {
        self.0.get(key).context("unable to get proof").cloned()
    }
}
use jammdb::{Data, Error, DB};
pub struct KeyValueDB {
    db: DB,
}

const BUCKET_NAME: &str = "v1_proof_store_test";
pub const ENV_PROOF_STORE: &str = "PROOF_STORE";
impl KeyValueDB {
    pub fn new_from_env(default: &str) -> Result<Self> {
        let path = std::env::var(ENV_PROOF_STORE).unwrap_or(default.to_string());
        Self::new(Path::new(&path))
    }
    pub fn new(path: &Path) -> Result<Self> {
        let db = DB::open(path)?;
        let tx = db.tx(true)?;
        match tx.create_bucket(BUCKET_NAME) {
            Ok(_) => log::info!("Created bucket {BUCKET_NAME} into store db at path {path:?}"),
            Err(e) => {
                match e {
                    Error::BucketExists => {
                        log::info!("Opening already existing bucket {BUCKET_NAME} into store db from {path:?}")
                    }
                    _ => panic!("Error creating bucket: {e}"),
                }
            }
        }
        tx.commit()?;
        Ok(Self { db })
    }
}

impl ProofStorage for KeyValueDB {
    fn store_proof(&mut self, key: ProofKey, proof: Vec<u8>) -> Result<()> {
        let store_key = key.compute_hash();
        let tx = self.db.tx(true)?;
        let bucket = tx.get_bucket(BUCKET_NAME)?;
        bucket.put(store_key.to_be_bytes(), proof)?;
        tx.commit()?;
        Ok(())
    }

    fn get_proof(&self, key: &ProofKey) -> Result<Vec<u8>> {
        let store_key = key.compute_hash();
        let tx = self.db.tx(true)?;
        let bucket = tx.get_bucket(BUCKET_NAME)?;
        let d = bucket
            .get(store_key.to_be_bytes())
            .context("proof with key {key:?} not found")?;
        match d {
            Data::Bucket(_) => bail!("bucket found while required proofs"),
            Data::KeyValue(kv) => Ok(kv.value().to_vec()),
        }
    }
}
