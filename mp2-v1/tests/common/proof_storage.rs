use std::{
    hash::{DefaultHasher, Hash, Hasher},
    path::{Path, PathBuf},
};

use super::{context::TestContextConfig, mkdir_all, table::TableID};
use alloy::primitives::{Address, U256};
use anyhow::{bail, Context, Result};
use envconfig::Envconfig;
use mp2_test::cells_tree::CellTree;
use mp2_v1::indexing::{
    block::{BlockPrimaryIndex, BlockTree},
    row::RowTreeKey,
};
use ryhope::tree::TreeTopology;
use serde::{Deserialize, Serialize};

type CellTreeKey = <CellTree as TreeTopology>::Key;
type IndexTreeKey = <BlockTree as TreeTopology>::Key;

type ContractKey = (Address, BlockPrimaryIndex);

/// This is the identifier we store cells tree proof under in storage. This identifier
/// is only unique per row tree key (i.e. secondary index value).
#[derive(Debug, Clone, Default, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub(crate) struct CellProofIdentifier<PrimaryIndex> {
    pub(crate) table: TableID,
    pub(crate) primary: PrimaryIndex,
    pub(crate) secondary: RowTreeKey,
    pub(crate) tree_key: CellTreeKey,
}

/// This is the identifier we are storing row tree proof in storage under. This identifier needs
/// to be unique accross all tables.
/// NOTE: The block number in this test is not stored as part of the identifier. Doing so would
/// require to have a "queue" of proofs for the same tree key. Since having access to historical proofs made
/// on the same tree key but at older blocks is not really useful, this test choose to only keep
/// the latest one. By not having the block number, redoing a proof for the same tree key will
/// overwrite preious proofs. Dist system could store the whole history as long as they correctly
/// pick the latest one when doing a tree update. See `prove_row_tree` function for more details.
/// _previous proofs_ ,
/// NOTE2: Ideally we would keep all proof history in case something goes wrong. In that case, when
/// building the row tree, one must have the ability to "search back in time". i.e. proving row
/// tree for block 4 can require searching for a node whose proof has been generated at block 2
/// TODO: make it nice with lifetimes, and easier constructor
#[derive(Debug, Clone, Default, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub(crate) struct RowProofIdentifier<PrimaryIndex> {
    pub(crate) table: TableID,
    pub(crate) primary: PrimaryIndex,
    pub(crate) tree_key: RowTreeKey,
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub(crate) struct IndexProofIdentifier<PrimaryIndex> {
    pub(crate) table: TableID,
    pub(crate) tree_key: PrimaryIndex,
}

pub type QueryID = String;

pub type PlaceholderValues = Vec<U256>;

/// Uniquely identifies a proof in the proof storage backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofKey {
    Cell(CellProofIdentifier<BlockPrimaryIndex>),
    Row(RowProofIdentifier<BlockPrimaryIndex>),
    Index(IndexProofIdentifier<BlockPrimaryIndex>),
    FinalExtraction((TableID, BlockPrimaryIndex)),
    ContractExtraction(ContractKey),
    BlockExtraction(BlockPrimaryIndex),
    ValueExtraction((TableID, BlockPrimaryIndex)),
    #[allow(clippy::upper_case_acronyms)]
    IVC(BlockPrimaryIndex),
    QueryUniversal((QueryID, PlaceholderValues, BlockPrimaryIndex, RowTreeKey)),
    QueryAggregateRow((QueryID, PlaceholderValues, BlockPrimaryIndex, RowTreeKey)),
    QueryAggregateIndex((QueryID, PlaceholderValues, BlockPrimaryIndex)),
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
            ProofKey::QueryUniversal(n) => {
                "query_universal".hash(state);
                n.hash(state);
            }
            ProofKey::QueryAggregateRow(n) => {
                "query_aggregate_row".hash(state);
                n.hash(state);
            }
            ProofKey::QueryAggregateIndex(n) => {
                "query_aggregate_index".hash(state);
                n.hash(state);
            }
        }
    }
}
pub trait ProofStorage {
    fn store_proof(&mut self, key: ProofKey, proof: Vec<u8>) -> Result<()>;
    fn get_proof_exact(&self, key: &ProofKey) -> Result<Vec<u8>>;
    /// Move the proof form the old key to the new key. This is **required** for cells proofs
    /// when the secondary index value changes.
    /// If there is no proof at the old key, it simply does nothing.
    /// Take for example the row [A,b,c,d] where A is
    /// the secondary index value. Proofs for b c d are stored under a key related to A.
    /// Imagine now A changes, to F, the row is now [F,b,c,d]. But the proofs of b,c,d are still
    /// stored under the key related to A. This function must be called to move them from A -> F.
    /// By safety, the storage should not keep the previous version of the cells proofs (the ones under A)
    /// otherwse it may cause conflict down the line.
    /// If there is a new row after being inserted like [A,b,s,t] after, normally this code should
    /// generate a new proof for b and store it under the old key A, overwriting any previous proof
    /// if present, but best to be cautious and erase everything, since once a row is deleted, we
    /// should not need its proofs anymore.
    fn move_proof(&mut self, old_key: &ProofKey, new_key: &ProofKey) -> Result<()>;
}

use jammdb::{Data, Error, DB};
pub struct ProofKV {
    db: DB,
}

/// Bucket storing the last block number "proven" for each row tree key
/// This allows when proving the update to fetch row tree proofs that already have been proven many
/// blocks ago.
const ROW_BUCKET_NAME: &str = "row_proof_id";
const BUCKET_NAME: &str = "v1_proof_store_test";
pub const ENV_PROOF_STORE: &str = "proofs.store";
pub const DEFAULT_PROOF_STORE_FOLDER: &str = "store/";

impl ProofKV {
    pub fn new_from_env(default: &str) -> Result<Self> {
        let filename = std::env::var(ENV_PROOF_STORE).unwrap_or(default.to_string());
        Self::new(Path::new(&filename))
    }
    pub fn new(filename: &Path) -> Result<Self> {
        let cfg = TestContextConfig::init_from_env().context("while parsing configuration")?;

        let path = cfg
            .params_dir
            .unwrap_or(DEFAULT_PROOF_STORE_FOLDER.to_string());
        mkdir_all(&path)?;
        let mut path = PathBuf::from(path);
        path.push(filename);
        let db = DB::open(path.clone())?;
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
        match tx.create_bucket(ROW_BUCKET_NAME) {
            Ok(_) => log::info!("Created bucket {ROW_BUCKET_NAME} into store row block info"),
            Err(e) => match e {
                Error::BucketExists => {
                    log::info!("Opening already existing bucket {ROW_BUCKET_NAME} into store db")
                }
                _ => panic!("Error creating row bucket: {e}"),
            },
        }
        tx.commit()?;
        Ok(Self { db })
    }
}

impl ProofStorage for ProofKV {
    fn store_proof(&mut self, key: ProofKey, proof: Vec<u8>) -> Result<()> {
        let store_key = key.compute_hash();
        let tx = self.db.tx(true)?;
        let bucket = tx.get_bucket(BUCKET_NAME)?;
        bucket.put(store_key.to_be_bytes(), proof)?;
        if let ProofKey::Row(row_key) = key {
            let row_bucket = tx.get_bucket(ROW_BUCKET_NAME)?;
            // store the latest primary index key for which this tree key have been proven
            // TODO: use a proper hash, no need to store in raw everything
            println!(
                "??STORING latest block number {} for row tree key {:?}",
                row_key.primary, row_key.tree_key
            );

            row_bucket.put(row_key.tree_key.to_bytes()?, row_key.primary.to_be_bytes())?;
            println!(
                "STORED latest block number {} for row tree key {:?}",
                row_key.primary, row_key.tree_key
            );
        }
        tx.commit()?;
        Ok(())
    }

    fn move_proof(&mut self, old_key: &ProofKey, new_key: &ProofKey) -> Result<()> {
        let store_key = old_key.compute_hash();
        let data = {
            // have to it inside a {} since mutable borrow happens at self.db.tx
            let tx = self.db.tx(true)?;
            let bucket = tx.get_bucket(BUCKET_NAME)?;
            match bucket.get(store_key.to_be_bytes()) {
                Some(d) => match d {
                    Data::Bucket(_) => bail!("bucket found while required proofs"),
                    Data::KeyValue(kv) => {
                        bucket
                            .delete(store_key.to_be_bytes())
                            .expect("Can't delete proof from kv storage");
                        Some(kv.value().to_vec())
                    }
                },
                // silent move
                None => None,
            }
        };
        match data {
            Some(d) => self.store_proof(new_key.clone(), d),
            None => Ok(()),
        }
    }

    fn get_proof_exact(&self, key: &ProofKey) -> Result<Vec<u8>> {
        let store_key = key.compute_hash();
        let tx = self.db.tx(false)?;
        let bucket = tx.get_bucket(BUCKET_NAME)?;
        let d = bucket
            .get(store_key.to_be_bytes())
            .context(format!("proof with key {:?} not found", key))?;
        match d {
            Data::Bucket(_) => bail!("bucket found while required proofs"),
            Data::KeyValue(kv) => Ok(kv.value().to_vec()),
        }
    }
}
