//! Utility structs and functions used for integration tests
use alloy::primitives::Address;
use anyhow::Result;
use cases::table_source::TableSource;
use mp2_v1::api::MetadataHash;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use table::{TableColumns, TableRowUniqueID};
pub mod benchmarker;
pub mod bindings;
mod block_extraction;
pub mod cases;
pub mod celltree;
pub mod context;
mod contract_extraction;
mod final_extraction;
pub mod index_tree;
pub mod ivc;
mod length_extraction;
pub(crate) mod proof_storage;
mod receipt_trie;
pub mod rowtree;
mod storage_trie;
pub mod table;
mod values_extraction;

use std::path::PathBuf;

use anyhow::Context;
pub(crate) use context::TestContext;

use mp2_common::{proof::ProofWithVK, types::HashOutput};
use plonky2::plonk::config::GenericHashOut;

/// Testing maximum columns
pub(crate) const TEST_MAX_COLUMNS: usize = 32;

type ColumnIdentifier = u64;
type PublicParameters = mp2_v1::api::PublicParameters<TEST_MAX_COLUMNS>;

fn cell_tree_proof_to_hash(proof: &[u8]) -> HashOutput {
    let root_pi = ProofWithVK::deserialize(proof)
        .expect("while deserializing proof")
        .proof
        .public_inputs;
    verifiable_db::cells_tree::PublicInputs::from_slice(&root_pi)
        .node_hash()
        .to_bytes()
        .try_into()
        .unwrap()
}

fn row_tree_proof_to_hash(proof: &[u8]) -> HashOutput {
    let root_pi = ProofWithVK::deserialize(proof)
        .expect("while deserializing proof")
        .proof
        .public_inputs;
    verifiable_db::row_tree::PublicInputs::from_slice(&root_pi)
        .root_hash()
        .to_bytes()
        .try_into()
        .unwrap()
}

pub fn mkdir_all(params_path_str: &str) -> Result<()> {
    let params_path = PathBuf::from(params_path_str);
    if !params_path.exists() {
        std::fs::create_dir_all(&params_path).context("while creating parameters folder")?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "T: Serialize + DeserializeOwned")]
pub struct TableInfo<T: TableSource> {
    pub columns: TableColumns,
    pub row_unique_id: TableRowUniqueID,
    // column to do queries over for numerical values, NOT secondary index
    pub value_column: String,
    pub public_name: String,
    pub contract_address: Address,
    pub chain_id: u64,
    pub source: T,
}

impl<T: TableSource> TableInfo<T> {
    pub fn metadata_hash(&self) -> MetadataHash {
        self.source
            .metadata_hash(self.contract_address, self.chain_id)
    }
}
