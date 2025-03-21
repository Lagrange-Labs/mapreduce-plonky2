//! Utility structs and functions used for integration tests
use alloy::primitives::Address;
use anyhow::Result;
use cases::table_source::TableSource;
use mp2_v1::api::{merge_metadata_hash, metadata_hash, MetadataHash, SlotInputs};
use serde::{Deserialize, Serialize};
use table::TableColumns;
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
pub mod rowtree;
mod storage_trie;
pub mod table;
mod values_extraction;

use std::path::PathBuf;

use anyhow::Context;
pub(crate) use context::TestContext;

use mp2_common::{proof::ProofWithVK, types::HashOutput};
use plonky2::plonk::config::GenericHashOut;

type ColumnIdentifier = u64;

fn cell_tree_proof_to_hash(proof: &[u8]) -> HashOutput {
    let root_pi = ProofWithVK::deserialize(proof)
        .expect("while deserializing proof")
        .proof
        .public_inputs;
    verifiable_db::cells_tree::PublicInputs::from_slice(&root_pi)
        .root_hash_hashout()
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
        .root_hash_hashout()
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
pub struct TableInfo {
    pub columns: TableColumns,
    // column to do queries over for numerical values, NOT secondary index
    pub value_column: String,
    pub public_name: String,
    pub contract_address: Address,
    pub chain_id: u64,
    pub source: TableSource,
}

impl TableInfo {
    pub fn metadata_hash(&self) -> MetadataHash {
        match &self.source {
            TableSource::Mapping((mapping, _)) => {
                let slot = SlotInputs::Mapping(mapping.slot);
                metadata_hash(slot, &self.contract_address, self.chain_id, vec![])
            }
            // mapping with length not tested right now
            TableSource::SingleValues(args) => {
                let slot = SlotInputs::Simple(args.slots.clone());
                metadata_hash(slot, &self.contract_address, self.chain_id, vec![])
            }
            TableSource::Merge(merge) => {
                let single = SlotInputs::Simple(merge.single.slots.clone());
                let mapping = SlotInputs::Mapping(merge.mapping.slot);
                merge_metadata_hash(
                    self.contract_address,
                    self.chain_id,
                    vec![],
                    single,
                    mapping,
                )
            }
        }
    }
}
