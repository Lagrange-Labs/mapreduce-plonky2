//! Utility structs and functions used for integration tests
use alloy::primitives::Address;
use anyhow::Result;
use cases::TableSourceSlot;
use mp2_v1::api::{metadata_hash, MetadataHash, SlotInputs};
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
pub(crate) use cases::TestCase;
pub(crate) use context::TestContext;

use mp2_common::{proof::ProofWithVK, types::HashOutput};
use plonky2::plonk::config::GenericHashOut;

type ColumnIdentifier = u64;

fn cell_tree_proof_to_hash(proof: &[u8]) -> HashOutput {
    let root_pi = ProofWithVK::deserialize(&proof)
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
    let root_pi = ProofWithVK::deserialize(&proof)
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
    pub public_name: String,
    pub contract_address: Address,
    pub chain_id: u64,
    pub source: TableSourceSlot,
}

impl TableInfo {
    pub fn metadata_hash(&self) -> MetadataHash {
        let slots = match &self.source {
            TableSourceSlot::Mapping((mapping, _)) => SlotInputs::Mapping(mapping.slot),
            // mapping with length not tested right now
            TableSourceSlot::SingleValues(args) => SlotInputs::Simple(args.slots.clone()),
        };
        metadata_hash(slots, &self.contract_address, self.chain_id, vec![])
    }
}
