//! Utility structs and functions used for integration tests
use alloy::primitives::Address;
use anyhow::Result;
use cases::TableSourceSlot;
use mp2_v1::{
    api::{metadata_hash, MetadataHash, SlotInputs},
    MAX_LEAF_NODE_LEN,
};
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

/// Testing maximum columns
const TEST_MAX_COLUMNS: usize = 32;
/// Testing maximum fields for each EVM word
const TEST_MAX_FIELD_PER_EVM: usize = 32;

type ColumnIdentifier = u64;
type StorageSlotInfo =
    mp2_v1::values_extraction::StorageSlotInfo<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>;
type MetadataGadget = mp2_v1::values_extraction::gadgets::metadata_gadget::MetadataGadget<
    TEST_MAX_COLUMNS,
    TEST_MAX_FIELD_PER_EVM,
>;
type PublicParameters = mp2_v1::api::PublicParameters<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>;

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
            TableSourceSlot::SingleValues(args) => {
                let slots = args
                    .slots
                    .iter()
                    .map(|slot_info| slot_info.slot().slot())
                    .collect();
                SlotInputs::Simple(slots)
            }
        };
        metadata_hash::<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>(
            slots,
            &self.contract_address,
            self.chain_id,
            vec![],
        )
    }
}
