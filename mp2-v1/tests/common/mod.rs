//! Utility structs and functions used for integration tests
use alloy::primitives::Address;
use anyhow::Result;
use cases::table_source::TableSource;
use itertools::Itertools;
use mp2_v1::api::{merge_metadata_hash, metadata_hash, MetadataHash, SlotInput, SlotInputs};
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
                let slot_input = SlotInputs::Mapping(vec![SlotInput::new(
                    mapping.slot, // byte_offset
                    0,            // bit_offset
                    0,            // length
                    0,            // evm_word
                    0,
                )]);
                metadata_hash::<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>(
                    slot_input,
                    &self.contract_address,
                    self.chain_id,
                    vec![],
                )
            }
            // mapping with length not tested right now
            TableSource::SingleValues(args) => {
                let inputs = args
                    .slots
                    .iter()
                    .flat_map(|slot_info| {
                        slot_info
                            .metadata()
                            .extracted_table_info()
                            .iter()
                            .map(Into::into)
                            .collect_vec()
                    })
                    .collect();
                let slot = SlotInputs::Simple(inputs);
                metadata_hash::<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>(
                    slot,
                    &self.contract_address,
                    self.chain_id,
                    vec![],
                )
            }
            TableSource::Merge(merge) => {
                let inputs = merge
                    .single
                    .slots
                    .iter()
                    .flat_map(|slot_info| {
                        slot_info
                            .metadata()
                            .extracted_table_info()
                            .iter()
                            .map(Into::into)
                            .collect_vec()
                    })
                    .collect();
                let single = SlotInputs::Simple(inputs);
                let mapping = SlotInputs::Mapping(vec![SlotInput::new(
                    merge.mapping.slot, // byte_offset
                    0,                  // bit_offset
                    0,                  // length
                    0,                  // evm_word
                    0,
                )]);
                merge_metadata_hash::<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>(
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
