//! Utility structs and functions used for integration tests
use alloy::primitives::{Address, U256};
use anyhow::Result;
use cases::table_source::{SingleStructExtractionArgs, SingleValuesExtractionArgs, TableSource};
use mp2_v1::api::{merge_metadata_hash, metadata_hash, MetadataHash, SlotInputs};
use serde::{Deserialize, Serialize};
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
type ColumnGadgetData =
    mp2_v1::values_extraction::gadgets::column_gadget::ColumnGadgetData<TEST_MAX_FIELD_PER_EVM>;
type PublicParameters = mp2_v1::api::PublicParameters<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>;

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

/// Abstract for the value saved in the storage slot.
/// It could be a single value of Uint256 or a Struct.
pub trait StorageSlotValue: Clone {
    /// Generate a random value for testing.
    fn sample() -> Self;
    /// Convert from an Uint256 vector.
    fn from_u256_slice(u: &[U256]) -> Self;
    /// Convert into an Uint256 vector.
    fn to_u256_vec(&self) -> Vec<U256>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableInfo {
    pub columns: TableColumns,
    pub row_unique_id: TableRowUniqueID,
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
            // mapping with length not tested right now
            TableSource::SingleValues(_) => {
                let slot = SlotInputs::Simple(SingleValuesExtractionArgs::slot_inputs());
                metadata_hash::<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>(
                    slot,
                    &self.contract_address,
                    self.chain_id,
                    vec![],
                )
            }
            TableSource::SingleStruct(_) => {
                let slot = SlotInputs::Simple(SingleStructExtractionArgs::slot_inputs());
                metadata_hash::<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>(
                    slot,
                    &self.contract_address,
                    self.chain_id,
                    vec![],
                )
            }
            TableSource::MappingValues(args, _) => {
                let slot_inputs = SlotInputs::Mapping(args.slot_inputs().to_vec());
                metadata_hash::<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>(
                    slot_inputs,
                    &self.contract_address,
                    self.chain_id,
                    vec![],
                )
            }
            TableSource::MappingStruct(args, _) => {
                let slot_inputs = SlotInputs::Mapping(args.slot_inputs().to_vec());
                metadata_hash::<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>(
                    slot_inputs,
                    &self.contract_address,
                    self.chain_id,
                    vec![],
                )
            }
            TableSource::Merge(source) => {
                let single = SlotInputs::Simple(SingleValuesExtractionArgs::slot_inputs());
                let mapping = SlotInputs::Mapping(source.mapping.slot_inputs().to_vec());
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
