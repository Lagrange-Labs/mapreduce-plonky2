use crate::api::SlotInput;

use gadgets::{
    column_info::{ExtractedColumnInfo, InputColumnInfo},
    metadata_gadget::TableMetadata,
};
use itertools::Itertools;

use alloy::primitives::Address;
use mp2_common::{
    digest::Digest,
    eth::{left_pad32, StorageSlot},
    poseidon::{empty_poseidon_hash, H},
    types::{HashOutput, MAPPING_LEAF_VALUE_LEN},
    utils::{Endianness, Packer, ToFields},
    F,
};
use plonky2::{
    field::types::{Field, PrimeField64},
    plonk::config::Hasher,
};

use serde::{Deserialize, Serialize};
use std::iter::once;

pub mod api;
mod branch;
mod dummy;
mod extension;
pub mod gadgets;
mod leaf_mapping;
mod leaf_mapping_of_mappings;
mod leaf_receipt;
mod leaf_single;
pub mod planner;
pub mod public_inputs;

pub use api::{build_circuits_params, generate_proof, CircuitInput, PublicParameters};
pub use public_inputs::PublicInputs;

/// Constant prefixes for the mapping key ID. Restrict to 4-bytes (Uint32).
pub(crate) const KEY_ID_PREFIX: &[u8] = b"\0KEY";

/// Constant prefixes for the inner and outer key IDs of mapping slot.
/// Restrict to 8-bytes (Uint64).
pub(crate) const INNER_KEY_ID_PREFIX: &[u8] = b"\0\0IN_KEY";
pub(crate) const OUTER_KEY_ID_PREFIX: &[u8] = b"\0OUT_KEY";

pub(crate) const BLOCK_ID_DST: &[u8] = b"BLOCK_NUMBER";

/// Type for mapping keys
pub type MappingKey = Vec<u8>;
/// Type for column ID
pub type ColumnId = u64;

/// Storage slot information for generating the extraction proof
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct StorageSlotInfo {
    slot: StorageSlot,
    table_info: Vec<ExtractedColumnInfo>,
}

impl StorageSlotInfo {
    pub fn new(slot: StorageSlot, table_info: Vec<ExtractedColumnInfo>) -> Self {
        Self { slot, table_info }
    }

    pub fn slot(&self) -> &StorageSlot {
        &self.slot
    }

    pub fn table_info(&self) -> &[ExtractedColumnInfo] {
        &self.table_info
    }

    pub fn evm_word(&self) -> u32 {
        self.slot.evm_offset()
    }

    pub fn outer_key_id(
        &self,
        contract_address: &Address,
        chain_id: u64,
        extra: Vec<u8>,
    ) -> Option<ColumnId> {
        let extra = identifier_raw_extra(contract_address, chain_id, extra);

        self.outer_key_id_raw(extra)
    }

    pub fn inner_key_id(
        &self,
        contract_address: &Address,
        chain_id: u64,
        extra: Vec<u8>,
    ) -> Option<ColumnId> {
        let extra = identifier_raw_extra(contract_address, chain_id, extra);

        self.inner_key_id_raw(extra)
    }

    pub fn outer_key_id_raw(&self, extra: Vec<u8>) -> Option<u64> {
        let slot = self.slot().slot();
        let num_mapping_keys = self.slot().mapping_keys().len();
        match num_mapping_keys {
            _ if num_mapping_keys == 0 => None,
            _ if num_mapping_keys == 1 => Some(identifier_for_mapping_key_column_raw(slot, extra)),
            _ if num_mapping_keys == 2 => {
                Some(identifier_for_outer_mapping_key_column_raw(slot, extra))
            }
            _ => panic!("Unsupport for the nested mapping keys of length greater than 2"),
        }
    }

    pub fn inner_key_id_raw(&self, extra: Vec<u8>) -> Option<u64> {
        let slot = self.slot().slot();
        let num_mapping_keys = self.slot().mapping_keys().len();
        match num_mapping_keys {
            _ if num_mapping_keys < 2 => None,
            _ if num_mapping_keys == 2 => {
                Some(identifier_for_inner_mapping_key_column_raw(slot, extra))
            }
            _ => panic!("Unsupport for the nested mapping keys of length greater than 2"),
        }
    }

    pub fn slot_inputs<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>(
        &self,
    ) -> Vec<SlotInput> {
        self.table_info().iter().map(SlotInput::from).collect()
    }

    pub fn table_columns(
        &self,
        contract_address: &Address,
        chain_id: u64,
        extra: Vec<u8>,
    ) -> TableMetadata {
        let slot = self.slot().slot();
        let num_mapping_keys = self.slot().mapping_keys().len();

        let input_columns = match num_mapping_keys {
            0 => vec![],
            1 => {
                let identifier = compute_id_with_prefix(
                    KEY_ID_PREFIX,
                    slot,
                    contract_address,
                    chain_id,
                    extra.clone(),
                );
                let input_column = InputColumnInfo::new(&[slot], identifier, KEY_ID_PREFIX, 32);
                vec![input_column]
            }
            2 => {
                let outer_identifier = compute_id_with_prefix(
                    OUTER_KEY_ID_PREFIX,
                    slot,
                    contract_address,
                    chain_id,
                    extra.clone(),
                );
                let inner_identifier = compute_id_with_prefix(
                    INNER_KEY_ID_PREFIX,
                    slot,
                    contract_address,
                    chain_id,
                    extra.clone(),
                );
                vec![
                    InputColumnInfo::new(&[slot], outer_identifier, OUTER_KEY_ID_PREFIX, 32),
                    InputColumnInfo::new(&[slot], inner_identifier, INNER_KEY_ID_PREFIX, 32),
                ]
            }
            _ => vec![],
        };

        TableMetadata::new(&input_columns, self.table_info())
    }
}

/// Prefix used for making a topic column id.
pub const TOPIC_PREFIX: &[u8] = b"topic";
/// [`TOPIC_PREFIX`] as a [`str`]
pub const TOPIC_NAME: &str = "topic";

/// Prefix used for making a data column id.
pub const DATA_PREFIX: &[u8] = b"data";
/// [`DATA_PREFIX`] as a [`str`]
pub const DATA_NAME: &str = "data";

/// Prefix for transaction index
pub const TX_INDEX_PREFIX: &[u8] = b"tx_index";
/// [`TX_INDEX_PREFIX`] as a [`str`]
pub const TX_INDEX_NAME: &str = "tx_index";

/// Prefix for gas used
pub const GAS_USED_PREFIX: &[u8] = b"gas_used";
/// [`GAS_USED_PREFIX`] as a [`str`]
pub const GAS_USED_NAME: &str = "gas_used";

pub fn identifier_block_column() -> ColumnId {
    let inputs: Vec<F> = BLOCK_ID_DST.to_fields();
    H::hash_no_pad(&inputs).elements[0].to_canonical_u64()
}

/// Compute identifier for value column.
///
/// The value column could be either simple or mapping slot.
/// `id = H(slot || byte_offset || length || evm_word || contract_address || chain_id || extra)[0]`
pub fn identifier_for_value_column(
    input: &SlotInput,
    contract_address: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> ColumnId {
    let extra = contract_address
        .0
        .into_iter()
        .chain(chain_id.to_be_bytes())
        .chain(extra)
        .collect_vec();

    identifier_for_value_column_raw(input, extra)
}

/// Compute identifier for value column in raw mode.
/// The value column could be either simple or mapping slot.
/// `id = H(slot || byte_offset || length || evm_word || extra)[0]`
///
/// We could custom the `extra` argument, if it's set to `(contract_address || chain_id || extra)`,
/// It's same with `identifier_for_mapping_key_column`.
pub fn identifier_for_value_column_raw(input: &SlotInput, extra: Vec<u8>) -> ColumnId {
    let inputs = once(input.slot)
        .chain(input.byte_offset.to_be_bytes())
        .chain(input.length.to_be_bytes())
        .chain(input.evm_word.to_be_bytes())
        .chain(extra)
        .map(F::from_canonical_u8)
        .collect_vec();

    H::hash_no_pad(&inputs).elements[0].to_canonical_u64()
}

/// Compute key indetifier for mapping variable.
/// `key_id = H(KEY || slot || contract_address || chain_id)[0]`
pub fn identifier_for_mapping_key_column(
    slot: u8,
    contract_address: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> ColumnId {
    compute_id_with_prefix(KEY_ID_PREFIX, slot, contract_address, chain_id, extra)
}

/// Compute key indetifier for mapping variable in raw mode.
/// `key_id = H(KEY || slot || contract_address || chain_id)[0]`
///
/// We could custom the `extra` argument, if it's set to `(contract_address || chain_id || extra)`,
/// It's same with `identifier_for_mapping_key_column`.
pub fn identifier_for_mapping_key_column_raw(slot: u8, extra: Vec<u8>) -> u64 {
    compute_id_with_prefix_raw(KEY_ID_PREFIX, slot, extra)
}

/// Compute outer key indetifier for mapping of mappings variable.
/// `outer_key_id = H(OUT_KEY || slot || contract_address || chain_id)[0]`
pub fn identifier_for_outer_mapping_key_column(
    slot: u8,
    contract_address: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> ColumnId {
    compute_id_with_prefix(OUTER_KEY_ID_PREFIX, slot, contract_address, chain_id, extra)
}

/// Compute outer key indetifier for mapping of mappings variable in raw mode.
/// `outer_key_id = H(OUT_KEY || slot || contract_address || chain_id)[0]`
///
/// We could custom the `extra` argument, if it's set to `(contract_address || chain_id || extra)`,
/// It's same with `identifier_for_outer_mapping_key_column`.
pub fn identifier_for_outer_mapping_key_column_raw(slot: u8, extra: Vec<u8>) -> u64 {
    compute_id_with_prefix_raw(OUTER_KEY_ID_PREFIX, slot, extra)
}
/// Compute inner key indetifier for mapping of mappings variable.
/// `inner_key_id = H(IN_KEY || slot || contract_address || chain_id)[0]`
pub fn identifier_for_inner_mapping_key_column(
    slot: u8,
    contract_address: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> ColumnId {
    compute_id_with_prefix(INNER_KEY_ID_PREFIX, slot, contract_address, chain_id, extra)
}

/// Compute inner key indetifier for mapping of mappings variable in raw mode.
/// `inner_key_id = H(IN_KEY || slot || extra)[0]`
///
/// We could custom the `extra` argument, if it's set to `(contract_address || chain_id || extra)`,
/// It's same with `identifier_for_inner_mapping_key_column`.
pub fn identifier_for_inner_mapping_key_column_raw(slot: u8, extra: Vec<u8>) -> u64 {
    compute_id_with_prefix_raw(INNER_KEY_ID_PREFIX, slot, extra)
}

/// Calculate ID with prefix.
pub(crate) fn compute_id_with_prefix(
    prefix: &[u8],
    slot: u8,
    contract_address: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> ColumnId {
    let extra = identifier_raw_extra(contract_address, chain_id, extra);

    compute_id_with_prefix_raw(prefix, slot, extra)
}

/// Construct the raw extra by contract address, chain ID and extra data.
pub fn identifier_raw_extra(contract_address: &Address, chain_id: u64, extra: Vec<u8>) -> Vec<u8> {
    contract_address
        .0
        .into_iter()
        .chain(chain_id.to_be_bytes())
        .chain(extra)
        .collect()
}

/// Calculate ID with prefix in raw mode.
///
/// We could custom the `extra` argument, if it's set to `(contract_address || chain_id || extra)`,
/// It's same with `compute_id_with_prefix`.
fn compute_id_with_prefix_raw(prefix: &[u8], slot: u8, extra: Vec<u8>) -> ColumnId {
    let inputs: Vec<F> = prefix
        .iter()
        .cloned()
        .chain(once(slot))
        .chain(extra)
        .collect_vec()
        .to_fields();

    H::hash_no_pad(&inputs).elements[0].to_canonical_u64()
}

/// Compute the row unique data for single leaf.
pub fn row_unique_data_for_single_leaf() -> HashOutput {
    empty_poseidon_hash().into()
}

/// Compute the row unique data for mapping leaf.
pub fn row_unique_data_for_mapping_leaf(mapping_key: &[u8]) -> HashOutput {
    // row_unique_data = H(pack(left_pad32(key))
    let packed_mapping_key = left_pad32(mapping_key)
        .pack(Endianness::Big)
        .into_iter()
        .map(F::from_canonical_u32)
        .collect_vec();
    H::hash_no_pad(&packed_mapping_key).into()
}

/// Compute the row unique data for mapping of mappings leaf.
pub fn row_unique_data_for_mapping_of_mappings_leaf(
    outer_mapping_key: &[u8],
    inner_mapping_key: &[u8],
) -> HashOutput {
    let [packed_outer_key, packed_inner_key] = [outer_mapping_key, inner_mapping_key].map(|key| {
        left_pad32(key)
            .pack(Endianness::Big)
            .into_iter()
            .map(F::from_canonical_u32)
    });
    // Compute the unique data to identify a row is the mapping key:
    // row_unique_data = H(outer_key || inner_key)
    let inputs = packed_outer_key.chain(packed_inner_key).collect_vec();
    H::hash_no_pad(&inputs).into()
}

/// Function to compute a storage value digest
pub fn storage_value_digest(
    table_metadata: &TableMetadata,
    keys: &[&[u8]],
    value: &[u8; MAPPING_LEAF_VALUE_LEN],
    evm_word: u32,
) -> Digest {
    let padded_keys = keys
        .iter()
        .map(|slice| left_pad32(slice))
        .collect::<Vec<[u8; 32]>>();
    // Panic if the number of keys provided is not equal to the number of input columns
    assert_eq!(
        keys.len(),
        table_metadata.input_columns.len(),
        "Number of keys: {}, does not equal the number of input columns: {}",
        keys.len(),
        table_metadata.input_columns.len()
    );
    table_metadata.storage_values_digest(padded_keys.as_slice(), value.as_slice(), evm_word)
}
