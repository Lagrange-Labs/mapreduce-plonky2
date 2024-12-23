use crate::api::SlotInput;

use anyhow::anyhow;
use gadgets::{
    column_info::{ExtractedColumnInfo, InputColumnInfo},
    metadata_gadget::TableMetadata,
};
use itertools::Itertools;

use alloy::primitives::Address;
use mp2_common::{
    eth::{left_pad32, EventLogInfo, StorageSlot},
    poseidon::{empty_poseidon_hash, H},
    types::{GFp, HashOutput},
    utils::{Endianness, Packer, ToFields},
    F,
};
use plonky2::{
    field::types::{Field, PrimeField64},
    plonk::config::Hasher,
};

use plonky2_ecgfp5::curve::curve::Point;

use serde::{Deserialize, Serialize};
use std::iter::once;

pub mod api;
mod branch;
mod extension;
pub mod gadgets;
mod leaf_mapping;
mod leaf_mapping_of_mappings;
mod leaf_receipt;
mod leaf_single;
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
    ) -> ColumnMetadata {
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

        ColumnMetadata::new(input_columns, self.table_info().to_vec())
    }
}

/// Struct that mirrors [`TableMetadata`] but without having to specify generic constants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnMetadata {
    pub input_columns: Vec<InputColumnInfo>,
    pub extracted_columns: Vec<ExtractedColumnInfo>,
}

impl ColumnMetadata {
    /// Create a new instance of [`ColumnMetadata`]
    pub fn new(
        input_columns: Vec<InputColumnInfo>,
        extracted_columns: Vec<ExtractedColumnInfo>,
    ) -> ColumnMetadata {
        ColumnMetadata {
            input_columns,
            extracted_columns,
        }
    }

    /// Getter for the [`InputColumnInfo`]
    pub fn input_columns(&self) -> &[InputColumnInfo] {
        &self.input_columns
    }

    /// Getter for the [`ExtractedColumnInfo`]
    pub fn extracted_columns(&self) -> &[ExtractedColumnInfo] {
        &self.extracted_columns
    }

    /// Computes the value digest for a provided value array and the unique row_id
    pub fn input_value_digest(&self, input_vals: &[&[u8; 32]]) -> (Point, HashOutput) {
        let point = self
            .input_columns()
            .iter()
            .zip(input_vals.iter())
            .fold(Point::NEUTRAL, |acc, (column, value)| {
                acc + column.value_digest(value.as_slice())
            });

        let row_id_input = input_vals
            .into_iter()
            .map(|key| {
                key.pack(Endianness::Big)
                    .into_iter()
                    .map(F::from_canonical_u32)
            })
            .into_iter()
            .flatten()
            .collect::<Vec<F>>();

        (point, H::hash_no_pad(&row_id_input).into())
    }

    /// Compute the metadata digest.
    pub fn digest(&self) -> Point {
        let input_iter = self
            .input_columns()
            .iter()
            .map(|column| column.digest())
            .collect::<Vec<Point>>();

        let extracted_iter = self
            .extracted_columns()
            .iter()
            .map(|column| column.digest())
            .collect::<Vec<Point>>();

        input_iter
            .into_iter()
            .chain(extracted_iter)
            .fold(Point::NEUTRAL, |acc, b| acc + b)
    }

    pub fn extracted_value_digest(
        &self,
        value: &[u8],
        extraction_id: &[u8],
        location_offset: F,
    ) -> Point {
        let mut extraction_vec = extraction_id.pack(Endianness::Little);
        extraction_vec.resize(8, 0u32);
        extraction_vec.reverse();
        let extraction_id: [F; 8] = extraction_vec
            .into_iter()
            .map(F::from_canonical_u32)
            .collect::<Vec<F>>()
            .try_into()
            .expect("This should never fail");

        self.extracted_columns()
            .iter()
            .fold(Point::NEUTRAL, |acc, column| {
                let correct_id = extraction_id == column.extraction_id();
                let correct_offset = location_offset == column.location_offset();
                let correct_location = correct_id && correct_offset;

                if correct_location {
                    acc + column.value_digest(value)
                } else {
                    acc
                }
            })
    }
}

impl<const MAX_COLUMNS: usize, const INPUT_COLUMNS: usize> TryFrom<ColumnMetadata>
    for TableMetadata<MAX_COLUMNS, INPUT_COLUMNS>
where
    [(); MAX_COLUMNS - INPUT_COLUMNS]:,
{
    type Error = anyhow::Error;

    fn try_from(value: ColumnMetadata) -> Result<Self, Self::Error> {
        let ColumnMetadata {
            input_columns,
            extracted_columns,
        } = value;
        let input_array: [InputColumnInfo; INPUT_COLUMNS] =
            input_columns.try_into().map_err(|e| {
                anyhow!(
                    "Could not convert input columns to fixed length array: {:?}",
                    e
                )
            })?;

        Ok(TableMetadata::<MAX_COLUMNS, INPUT_COLUMNS>::new(
            &input_array,
            &extracted_columns,
        ))
    }
}

/// Prefix used for making a topic column id.
const TOPIC_PREFIX: &[u8] = b"topic";
/// [`TOPIC_PREFIX`] as a [`str`]
const TOPIC_NAME: &str = "topic";

/// Prefix used for making a data column id.
const DATA_PREFIX: &[u8] = b"data";
/// [`DATA_PREFIX`] as a [`str`]
const DATA_NAME: &str = "data";

/// Prefix for transaction index
const TX_INDEX_PREFIX: &[u8] = b"tx index";

/// Prefix for log number
const LOG_NUMBER_PREFIX: &[u8] = b"log number";
/// [`LOG_NUMBER_PREFIX`] as a [`str`]
const LOG_NUMBER_NAME: &str = "log number";

/// Prefix for gas used
const GAS_USED_PREFIX: &[u8] = b"gas used";
/// [`GAS_USED_PREFIX`] as a [`str`]
const GAS_USED_NAME: &str = "gas used";

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

/// Function that computes the column identifiers for the non-indexed columns together with their names as [`String`]s.
pub fn compute_non_indexed_receipt_column_ids<const NO_TOPICS: usize, const MAX_DATA: usize>(
    event: &EventLogInfo<NO_TOPICS, MAX_DATA>,
) -> Vec<(String, GFp)> {
    let gas_used_input = [
        event.address.as_slice(),
        event.event_signature.as_slice(),
        GAS_USED_PREFIX,
    ]
    .concat()
    .into_iter()
    .map(GFp::from_canonical_u8)
    .collect::<Vec<GFp>>();
    let gas_used_column_id = H::hash_no_pad(&gas_used_input).elements[0];

    let topic_ids = event
        .topics
        .iter()
        .enumerate()
        .map(|(j, _)| {
            let input = [
                event.address.as_slice(),
                event.event_signature.as_slice(),
                TOPIC_PREFIX,
                &[j as u8 + 1],
            ]
            .concat()
            .into_iter()
            .map(GFp::from_canonical_u8)
            .collect::<Vec<GFp>>();
            (
                format!("{}_{}", TOPIC_NAME, j + 1),
                H::hash_no_pad(&input).elements[0],
            )
        })
        .collect::<Vec<(String, GFp)>>();

    let data_ids = event
        .data
        .iter()
        .enumerate()
        .map(|(j, _)| {
            let input = [
                event.address.as_slice(),
                event.event_signature.as_slice(),
                DATA_PREFIX,
                &[j as u8 + 1],
            ]
            .concat()
            .into_iter()
            .map(GFp::from_canonical_u8)
            .collect::<Vec<GFp>>();
            (
                format!("{}_{}", DATA_NAME, j + 1),
                H::hash_no_pad(&input).elements[0],
            )
        })
        .collect::<Vec<(String, GFp)>>();

    [
        vec![(GAS_USED_NAME.to_string(), gas_used_column_id)],
        topic_ids,
        data_ids,
    ]
    .concat()
}
