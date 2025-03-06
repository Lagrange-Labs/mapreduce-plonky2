use crate::api::SlotInput;
use alloy::primitives::Address;
use anyhow::{ensure, Result};
use gadgets::{
    column_gadget::{filter_table_column_identifiers, ColumnGadgetData},
    column_info::ColumnInfo,
    metadata_gadget::ColumnsMetadata,
};
use itertools::Itertools;
use mp2_common::{
    eth::{left_pad32, StorageSlot},
    group_hashing::map_to_curve_point,
    poseidon::{hash_to_int_value, H},
    types::{HashOutput, MAPPING_LEAF_VALUE_LEN},
    utils::{Endianness, Packer, ToFields},
    F,
};
use plonky2::{
    field::types::{Field, PrimeField64},
    hash::hash_types::HashOut,
    plonk::config::Hasher,
};
use plonky2_ecgfp5::curve::{curve::Point as Digest, scalar_field::Scalar};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, iter::once};

pub mod api;
mod branch;
mod extension;
pub mod gadgets;
mod leaf_mapping;
mod leaf_mapping_of_mappings;
mod leaf_single;
pub mod public_inputs;

pub use api::{build_circuits_params, generate_proof, CircuitInput, PublicParameters};
pub use public_inputs::PublicInputs;

use crate::indexing::row::CellCollection;

/// Constant prefixes for the mapping key ID. Restrict to 4-bytes (Uint32).
pub(crate) const KEY_ID_PREFIX: &[u8] = b"\0KEY";

/// Constant prefixes for the inner and outer key IDs of mapping slot.
/// Restrict to 8-bytes (Uint64).
pub(crate) const INNER_KEY_ID_PREFIX: &[u8] = b"\0\0IN_KEY";
pub(crate) const OUTER_KEY_ID_PREFIX: &[u8] = b"\0OUT_KEY";

pub(crate) const BLOCK_ID_DST: &[u8] = b"BLOCK_NUMBER";
pub(crate) const OFFCHAIN_TABLE_DST: &str = "OFFCHAIN_TABLE";

/// Compute the identifier for a column of a table containing off-chain data
pub fn identifier_offchain_column(table_name: &str, column_name: &str) -> u64 {
    let inputs: Vec<F> = vec![OFFCHAIN_TABLE_DST, table_name, column_name]
        .into_iter()
        .flat_map(|name| name.as_bytes().to_fields())
        .collect_vec();
    H::hash_no_pad(&inputs).elements[0].to_canonical_u64()
}

/// Storage slot information for generating the extraction proof
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct StorageSlotInfo {
    slot: StorageSlot,
    table_info: Vec<ColumnInfo>,
}

impl StorageSlotInfo {
    pub fn new(slot: StorageSlot, table_info: Vec<ColumnInfo>) -> Self {
        Self { slot, table_info }
    }

    pub fn slot(&self) -> &StorageSlot {
        &self.slot
    }

    pub fn table_info(&self) -> &[ColumnInfo] {
        &self.table_info
    }

    pub fn evm_word(&self) -> u32 {
        self.slot.evm_offset()
    }

    pub fn metadata<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>(
        &self,
    ) -> ColumnsMetadata<MAX_COLUMNS, MAX_FIELD_PER_EVM> {
        let evm_word = self.evm_word();
        let extracted_column_identifiers =
            filter_table_column_identifiers(&self.table_info, self.slot.slot(), evm_word);

        ColumnsMetadata::new(
            self.table_info.clone(),
            &extracted_column_identifiers,
            evm_word,
        )
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
        self.metadata::<MAX_COLUMNS, MAX_FIELD_PER_EVM>()
            .extracted_table_info()
            .iter()
            .map(Into::into)
            .collect_vec()
    }
}

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
fn compute_id_with_prefix(
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
    row_unique_data(vec![])
}

/// Compute the row unique data for mapping leaf.
pub fn row_unique_data_for_mapping_leaf(mapping_key: &[u8]) -> HashOutput {
    row_unique_data(vec![mapping_key])
}

/// Compute the row unique data for mapping of mappings leaf.
pub fn row_unique_data_for_mapping_of_mappings_leaf(
    outer_mapping_key: &[u8],
    inner_mapping_key: &[u8],
) -> HashOutput {
    row_unique_data(vec![outer_mapping_key, inner_mapping_key])
}

/// Compute the metadata digest for single variable leaf.
pub fn compute_leaf_single_metadata_digest<
    const MAX_COLUMNS: usize,
    const MAX_FIELD_PER_EVM: usize,
>(
    table_info: Vec<ColumnInfo>,
) -> Digest {
    // We don't need `extracted_column_identifiers` and `evm_word` to compute the metadata digest.
    ColumnsMetadata::<MAX_COLUMNS, MAX_FIELD_PER_EVM>::new(table_info, &[], 0).digest()
}

/// Compute the values digest for single variable leaf.
pub fn compute_leaf_single_values_digest<const MAX_FIELD_PER_EVM: usize>(
    table_info: Vec<ColumnInfo>,
    extracted_column_identifiers: &[ColumnId],
    value: [u8; MAPPING_LEAF_VALUE_LEN],
) -> Digest {
    let num_actual_columns = table_info.len();
    let values_digest =
        ColumnGadgetData::<MAX_FIELD_PER_EVM>::new(table_info, extracted_column_identifiers, value)
            .digest();

    // value_digest * row_id
    let row_id = compute_row_id(row_unique_data_for_single_leaf(), num_actual_columns);
    values_digest * row_id
}

/// Compute the metadata digest for mapping variable leaf.
pub fn compute_leaf_mapping_metadata_digest<
    const MAX_COLUMNS: usize,
    const MAX_FIELD_PER_EVM: usize,
>(
    table_info: Vec<ColumnInfo>,
    slot: u8,
    key_id: ColumnId,
) -> Digest {
    // We don't need `extracted_column_identifiers` and `evm_word` to compute the metadata digest.
    let metadata_digest =
        ColumnsMetadata::<MAX_COLUMNS, MAX_FIELD_PER_EVM>::new(table_info, &[], 0).digest();

    // key_column_md = H( "\0KEY" || slot)
    let key_id_prefix = u32::from_be_bytes(KEY_ID_PREFIX.try_into().unwrap());
    let inputs = vec![
        F::from_canonical_u32(key_id_prefix),
        F::from_canonical_u8(slot),
    ];
    let key_column_md = H::hash_no_pad(&inputs);
    // metadata_digest += D(key_column_md || key_id)
    let inputs = key_column_md
        .to_fields()
        .into_iter()
        .chain(once(F::from_canonical_u64(key_id)))
        .collect_vec();
    let metadata_key_digest = map_to_curve_point(&inputs);

    metadata_digest + metadata_key_digest
}

/// Compute the values digest for mapping variable leaf.
pub fn compute_leaf_mapping_values_digest<const MAX_FIELD_PER_EVM: usize>(
    table_info: Vec<ColumnInfo>,
    extracted_column_identifiers: &[u64],
    value: [u8; MAPPING_LEAF_VALUE_LEN],
    mapping_key: MappingKey,
    evm_word: u32,
    key_id: ColumnId,
) -> Digest {
    // We add key column to number of actual columns.
    let num_actual_columns = table_info.len() + 1;
    let mut values_digest =
        ColumnGadgetData::<MAX_FIELD_PER_EVM>::new(table_info, extracted_column_identifiers, value)
            .digest();

    // values_digest += evm_word == 0 ? D(key_id || pack(left_pad32(key))) : CURVE_ZERO
    let packed_mapping_key = left_pad32(&mapping_key)
        .pack(Endianness::Big)
        .into_iter()
        .map(F::from_canonical_u32);
    if evm_word == 0 {
        let inputs = once(F::from_canonical_u64(key_id))
            .chain(packed_mapping_key.clone())
            .collect_vec();
        let values_key_digest = map_to_curve_point(&inputs);
        values_digest += values_key_digest;
    }
    let row_unique_data = row_unique_data_for_mapping_leaf(&mapping_key);

    // value_digest * row_id
    let row_id = compute_row_id(row_unique_data, num_actual_columns);
    values_digest * row_id
}

/// Compute the metadata digest for mapping of mappings leaf.
pub fn compute_leaf_mapping_of_mappings_metadata_digest<
    const MAX_COLUMNS: usize,
    const MAX_FIELD_PER_EVM: usize,
>(
    table_info: Vec<ColumnInfo>,
    slot: u8,
    outer_key_id: ColumnId,
    inner_key_id: ColumnId,
) -> Digest {
    // We don't need `extracted_column_identifiers` and `evm_word` to compute the metadata digest.
    let metadata_digest =
        ColumnsMetadata::<MAX_COLUMNS, MAX_FIELD_PER_EVM>::new(table_info, &[], 0).digest();

    // Compute the outer and inner key metadata digests.
    let [outer_key_digest, inner_key_digest] = [
        (OUTER_KEY_ID_PREFIX, outer_key_id),
        (INNER_KEY_ID_PREFIX, inner_key_id),
    ]
    .map(|(prefix, key_id)| {
        // key_column_md = H(KEY_ID_PREFIX || slot)
        let prefix = u64::from_be_bytes(prefix.try_into().unwrap());
        let inputs = vec![F::from_canonical_u64(prefix), F::from_canonical_u8(slot)];
        let key_column_md = H::hash_no_pad(&inputs);

        // key_digest = D(key_column_md || key_id)
        let inputs = key_column_md
            .to_fields()
            .into_iter()
            .chain(once(F::from_canonical_u64(key_id)))
            .collect_vec();
        map_to_curve_point(&inputs)
    });

    // Add the outer and inner key digests into the metadata digest.
    // metadata_digest + outer_key_digest + inner_key_digest
    metadata_digest + inner_key_digest + outer_key_digest
}

pub type MappingKey = Vec<u8>;
pub type ColumnId = u64;

/// Compute the values digest for mapping of mappings leaf.
#[allow(clippy::too_many_arguments)]
pub fn compute_leaf_mapping_of_mappings_values_digest<const MAX_FIELD_PER_EVM: usize>(
    table_info: Vec<ColumnInfo>,
    extracted_column_identifiers: &[ColumnId],
    value: [u8; MAPPING_LEAF_VALUE_LEN],
    evm_word: u32,
    outer_mapping_data: (MappingKey, ColumnId),
    inner_mapping_data: (MappingKey, ColumnId),
) -> Digest {
    // Add inner key and outer key columns to the number of actual columns.
    let num_actual_columns = table_info.len() + 2;
    let mut values_digest =
        ColumnGadgetData::<MAX_FIELD_PER_EVM>::new(table_info, extracted_column_identifiers, value)
            .digest();

    // Compute the outer and inner key values digests.
    let [packed_outer_key, packed_inner_key] =
        [&outer_mapping_data.0, &inner_mapping_data.0].map(|key| {
            left_pad32(key)
                .pack(Endianness::Big)
                .into_iter()
                .map(F::from_canonical_u32)
        });
    if evm_word == 0 {
        let [outer_key_digest, inner_key_digest] = [
            (outer_mapping_data.1, packed_outer_key.clone()),
            (inner_mapping_data.1, packed_inner_key.clone()),
        ]
        .map(|(key_id, packed_key)| {
            // D(key_id || pack(key))
            let inputs = once(F::from_canonical_u64(key_id))
                .chain(packed_key)
                .collect_vec();
            map_to_curve_point(&inputs)
        });
        // values_digest += outer_key_digest + inner_key_digest
        values_digest += inner_key_digest + outer_key_digest;
    }

    let row_unique_data =
        row_unique_data_for_mapping_of_mappings_leaf(&outer_mapping_data.0, &inner_mapping_data.0);

    // values_digest = values_digest * row_id
    let row_id = compute_row_id(row_unique_data, num_actual_columns);
    values_digest * row_id
}

/// Compute the row unique data using the set of column values provided as input
pub fn row_unique_data<'a, I: IntoIterator<Item = &'a [u8]>>(columns: I) -> HashOutput {
    let packed_columns = columns
        .into_iter()
        .flat_map(|column| {
            left_pad32(column)
                .pack(Endianness::Big)
                .into_iter()
                .map(F::from_canonical_u32)
        })
        .collect_vec();
    H::hash_no_pad(&packed_columns).into()
}

fn compute_row_id(row_unique_data: HashOutput, num_actual_columns: usize) -> Scalar {
    // row_id = H2int(row_unique_data || num_actual_columns)
    let inputs = HashOut::from(row_unique_data)
        .to_fields()
        .into_iter()
        .chain(once(F::from_canonical_usize(num_actual_columns)))
        .collect_vec();
    let hash = H::hash_no_pad(&inputs);
    let row_id = hash_to_int_value(hash);

    Scalar::from_noncanonical_biguint(row_id)
}

/// Compute the row value digest of one table, taking as input the rows of the
/// table and the identifiers of columns employed to compute the row unique data
pub fn compute_table_row_digest<PrimaryIndex: PartialEq + Eq + Default + Clone + Debug>(
    table_rows: &[CellCollection<PrimaryIndex>],
    row_unique_columns: &[ColumnId],
) -> Result<Digest> {
    let column_ids = table_rows[0].column_ids();
    let num_actual_columns = column_ids.len();
    // check that the identifiers of row unique columns are actual identifiers of the columns
    // of the table
    ensure!(row_unique_columns.iter().all(|id| column_ids.contains(id)));
    Ok(table_rows
        .iter()
        .enumerate()
        .fold(Digest::NEUTRAL, |acc, (i, row)| {
            let current_column_ids = row.column_ids();
            // check that column ids are the same for each row
            assert_eq!(
                current_column_ids, column_ids,
                "row {i} has different column ids than other rows"
            );
            let current_row_digest =
                current_column_ids
                    .into_iter()
                    .fold(Digest::NEUTRAL, |acc, id| {
                        let current = map_to_curve_point(
                            &once(F::from_canonical_u64(id))
                                .chain(row.find_by_column(id).unwrap().value.to_fields())
                                .collect_vec(),
                        );
                        acc + current
                    });
            // compute row unique data for current row
            let row_unique_data = {
                let column_values = row_unique_columns
                    .iter()
                    .map(|&id| {
                        row.find_by_column(id)
                            .unwrap()
                            .value
                            .to_be_bytes_trimmed_vec()
                    })
                    .collect_vec();
                row_unique_data(column_values.iter().map(|v| v.as_slice()))
            };
            // compute row_id to be multiplied to `current_row_digest`
            let row_id = compute_row_id(row_unique_data, num_actual_columns);
            // accumulate with digest of previous rows
            acc + row_id * current_row_digest
        }))
}
