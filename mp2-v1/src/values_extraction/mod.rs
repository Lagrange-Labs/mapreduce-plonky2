use crate::api::SlotInput;

use gadgets::{
    column_gadget::{filter_table_column_identifiers, ColumnGadgetData},
    column_info::ColumnInfo,
    metadata_gadget::ColumnsMetadata,
};
use itertools::Itertools;

use alloy::{
    consensus::TxReceipt,
    primitives::{Address, IntoLogData},
};
use mp2_common::{
    eth::{left_pad32, EventLogInfo, ReceiptProofInfo, StorageSlot},
    group_hashing::map_to_curve_point,
    poseidon::{empty_poseidon_hash, hash_to_int_value, H},
    types::{GFp, HashOutput, MAPPING_LEAF_VALUE_LEN},
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
use std::iter::{self, once};

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
    ) -> Option<u64> {
        let extra = identifier_raw_extra(contract_address, chain_id, extra);

        self.outer_key_id_raw(extra)
    }

    pub fn inner_key_id(
        &self,
        contract_address: &Address,
        chain_id: u64,
        extra: Vec<u8>,
    ) -> Option<u64> {
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
/// Prefix used for making a topic column id.
const TOPIC_PREFIX: &[u8] = b"topic";

/// Prefix used for making a data column id.
const DATA_PREFIX: &[u8] = b"data";

/// Prefix for transaction index
const TX_INDEX_PREFIX: &[u8] = b"tx index";

/// Prefix for log number
const LOG_NUMBER_PREFIX: &[u8] = b"log number";

/// Prefix for gas used
const GAS_USED_PREFIX: &[u8] = b" gas used";

pub fn identifier_block_column() -> u64 {
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
) -> u64 {
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
pub fn identifier_for_value_column_raw(input: &SlotInput, extra: Vec<u8>) -> u64 {
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
) -> u64 {
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
) -> u64 {
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
) -> u64 {
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
) -> u64 {
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
fn compute_id_with_prefix_raw(prefix: &[u8], slot: u8, extra: Vec<u8>) -> u64 {
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
    extracted_column_identifiers: &[u64],
    value: [u8; MAPPING_LEAF_VALUE_LEN],
) -> Digest {
    let num_actual_columns = F::from_canonical_usize(table_info.len());
    let values_digest =
        ColumnGadgetData::<MAX_FIELD_PER_EVM>::new(table_info, extracted_column_identifiers, value)
            .digest();

    // row_id = H2int(H("") || num_actual_columns)
    let inputs = HashOut::from(row_unique_data_for_single_leaf())
        .to_fields()
        .into_iter()
        .chain(once(num_actual_columns))
        .collect_vec();
    let hash = H::hash_no_pad(&inputs);
    let row_id = hash_to_int_value(hash);

    // value_digest * row_id
    let row_id = Scalar::from_noncanonical_biguint(row_id);
    values_digest * row_id
}

/// Compute the metadata digest for mapping variable leaf.
pub fn compute_leaf_mapping_metadata_digest<
    const MAX_COLUMNS: usize,
    const MAX_FIELD_PER_EVM: usize,
>(
    table_info: Vec<ColumnInfo>,
    slot: u8,
    key_id: u64,
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
    mapping_key: Vec<u8>,
    evm_word: u32,
    key_id: u64,
) -> Digest {
    // We add key column to number of actual columns.
    let num_actual_columns = F::from_canonical_usize(table_info.len() + 1);
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
    let row_unique_data = HashOut::from(row_unique_data_for_mapping_leaf(&mapping_key));
    // row_id = H2int(row_unique_data || num_actual_columns)
    let inputs = row_unique_data
        .to_fields()
        .into_iter()
        .chain(once(num_actual_columns))
        .collect_vec();
    let hash = H::hash_no_pad(&inputs);
    let row_id = hash_to_int_value(hash);

    // value_digest * row_id
    let row_id = Scalar::from_noncanonical_biguint(row_id);
    values_digest * row_id
}

/// Compute the metadata digest for mapping of mappings leaf.
pub fn compute_leaf_mapping_of_mappings_metadata_digest<
    const MAX_COLUMNS: usize,
    const MAX_FIELD_PER_EVM: usize,
>(
    table_info: Vec<ColumnInfo>,
    slot: u8,
    outer_key_id: u64,
    inner_key_id: u64,
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

/// Compute the values digest for mapping of mappings leaf.
#[allow(clippy::too_many_arguments)]
pub fn compute_leaf_mapping_of_mappings_values_digest<const MAX_FIELD_PER_EVM: usize>(
    table_info: Vec<ColumnInfo>,
    extracted_column_identifiers: &[u64],
    value: [u8; MAPPING_LEAF_VALUE_LEN],
    evm_word: u32,
    outer_mapping_key: Vec<u8>,
    inner_mapping_key: Vec<u8>,
    outer_key_id: u64,
    inner_key_id: u64,
) -> Digest {
    // Add inner key and outer key columns to the number of actual columns.
    let num_actual_columns = F::from_canonical_usize(table_info.len() + 2);
    let mut values_digest =
        ColumnGadgetData::<MAX_FIELD_PER_EVM>::new(table_info, extracted_column_identifiers, value)
            .digest();

    // Compute the outer and inner key values digests.
    let [packed_outer_key, packed_inner_key] =
        [&outer_mapping_key, &inner_mapping_key].map(|key| {
            left_pad32(key)
                .pack(Endianness::Big)
                .into_iter()
                .map(F::from_canonical_u32)
        });
    if evm_word == 0 {
        let [outer_key_digest, inner_key_digest] = [
            (outer_key_id, packed_outer_key.clone()),
            (inner_key_id, packed_inner_key.clone()),
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

    let row_unique_data = HashOut::from(row_unique_data_for_mapping_of_mappings_leaf(
        &outer_mapping_key,
        &inner_mapping_key,
    ));
    // row_id = H2int(row_unique_data || num_actual_columns)
    let inputs = row_unique_data
        .to_fields()
        .into_iter()
        .chain(once(num_actual_columns))
        .collect_vec();
    let hash = H::hash_no_pad(&inputs);
    let row_id = hash_to_int_value(hash);

    // values_digest = values_digest * row_id
    let row_id = Scalar::from_noncanonical_biguint(row_id);
    values_digest * row_id
}
/// Calculate `metadata_digest = D(address || signature || topics)` for receipt leaf.
/// Topics is an array of 5 values (some are dummies), each being `column_id`, `rel_byte_offset` (from the start of the log)
/// and `len`.
pub fn compute_receipt_leaf_metadata_digest<const NO_TOPICS: usize, const MAX_DATA: usize>(
    event: &EventLogInfo<NO_TOPICS, MAX_DATA>,
) -> Digest {
    let mut out = Vec::new();
    out.push(event.size);
    out.extend_from_slice(&event.address.0.map(|byte| byte as usize));
    out.push(event.add_rel_offset);
    out.extend_from_slice(&event.event_signature.map(|byte| byte as usize));
    out.push(event.sig_rel_offset);

    let mut field_out = out
        .into_iter()
        .map(GFp::from_canonical_usize)
        .collect::<Vec<GFp>>();
    // Work out the column ids for tx_index, log_number and gas_used
    let tx_index_input = [
        event.address.as_slice(),
        event.event_signature.as_slice(),
        TX_INDEX_PREFIX,
    ]
    .concat()
    .into_iter()
    .map(GFp::from_canonical_u8)
    .collect::<Vec<GFp>>();
    let tx_index_column_id = H::hash_no_pad(&tx_index_input).elements[0];

    let log_number_input = [
        event.address.as_slice(),
        event.event_signature.as_slice(),
        LOG_NUMBER_PREFIX,
    ]
    .concat()
    .into_iter()
    .map(GFp::from_canonical_u8)
    .collect::<Vec<GFp>>();
    let log_number_column_id = H::hash_no_pad(&log_number_input).elements[0];

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
    field_out.push(tx_index_column_id);
    field_out.push(log_number_column_id);
    field_out.push(gas_used_column_id);

    let core_metadata = map_to_curve_point(&field_out);

    let topic_digests = event
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
            let column_id = H::hash_no_pad(&input).elements[0];
            map_to_curve_point(&[column_id])
        })
        .collect::<Vec<Digest>>();

    let data_digests = event
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
            let column_id = H::hash_no_pad(&input).elements[0];
            map_to_curve_point(&[column_id])
        })
        .collect::<Vec<Digest>>();

    iter::once(core_metadata)
        .chain(topic_digests)
        .chain(data_digests)
        .fold(Digest::NEUTRAL, |acc, p| acc + p)
}

/// Calculate `value_digest` for receipt leaf.
pub fn compute_receipt_leaf_value_digest<const NO_TOPICS: usize, const MAX_DATA: usize>(
    receipt_proof_info: &ReceiptProofInfo,
    event: &EventLogInfo<NO_TOPICS, MAX_DATA>,
) -> Digest {
    let receipt = receipt_proof_info.to_receipt().unwrap();
    let gas_used = receipt.cumulative_gas_used();

    // Only use events that we are indexing
    let address = event.address;
    let sig = event.event_signature;

    // Work out the column ids for tx_index, log_number and gas_used
    let tx_index_input = [
        event.address.as_slice(),
        event.event_signature.as_slice(),
        TX_INDEX_PREFIX,
    ]
    .concat()
    .into_iter()
    .map(GFp::from_canonical_u8)
    .collect::<Vec<GFp>>();
    let tx_index_column_id = H::hash_no_pad(&tx_index_input).elements[0];

    let log_number_input = [
        event.address.as_slice(),
        event.event_signature.as_slice(),
        LOG_NUMBER_PREFIX,
    ]
    .concat()
    .into_iter()
    .map(GFp::from_canonical_u8)
    .collect::<Vec<GFp>>();
    let log_number_column_id = H::hash_no_pad(&log_number_input).elements[0];

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

    let index_digest = map_to_curve_point(&[
        tx_index_column_id,
        GFp::from_canonical_u64(receipt_proof_info.tx_index),
    ]);

    let gas_digest =
        map_to_curve_point(&[gas_used_column_id, GFp::from_noncanonical_u128(gas_used)]);
    let mut n = 0;
    receipt
        .logs()
        .iter()
        .cloned()
        .filter_map(|log| {
            let log_address = log.address;
            let log_data = log.to_log_data();
            let (topics, data) = log_data.split();

            if log_address == address && topics[0].0 == sig {
                n += 1;
                let topics_value_digest = topics
                    .iter()
                    .enumerate()
                    .skip(1)
                    .map(|(j, fixed)| {
                        let packed = fixed.0.pack(mp2_common::utils::Endianness::Big).to_fields();
                        let input = [
                            event.address.as_slice(),
                            event.event_signature.as_slice(),
                            TOPIC_PREFIX,
                            &[j as u8],
                        ]
                        .concat()
                        .into_iter()
                        .map(GFp::from_canonical_u8)
                        .collect::<Vec<GFp>>();
                        let mut values = vec![H::hash_no_pad(&input).elements[0]];
                        values.extend_from_slice(&packed);
                        map_to_curve_point(&values)
                    })
                    .collect::<Vec<_>>();
                let data_value_digest = data
                    .chunks(32)
                    .enumerate()
                    .map(|(j, fixed)| {
                        let packed = fixed.pack(mp2_common::utils::Endianness::Big).to_fields();
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
                        let mut values = vec![H::hash_no_pad(&input).elements[0]];
                        values.extend_from_slice(&packed);
                        map_to_curve_point(&values)
                    })
                    .collect::<Vec<_>>();
                let log_no_digest =
                    map_to_curve_point(&[log_number_column_id, GFp::from_canonical_usize(n)]);
                let initial_digest = index_digest + gas_digest + log_no_digest;

                let row_value = std::iter::once(initial_digest)
                    .chain(topics_value_digest)
                    .chain(data_value_digest)
                    .fold(Digest::NEUTRAL, |acc, p| acc + p);

                Some(map_to_curve_point(&row_value.to_fields()))
            } else {
                None
            }
        })
        .fold(Digest::NEUTRAL, |acc, p| acc + p)
}
