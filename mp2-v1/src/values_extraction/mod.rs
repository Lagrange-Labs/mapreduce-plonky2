use alloy::{
    consensus::TxReceipt,
    primitives::{Address, IntoLogData, B256, U256},
};
use mp2_common::{
    eth::{left_pad32, EventLogInfo, ReceiptProofInfo},
    group_hashing::map_to_curve_point,
    poseidon::H,
    types::{GFp, MAPPING_KEY_LEN, MAPPING_LEAF_VALUE_LEN},
    utils::{Endianness, Packer, ToFields},
    F,
};
use plonky2::{
    field::types::{Field, PrimeField64},
    plonk::config::Hasher,
};
use plonky2_ecgfp5::curve::curve::Point as Digest;
use std::iter;

pub mod api;
mod branch;
mod extension;
mod leaf_mapping;
mod leaf_receipt;
mod leaf_single;
pub mod planner;
pub mod public_inputs;

pub use api::{build_circuits_params, generate_proof, CircuitInput, PublicParameters};
pub use public_inputs::PublicInputs;

/// Constant prefixes for key and value IDs. Restrict both prefixes to 3-bytes,
/// so `prefix + slot (u8)` could be converted to an U32.
pub(crate) const KEY_ID_PREFIX: &[u8] = b"KEY";
pub(crate) const VALUE_ID_PREFIX: &[u8] = b"VAL";

pub(crate) const BLOCK_ID_DST: &[u8] = b"BLOCK_NUMBER";

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
/// [`TX_INDEX_PREFIX`] as a [`str`]
const TX_INDEX_NAME: &str = "tx index";

/// Prefix for log number
const LOG_NUMBER_PREFIX: &[u8] = b"log number";
/// [`LOG_NUMBER_PREFIX`] as a [`str`]
const LOG_NUMBER_NAME: &str = "log number";

/// Prefix for gas used
const GAS_USED_PREFIX: &[u8] = b"gas used";
/// [`GAS_USED_PREFIX`] as a [`str`]
const GAS_USED_NAME: &str = "gas used";

pub fn identifier_block_column() -> u64 {
    let inputs: Vec<F> = BLOCK_ID_DST.to_fields();
    H::hash_no_pad(&inputs).elements[0].to_canonical_u64()
}

/// Calculate `id = Poseidon(slot || contract_address)[0]` for single variable.
pub fn identifier_single_var_column(
    slot: u8,
    contract_address: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> u64 {
    let fields = contract_address
        .0
        .iter()
        .copied()
        .chain(chain_id.to_be_bytes())
        .chain(extra)
        .collect::<Vec<u8>>()
        .to_fields();

    let inputs: Vec<_> = iter::once(GFp::from_canonical_u8(slot))
        .chain(fields)
        .collect();

    H::hash_no_pad(&inputs).elements[0].to_canonical_u64()
}

/// Calculate `key_id = Poseidon(KEY || slot || contract_address)[0]` for mapping variable leaf.
pub fn identifier_for_mapping_key_column(
    slot: u8,
    contract_address: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> u64 {
    compute_id_with_prefix(KEY_ID_PREFIX, slot, contract_address, chain_id, extra)
}

/// Calculate `value_id = Poseidon(VAL || slot || contract_address)[0]` for mapping variable leaf.
pub fn identifier_for_mapping_value_column(
    slot: u8,
    contract_address: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> u64 {
    compute_id_with_prefix(VALUE_ID_PREFIX, slot, contract_address, chain_id, extra)
}

/// Calculate ID with prefix.
fn compute_id_with_prefix(
    prefix: &[u8],
    slot: u8,
    contract_address: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> u64 {
    let inputs: Vec<F> = prefix
        .iter()
        .cloned()
        .chain(iter::once(slot))
        .chain(contract_address.0)
        .chain(chain_id.to_be_bytes())
        .chain(extra)
        .collect::<Vec<u8>>()
        .to_fields();

    H::hash_no_pad(&inputs).elements[0].to_canonical_u64()
}

/// Calculate `values_digest = D(D(key_id || key) + D(value_id || value))` for mapping variable leaf.
pub fn compute_leaf_mapping_values_digest(
    key_id: u64,
    value_id: u64,
    mapping_key: &[u8],
    value: &[u8],
) -> Digest {
    assert!(mapping_key.len() <= MAPPING_KEY_LEN);
    assert!(value.len() <= MAPPING_LEAF_VALUE_LEN);

    let [packed_key, packed_value] =
        [mapping_key, value].map(|arr| left_pad32(arr).pack(Endianness::Big).to_fields());

    let inputs: Vec<_> = iter::once(GFp::from_canonical_u64(key_id))
        .chain(packed_key)
        .collect();
    let k_digest = map_to_curve_point(&inputs);
    let inputs: Vec<_> = iter::once(GFp::from_canonical_u64(value_id))
        .chain(packed_value)
        .collect();
    let v_digest = map_to_curve_point(&inputs);
    // D(key_id || key) + D(value_id || value)
    let add_digest = (k_digest + v_digest).to_weierstrass();
    let inputs: Vec<_> = add_digest
        .x
        .0
        .into_iter()
        .chain(add_digest.y.0)
        .chain(iter::once(GFp::from_bool(add_digest.is_inf)))
        .collect();
    map_to_curve_point(&inputs)
}

/// Calculate `values_digest = D(id || value)` for single variable leaf.
pub fn compute_leaf_single_values_digest(id: u64, value: &[u8]) -> Digest {
    assert!(value.len() <= MAPPING_LEAF_VALUE_LEN);

    let packed_value = left_pad32(value).pack(Endianness::Big).to_fields();

    let inputs: Vec<_> = iter::once(GFp::from_canonical_u64(id))
        .chain(packed_value)
        .collect();
    map_to_curve_point(&inputs)
}

/// Calculate `metadata_digest = D(id || slot)` for single variable leaf.
pub fn compute_leaf_single_metadata_digest(id: u64, slot: u8) -> Digest {
    map_to_curve_point(&[GFp::from_canonical_u64(id), GFp::from_canonical_u8(slot)])
}

/// Calculate `metadata_digest = D(key_id || value_id || slot)` for mapping variable leaf.
pub fn compute_leaf_mapping_metadata_digest(key_id: u64, value_id: u64, slot: u8) -> Digest {
    map_to_curve_point(&[
        GFp::from_canonical_u64(key_id),
        GFp::from_canonical_u64(value_id),
        GFp::from_canonical_u8(slot),
    ])
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
    let gas_used_u256: B256 = U256::from(gas_used).into();
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

    let index_256: B256 = U256::from(receipt_proof_info.tx_index).into();
    let index_values = iter::once(tx_index_column_id)
        .chain(
            index_256
                .0
                .pack(mp2_common::utils::Endianness::Big)
                .to_fields(),
        )
        .collect::<Vec<GFp>>();
    let index_digest = map_to_curve_point(&index_values);

    let gas_used_values = iter::once(gas_used_column_id)
        .chain(
            gas_used_u256
                .0
                .pack(mp2_common::utils::Endianness::Big)
                .to_fields(),
        )
        .collect::<Vec<GFp>>();
    let gas_digest = map_to_curve_point(&gas_used_values);
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
                let log_no_256: B256 = U256::from(n).into();
                let log_no_values = iter::once(log_number_column_id)
                    .chain(
                        log_no_256
                            .0
                            .pack(mp2_common::utils::Endianness::Big)
                            .to_fields(),
                    )
                    .collect::<Vec<GFp>>();
                let log_no_digest = map_to_curve_point(&log_no_values);
                let initial_digest = index_digest + gas_digest + log_no_digest;

                let row_value = iter::once(initial_digest)
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

/// Function that computes the column identifiers for the non-indexed columns together with their names as [`String`]s.
pub fn compute_non_indexed_receipt_column_ids<const NO_TOPICS: usize, const MAX_DATA: usize>(
    event: &EventLogInfo<NO_TOPICS, MAX_DATA>,
) -> Vec<(String, GFp)> {
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
        vec![
            (LOG_NUMBER_NAME.to_string(), log_number_column_id),
            (GAS_USED_NAME.to_string(), gas_used_column_id),
        ],
        topic_ids,
        data_ids,
    ]
    .concat()
}

pub fn compute_all_receipt_coulmn_ids<const NO_TOPICS: usize, const MAX_DATA: usize>(
    event: &EventLogInfo<NO_TOPICS, MAX_DATA>,
) -> Vec<(String, GFp)> {
    let tx_index_input = [
        event.address.as_slice(),
        event.event_signature.as_slice(),
        TX_INDEX_PREFIX,
    ]
    .concat()
    .into_iter()
    .map(GFp::from_canonical_u8)
    .collect::<Vec<GFp>>();
    let tx_index_column_id = (
        TX_INDEX_NAME.to_string(),
        H::hash_no_pad(&tx_index_input).elements[0],
    );

    let mut other_ids = compute_non_indexed_receipt_column_ids(event);
    other_ids.insert(0, tx_index_column_id);

    other_ids
}
