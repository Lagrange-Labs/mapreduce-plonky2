use alloy::{
    consensus::TxReceipt,
    primitives::{Address, IntoLogData},
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
pub mod public_inputs;

pub use api::{build_circuits_params, generate_proof, CircuitInput, PublicParameters};
pub use public_inputs::PublicInputs;

/// Constant prefixes for key and value IDs. Restrict both prefixes to 3-bytes,
/// so `prefix + slot (u8)` could be converted to an U32.
pub(crate) const KEY_ID_PREFIX: &[u8] = b"KEY";
pub(crate) const VALUE_ID_PREFIX: &[u8] = b"VAL";

pub(crate) const BLOCK_ID_DST: &[u8] = b"BLOCK_NUMBER";

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
pub fn compute_receipt_leaf_metadata_digest(event: &EventLogInfo) -> Digest {
    let topics_flat = event
        .topics
        .iter()
        .chain(event.data.iter())
        .flat_map(|t| [t.column_id, t.rel_byte_offset, t.len])
        .collect::<Vec<usize>>();

    let mut out = Vec::new();
    out.push(event.size);
    out.extend_from_slice(&event.address.0.map(|byte| byte as usize));
    out.push(event.add_rel_offset);
    out.extend_from_slice(&event.event_signature.map(|byte| byte as usize));
    out.push(event.sig_rel_offset);
    out.extend_from_slice(&topics_flat);

    let data = out
        .into_iter()
        .map(GFp::from_canonical_usize)
        .collect::<Vec<_>>();
    map_to_curve_point(&data)
}

/// Calculate `value_digest` for receipt leaf.
pub fn compute_receipt_leaf_value_digest(receipt_proof_info: &ReceiptProofInfo) -> Digest {
    let receipt = receipt_proof_info.to_receipt().unwrap();
    let gas_used = receipt.cumulative_gas_used();

    // Only use events that we are indexing
    let address = receipt_proof_info.event_log_info.address;
    let sig = receipt_proof_info.event_log_info.event_signature;

    let index_digest = map_to_curve_point(&[GFp::from_canonical_u64(receipt_proof_info.tx_index)]);

    let gas_digest = map_to_curve_point(&[GFp::ZERO, GFp::from_noncanonical_u128(gas_used)]);
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
                let topics_field = topics
                    .iter()
                    .skip(1)
                    .map(|fixed| fixed.0.pack(mp2_common::utils::Endianness::Big).to_fields())
                    .collect::<Vec<_>>();
                let data_fixed_bytes = data
                    .chunks(32)
                    .map(|chunk| chunk.pack(mp2_common::utils::Endianness::Big).to_fields())
                    .take(2)
                    .collect::<Vec<_>>();
                let log_no_digest = map_to_curve_point(&[GFp::ONE, GFp::from_canonical_usize(n)]);
                let initial_digest = gas_digest + log_no_digest;
                Some(
                    topics_field
                        .iter()
                        .chain(data_fixed_bytes.iter())
                        .enumerate()
                        .fold(initial_digest, |acc, (i, fixed)| {
                            let mut values = vec![GFp::from_canonical_usize(i + 2)];
                            values.extend_from_slice(fixed);
                            acc + map_to_curve_point(&values)
                        }),
                )
            } else {
                None
            }
        })
        .fold(index_digest, |acc, p| acc + p)
}
