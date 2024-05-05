use mp2_common::{
    eth::left_pad32,
    group_hashing::map_to_curve_point,
    types::{GFp, MAPPING_KEY_LEN, MAPPING_LEAF_VALUE_LEN},
    utils::{convert_u8_to_u32_slice, pack_and_compute_poseidon_value},
};
use plonky2::{
    field::types::Field,
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    plonk::config::Hasher,
};
use plonky2_ecgfp5::curve::curve::Point;
use std::iter;

pub mod api;
mod branch;
mod extension;
mod key;
mod leaf_mapping;
mod leaf_single;
pub mod public_inputs;

pub(crate) const MAX_BRANCH_NODE_LEN: usize = 532;
/// rlp( rlp(max key 32b) + rlp(max value 32b) ) + 1 for compact encoding
/// see test_len()
pub(crate) const MAX_EXTENSION_NODE_LEN: usize = 69;
pub(crate) const MAX_LEAF_NODE_LEN: usize = MAX_EXTENSION_NODE_LEN;

/// Constant prefixes for key and value IDs. Restrict both prefixes to 3-bytes,
/// so `prefix + slot (u8)` could be converted to an U32.
pub(crate) const KEY_ID_PREFIX: &[u8] = b"KEY";
pub(crate) const VALUE_ID_PREFIX: &[u8] = b"VAL";

/// Calculate `id = Poseidon(slot)` for single variable leaf.
pub(crate) fn compute_leaf_single_id(slot: u8) -> HashOut<GFp> {
    PoseidonHash::hash_no_pad(&[GFp::from_canonical_u8(slot)])
}

/// Calculate `values_digest = D(id || value)` for single variable leaf.
pub(crate) fn compute_leaf_single_values_digest(id: &HashOut<GFp>, value: &[u8]) -> Point {
    assert!(value.len() <= MAPPING_LEAF_VALUE_LEN);

    let value = left_pad32(&value);
    let packed_value: Vec<_> = convert_u8_to_u32_slice(&value)
        .into_iter()
        .map(GFp::from_canonical_u32)
        .collect();

    let inputs: Vec<_> = id.elements.into_iter().chain(packed_value).collect();
    map_to_curve_point(&inputs)
}

/// Calculate `metadata_digest = D(id || slot)` for single variable leaf.
pub(crate) fn compute_leaf_single_metadata_digest(id: &HashOut<GFp>, slot: u8) -> Point {
    let inputs: Vec<_> = id
        .elements
        .into_iter()
        .chain(iter::once(GFp::from_canonical_u8(slot)))
        .collect();
    map_to_curve_point(&inputs)
}

/// Calculate `key_id = Poseidon(KEY || slot)` for mapping variable leaf.
pub(crate) fn compute_leaf_mapping_key_id(slot: u8) -> HashOut<GFp> {
    compute_id_with_prefix(KEY_ID_PREFIX, slot)
}

/// Calculate `value_id = Poseidon(VAL || slot)` for mapping variable leaf.
pub(crate) fn compute_leaf_mapping_value_id(slot: u8) -> HashOut<GFp> {
    compute_id_with_prefix(VALUE_ID_PREFIX, slot)
}

/// Calculate `values_digest = D(D(key_id || key) + D(value_id || value))` for mapping variable leaf.
pub(crate) fn compute_leaf_mapping_values_digest(
    key_id: &HashOut<GFp>,
    value_id: &HashOut<GFp>,
    mapping_key: &[u8],
    value: &[u8],
) -> Point {
    assert!(mapping_key.len() <= MAPPING_KEY_LEN);
    assert!(value.len() <= MAPPING_LEAF_VALUE_LEN);

    let [packed_key, packed_value] = [mapping_key, value].map(|arr| {
        let arr = left_pad32(&arr);

        convert_u8_to_u32_slice(&arr)
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect::<Vec<_>>()
    });

    let inputs: Vec<_> = key_id.elements.into_iter().chain(packed_key).collect();
    let k_digest = map_to_curve_point(&inputs);
    let inputs: Vec<_> = value_id.elements.into_iter().chain(packed_value).collect();
    let v_digest = map_to_curve_point(&inputs);

    k_digest + v_digest
}

/// Calculate `metadata_digest = D(key_id || value_id || slot)` for mapping variable leaf.
pub(crate) fn compute_leaf_mapping_metadata_digest(
    key_id: &HashOut<GFp>,
    value_id: &HashOut<GFp>,
    slot: u8,
) -> Point {
    let inputs: Vec<_> = key_id
        .elements
        .into_iter()
        .chain(value_id.elements)
        .chain(iter::once(GFp::from_canonical_u8(slot)))
        .collect();
    map_to_curve_point(&inputs)
}

/// Calculate ID with prefix.
fn compute_id_with_prefix(prefix: &[u8], slot: u8) -> HashOut<GFp> {
    let inputs: Vec<_> = prefix.iter().cloned().chain(iter::once(slot)).collect();
    pack_and_compute_poseidon_value(&inputs)
}
