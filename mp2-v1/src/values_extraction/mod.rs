use ethers::types::Address;
use mp2_common::{
    types::GFp,
    utils::{pack_and_compute_poseidon_value, Packer},
};
use plonky2::{
    field::types::{Field, PrimeField64},
    hash::poseidon::PoseidonHash,
    plonk::config::Hasher,
};
use std::iter;

pub mod api;
mod branch;
mod extension;
mod leaf_mapping;
mod leaf_single;
pub mod public_inputs;

pub use api::{build_circuits_params, generate_proof, CircuitInput, PublicParameters};

/// Constant prefixes for key and value IDs. Restrict both prefixes to 3-bytes,
/// so `prefix + slot (u8)` could be converted to an U32.
pub(crate) const KEY_ID_PREFIX: &[u8] = b"KEY";
pub(crate) const VALUE_ID_PREFIX: &[u8] = b"VAL";

/// Calculate `id = Poseidon(slot || contract_address)[0]` for single variable leaf.
pub fn compute_leaf_single_id(slot: u8, contract_address: &Address) -> u64 {
    let packed_contract_address: Vec<_> = contract_address
        .0
        .pack()
        .into_iter()
        .map(GFp::from_canonical_u32)
        .collect();

    let inputs: Vec<_> = iter::once(GFp::from_canonical_u8(slot))
        .chain(packed_contract_address)
        .collect();

    PoseidonHash::hash_no_pad(&inputs).elements[0].to_canonical_u64()
}

/// Calculate `key_id = Poseidon(KEY || slot || contract_address)[0]` for mapping variable leaf.
pub fn compute_leaf_mapping_key_id(slot: u8, contract_address: &Address) -> u64 {
    compute_id_with_prefix(KEY_ID_PREFIX, slot, contract_address)
}

/// Calculate `value_id = Poseidon(VAL || slot || contract_address)[0]` for mapping variable leaf.
pub fn compute_leaf_mapping_value_id(slot: u8, contract_address: &Address) -> u64 {
    compute_id_with_prefix(VALUE_ID_PREFIX, slot, contract_address)
}

/// Calculate ID with prefix.
fn compute_id_with_prefix(prefix: &[u8], slot: u8, contract_address: &Address) -> u64 {
    let inputs: Vec<_> = prefix
        .iter()
        .cloned()
        .chain(iter::once(slot))
        .chain(contract_address.0)
        .collect();

    pack_and_compute_poseidon_value::<GFp>(&inputs).elements[0].to_canonical_u64()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use mp2_common::{
        eth::left_pad32,
        group_hashing::map_to_curve_point,
        types::{MAPPING_KEY_LEN, MAPPING_LEAF_VALUE_LEN},
        utils::convert_u8_to_u32_slice,
    };
    use plonky2_ecgfp5::curve::curve::Point;

    /// Calculate `values_digest = D(id || value)` for single variable leaf.
    pub(crate) fn compute_leaf_single_values_digest(id: u64, value: &[u8]) -> Point {
        assert!(value.len() <= MAPPING_LEAF_VALUE_LEN);

        let value = left_pad32(&value);
        let packed_value: Vec<_> = convert_u8_to_u32_slice(&value)
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        let inputs: Vec<_> = iter::once(GFp::from_canonical_u64(id))
            .chain(packed_value)
            .collect();
        map_to_curve_point(&inputs)
    }

    /// Calculate `metadata_digest = D(id || slot)` for single variable leaf.
    pub(crate) fn compute_leaf_single_metadata_digest(id: u64, slot: u8) -> Point {
        map_to_curve_point(&[GFp::from_canonical_u64(id), GFp::from_canonical_u8(slot)])
    }

    /// Calculate `values_digest = D(D(key_id || key) + D(value_id || value))` for mapping variable leaf.
    pub(crate) fn compute_leaf_mapping_values_digest(
        key_id: u64,
        value_id: u64,
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

    /// Calculate `metadata_digest = D(key_id || value_id || slot)` for mapping variable leaf.
    pub(crate) fn compute_leaf_mapping_metadata_digest(
        key_id: u64,
        value_id: u64,
        slot: u8,
    ) -> Point {
        map_to_curve_point(&[
            GFp::from_canonical_u64(key_id),
            GFp::from_canonical_u64(value_id),
            GFp::from_canonical_u8(slot),
        ])
    }
}
