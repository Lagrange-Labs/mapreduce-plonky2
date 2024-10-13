use alloy::primitives::Address;
use gadgets::metadata_gadget::MetadataGadget;
use itertools::Itertools;
use mp2_common::{
    eth::{left_pad32, StorageSlot},
    group_hashing::map_to_curve_point,
    poseidon::H,
    types::{MAPPING_KEY_LEN, MAPPING_LEAF_VALUE_LEN},
    utils::{Endianness, Packer, ToFields},
    F,
};
use plonky2::{
    field::types::{Field, PrimeField64},
    plonk::config::Hasher,
};
use plonky2_ecgfp5::curve::curve::Point as Digest;
use serde::{Deserialize, Serialize};
use std::iter::once;

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

/// Constant prefixes for key and value IDs. Restrict both prefixes to 3-bytes,
/// so `prefix + slot (u8)` could be converted to an U32.
pub(crate) const KEY_ID_PREFIX: &[u8] = b"KEY";
pub(crate) const VALUE_ID_PREFIX: &[u8] = b"VAL";

/// Constant prefixes for the inner and outer key IDs of mapping slot.
/// Restrict to one field.
pub(crate) const INNER_KEY_ID_PREFIX: &[u8] = b"IN_KEY";
pub(crate) const OUTER_KEY_ID_PREFIX: &[u8] = b"OUT_KEY";

pub(crate) const BLOCK_ID_DST: &[u8] = b"BLOCK_NUMBER";

/// Storage slot information for generating the proof
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct StorageSlotInfo<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize> {
    slot: StorageSlot,
    metadata: MetadataGadget<MAX_COLUMNS, MAX_FIELD_PER_EVM>,
    outer_key_id: F,
    inner_key_id: F,
}

impl<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>
    StorageSlotInfo<MAX_COLUMNS, MAX_FIELD_PER_EVM>
{
    pub fn new(
        slot: StorageSlot,
        metadata: MetadataGadget<MAX_COLUMNS, MAX_FIELD_PER_EVM>,
        outer_key_id: F,
        inner_key_id: F,
    ) -> Self {
        Self {
            slot,
            metadata,
            outer_key_id,
            inner_key_id,
        }
    }

    pub fn slot(&self) -> &StorageSlot {
        &self.slot
    }

    pub fn metadata(&self) -> &MetadataGadget<MAX_COLUMNS, MAX_FIELD_PER_EVM> {
        &self.metadata
    }

    pub fn outer_key_id(&self) -> F {
        self.outer_key_id
    }

    pub fn inner_key_id(&self) -> F {
        self.inner_key_id
    }
}

pub fn identifier_block_column() -> u64 {
    let inputs: Vec<F> = BLOCK_ID_DST.to_fields();
    H::hash_no_pad(&inputs).elements[0].to_canonical_u64()
}

/// Compute identifier for single value or Struct.
/// `id = H(slot || evm_word || contract_address || chain_id)[0]`
pub fn identifier_single_var_column(
    slot: u8,
    evm_word: u32,
    contract_address: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> u64 {
    let inputs = once(slot)
        .chain(evm_word.to_be_bytes())
        .chain(contract_address.0.to_vec())
        .chain(chain_id.to_be_bytes())
        .chain(extra)
        .map(F::from_canonical_u8)
        .collect_vec();

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
        .chain(once(slot))
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

    let inputs: Vec<_> = once(F::from_canonical_u64(key_id))
        .chain(packed_key)
        .collect();
    let k_digest = map_to_curve_point(&inputs);
    let inputs: Vec<_> = once(F::from_canonical_u64(value_id))
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
        .chain(once(F::from_bool(add_digest.is_inf)))
        .collect();
    map_to_curve_point(&inputs)
}

/// Calculate `values_digest = D(id || value)` for single variable leaf.
pub fn compute_leaf_single_values_digest(id: u64, value: &[u8]) -> Digest {
    assert!(value.len() <= MAPPING_LEAF_VALUE_LEN);

    let packed_value = left_pad32(value).pack(Endianness::Big).to_fields();

    let inputs: Vec<_> = once(F::from_canonical_u64(id))
        .chain(packed_value)
        .collect();
    map_to_curve_point(&inputs)
}

/// Calculate `metadata_digest = D(id || slot)` for single variable leaf.
pub fn compute_leaf_single_metadata_digest(id: u64, slot: u8) -> Digest {
    map_to_curve_point(&[F::from_canonical_u64(id), F::from_canonical_u8(slot)])
}

/// Calculate `metadata_digest = D(key_id || value_id || slot)` for mapping variable leaf.
pub fn compute_leaf_mapping_metadata_digest(key_id: u64, value_id: u64, slot: u8) -> Digest {
    map_to_curve_point(&[
        F::from_canonical_u64(key_id),
        F::from_canonical_u64(value_id),
        F::from_canonical_u8(slot),
    ])
}
