use alloy::primitives::Address;
use gadgets::{
    column_gadget::ColumnGadgetData, column_info::ColumnInfo, metadata_gadget::MetadataGadget,
};
use itertools::Itertools;
use mp2_common::{
    eth::{left_pad32, StorageSlot},
    group_hashing::map_to_curve_point,
    poseidon::{empty_poseidon_hash, hash_to_int_value, H},
    types::MAPPING_LEAF_VALUE_LEN,
    utils::{Endianness, Packer, ToFields},
    F,
};
use plonky2::{
    field::types::{Field, PrimeField64},
    plonk::config::Hasher,
};
use plonky2_ecgfp5::curve::{curve::Point as Digest, scalar_field::Scalar};
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

/// Constant prefixes for the key and value IDs. Restrict to 4-bytes (Uint32).
pub(crate) const KEY_ID_PREFIX: &[u8] = b"\0KEY";
pub(crate) const VALUE_ID_PREFIX: &[u8] = b"\0VAL";

/// Constant prefixes for the inner and outer key IDs of mapping slot.
/// Restrict to 8-bytes (Uint64).
pub(crate) const INNER_KEY_ID_PREFIX: &[u8] = b"\0\0IN_KEY";
pub(crate) const OUTER_KEY_ID_PREFIX: &[u8] = b"\0OUT_KEY";

pub(crate) const BLOCK_ID_DST: &[u8] = b"BLOCK_NUMBER";

/// Storage slot information for generating the proof
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct StorageSlotInfo<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize> {
    slot: StorageSlot,
    metadata: MetadataGadget<MAX_COLUMNS, MAX_FIELD_PER_EVM>,
    outer_key_id: u64,
    inner_key_id: u64,
}

impl<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>
    StorageSlotInfo<MAX_COLUMNS, MAX_FIELD_PER_EVM>
{
    pub fn new(
        slot: StorageSlot,
        metadata: MetadataGadget<MAX_COLUMNS, MAX_FIELD_PER_EVM>,
        outer_key_id: Option<u64>,
        inner_key_id: Option<u64>,
    ) -> Self {
        let [outer_key_id, inner_key_id] =
            [outer_key_id, inner_key_id].map(|key_id| key_id.unwrap_or_default());
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

    pub fn outer_key_id(&self) -> u64 {
        self.outer_key_id
    }

    pub fn inner_key_id(&self) -> u64 {
        self.inner_key_id
    }
}

pub fn identifier_block_column() -> u64 {
    let inputs: Vec<F> = BLOCK_ID_DST.to_fields();
    H::hash_no_pad(&inputs).elements[0].to_canonical_u64()
}

/// Compute identifier for single variable (value of Struct).
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

/// Compute inner key indetifier for mapping of mappings variable.
/// `inner_key_id = H(OUT_KEY || slot || contract_address || chain_id)[0]`
pub fn identifier_for_inner_mapping_key_column(
    slot: u8,
    contract_address: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> u64 {
    compute_id_with_prefix(INNER_KEY_ID_PREFIX, slot, contract_address, chain_id, extra)
}

/// Compute value indetifier for mapping variable.
/// `value_id = H(VAL || slot || contract_address || chain_id)[0]`
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

/// Compute the metadata digest for single variable leaf.
pub fn compute_leaf_single_metadata_digest<
    const MAX_COLUMNS: usize,
    const MAX_FIELD_PER_EVM: usize,
>(
    table_info: Vec<ColumnInfo>,
) -> Digest {
    // We don't need `extracted_column_identifiers` and `evm_word` to compute the metadata digest.
    MetadataGadget::<MAX_COLUMNS, MAX_FIELD_PER_EVM>::new(table_info, &[], 0).digest()
}

/// Compute the values digest for single variable leaf.
pub fn compute_leaf_single_values_digest<const MAX_FIELD_PER_EVM: usize>(
    metadata_digest: &Digest,
    table_info: Vec<ColumnInfo>,
    extracted_column_identifiers: &[u64],
    value: [u8; MAPPING_LEAF_VALUE_LEN],
) -> Digest {
    let values_digest =
        ColumnGadgetData::<MAX_FIELD_PER_EVM>::new(table_info, extracted_column_identifiers, value)
            .digest();

    // row_id = H2int(H("") || metadata_digest)
    let inputs = empty_poseidon_hash()
        .to_fields()
        .into_iter()
        .chain(metadata_digest.to_fields())
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
        MetadataGadget::<MAX_COLUMNS, MAX_FIELD_PER_EVM>::new(table_info, &[], 0).digest();

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
    metadata_digest: &Digest,
    table_info: Vec<ColumnInfo>,
    extracted_column_identifiers: &[u64],
    value: [u8; MAPPING_LEAF_VALUE_LEN],
    mapping_key: Vec<u8>,
    evm_word: u32,
    key_id: u64,
) -> Digest {
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
    // row_unique_data = H(pack(left_pad32(key))
    let row_unique_data = H::hash_no_pad(&packed_mapping_key.collect_vec());
    // row_id = H2int(row_unique_data || metadata_digest)
    let inputs = row_unique_data
        .to_fields()
        .into_iter()
        .chain(metadata_digest.to_fields())
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
        MetadataGadget::<MAX_COLUMNS, MAX_FIELD_PER_EVM>::new(table_info, &[], 0).digest();

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
pub fn compute_leaf_mapping_of_mappings_values_digest<const MAX_FIELD_PER_EVM: usize>(
    metadata_digest: &Digest,
    table_info: Vec<ColumnInfo>,
    extracted_column_identifiers: &[u64],
    value: [u8; MAPPING_LEAF_VALUE_LEN],
    evm_word: u32,
    outer_mapping_key: Vec<u8>,
    inner_mapping_key: Vec<u8>,
    outer_key_id: u64,
    inner_key_id: u64,
) -> Digest {
    let mut values_digest =
        ColumnGadgetData::<MAX_FIELD_PER_EVM>::new(table_info, extracted_column_identifiers, value)
            .digest();

    // Compute the outer and inner key values digests.
    let [packed_outer_key, packed_inner_key] = [outer_mapping_key, inner_mapping_key].map(|key| {
        left_pad32(&key)
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

    // Compute the unique data to identify a row is the mapping key:
    // row_unique_data = H(outer_key || inner_key)
    let inputs = packed_outer_key.chain(packed_inner_key).collect_vec();
    let row_unique_data = H::hash_no_pad(&inputs);
    // row_id = H2int(row_unique_data || metadata_digest)
    let inputs = row_unique_data
        .to_fields()
        .into_iter()
        .chain(metadata_digest.to_fields())
        .collect_vec();
    let hash = H::hash_no_pad(&inputs);
    let row_id = hash_to_int_value(hash);

    // values_digest = values_digest * row_id
    let row_id = Scalar::from_noncanonical_biguint(row_id);
    values_digest * row_id
}
