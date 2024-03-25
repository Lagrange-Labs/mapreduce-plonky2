pub mod api;
mod inner_node;
pub(crate) mod leaf;
mod public_inputs;

pub use api::{Input, NodeInputs, PublicParameters};
pub use leaf::LeafCircuit;

use plonky2_ecgfp5::curve::curve::Point as Digest;
pub use public_inputs::PublicInputs;
#[cfg(test)]
mod tests;

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    plonk::config::{GenericHashOut, Hasher},
};

use crate::{
    eth::left_pad32, group_hashing::map_to_curve_point, types::HashOutput,
    utils::convert_u8_to_u32_slice,
};

/// Size of the input value we insert in a leaf node. Note the value is compacted in a u32 slice before hashing.
const LEAF_SIZE: usize = 32;
/// Size of the input value we insert in a leaf node. Note the key is compacted in u32 slice before hashing.
const KEY_SIZE: usize = 32;
/// Size of the leaf in bytes when compacted in a u32 slice
const PACKED_LEAF_SIZE: usize = 8;
/// Size of the key in bytes when compacted in a u32 slice
const PACKED_KEY_SIZE: usize = 8;

/// Returns the hash of the leaf node in the storage database for a mapping variable
/// given a mapping key and its associated value. The key and value must be both
/// less or equal than 32 bytes.
pub fn leaf_hash_for_mapping(key: &[u8], value: &[u8]) -> HashOutput {
    assert!(key.len() <= KEY_SIZE);
    assert!(value.len() <= LEAF_SIZE);
    let key = left_pad32(key);
    let value = left_pad32(value);
    let mut slice = [0u8; 64];
    slice[0..32].copy_from_slice(&key);
    slice[32..64].copy_from_slice(&value);
    leaf_hash(&slice)
}

/// Computes the hash of a leaf node of the lpn storage database
pub fn leaf_hash(value: &[u8]) -> HashOutput {
    assert!(value.len() % 4 == 0, "value must be a multiple of 4 bytes");
    let u32_slice = convert_u8_to_u32_slice(value);
    let f_slice = u32_slice
        .into_iter()
        .map(GoldilocksField::from_canonical_u32)
        .collect::<Vec<_>>();
    assert!(f_slice.len() != 8, "leaf hash input must NOT be of size 8");
    let hash_f = PoseidonHash::hash_no_pad(&f_slice);
    hash_f.to_bytes().try_into().unwrap()
}

/// Computes the intermediate node hash from two hash output from other intermediate
/// nodes or leaf nodes.
pub fn intermediate_node_hash(left: &HashOutput, right: &HashOutput) -> HashOutput {
    let f_slice = HashOut::<GoldilocksField>::from_bytes(left)
        .elements
        .into_iter()
        .chain(HashOut::from_bytes(right).elements)
        .collect::<Vec<_>>();
    let hash_f = PoseidonHash::hash_no_pad(&f_slice);
    hash_f.to_bytes().try_into().unwrap()
}

/// Computes the digest for a mapping entry with the mapping key and its associated value
pub fn leaf_digest_for_mapping(key: &[u8], value: &[u8]) -> Digest {
    assert!(key.len() <= KEY_SIZE);
    assert!(value.len() <= LEAF_SIZE);
    let key = left_pad32(key);
    let value = left_pad32(value);
    leaf_digest(&key.into_iter().chain(value).collect::<Vec<_>>())
}

/// Computes the digest for a leaf node in the storage database
pub fn leaf_digest(value: &[u8]) -> Digest {
    assert!(value.len() % 4 == 0, "value must be a multiple of 4 bytes");
    let u32_slice = convert_u8_to_u32_slice(value);
    map_to_curve_point(
        &u32_slice
            .into_iter()
            .map(GoldilocksField::from_canonical_u32)
            .collect::<Vec<_>>(),
    )
}
