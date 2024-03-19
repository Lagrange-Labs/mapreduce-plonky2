//! Lagrange Proving Network circuits

pub mod api;
pub(crate) mod leaf;
mod node;
mod public_inputs;

use ethers::types::Address;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    plonk::config::{GenericHashOut, Hasher},
};
pub use public_inputs::StateInputs;

use crate::{types::HashOutput, utils::convert_u8_to_u32_slice};

// TODO: remove public after moving the public inputs outside of leaf.

/// Returns the hash in bytes of the leaf of the state database. It takes as parameters
/// * the address of the contract,
/// * the mapping slot for which we're building the database over (v0 only functionality)
///     and the length slot corresponding to the variable holding the length of the mapping.
/// * the storage root of the lpn database corresponding to this contract
pub fn state_leaf_hash(
    add: Address,
    mapping_slot: u8,
    length_slot: u8,
    storage_root: HashOutput,
) -> HashOutput {
    let packed = convert_u8_to_u32_slice(add.as_bytes());
    let f_slice = packed
        .into_iter()
        .chain(std::iter::once(mapping_slot as u32))
        .chain(std::iter::once(length_slot as u32))
        .map(GoldilocksField::from_canonical_u32)
        .chain(HashOut::from_bytes(&storage_root).elements)
        .collect::<Vec<_>>();
    assert!(
        f_slice.len() != 8,
        "state leaf hash input must NOT be of size 8"
    );
    let hash_f = PoseidonHash::hash_no_pad(&f_slice);
    hash_f.to_bytes().try_into().unwrap()
}

/// Returns the hash in bytes of the node of the state database.
/// TODO: test when the circuit is ready
pub fn state_node_hash(left: HashOutput, right: HashOutput) -> HashOutput {
    let f_slice = HashOut::<GoldilocksField>::from_bytes(&left)
        .elements
        .into_iter()
        .chain(HashOut::from_bytes(&right).elements)
        .collect::<Vec<_>>();
    let hash_f = PoseidonHash::hash_no_pad(&f_slice);
    hash_f.to_bytes().try_into().unwrap()
}
