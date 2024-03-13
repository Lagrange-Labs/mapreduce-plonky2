//! Lagrange Proving Network circuits

use ethers::types::Address;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    plonk::config::{GenericHashOut, Hasher},
};

use crate::{types::HashOutput, utils::convert_u8_to_u32_slice};

// TODO: remove public after moving the public inputs outside of leaf.
pub(crate) mod leaf;

/// Domain separation tag for the leaf value hashing scheme for the state database
const STATE_LEAF_DST: u8 = 0x22;
/// Domain separation tag for the node value hashing scheme for the state database
const STATE_NODE_DST: u8 = 0x23;
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
    let f_slice = std::iter::once(STATE_LEAF_DST as u32)
        .chain(packed)
        .chain(std::iter::once(mapping_slot as u32))
        .chain(std::iter::once(length_slot as u32))
        .map(GoldilocksField::from_canonical_u32)
        .chain(HashOut::from_bytes(&storage_root).elements)
        .collect::<Vec<_>>();
    let hash_f = PoseidonHash::hash_no_pad(&f_slice);
    hash_f.to_bytes().try_into().unwrap()
}

/// Returns the hash in bytes of the node of the state database.
/// TODO: test when the circuit is ready
pub fn state_node_hash(left: HashOutput, right: HashOutput) -> HashOutput {
    let f_slice = std::iter::once(GoldilocksField::from_canonical_u8(STATE_NODE_DST))
        .chain(HashOut::from_bytes(&left).elements)
        .chain(HashOut::from_bytes(&right).elements)
        .collect::<Vec<_>>();
    let hash_f = PoseidonHash::hash_no_pad(&f_slice);
    hash_f.to_bytes().try_into().unwrap()
}
