use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::config::{GenericConfig, GenericHashOut, Hasher, PoseidonGoldilocksConfig};

use crate::utils::convert_u8_to_u32_slice;
use plonky2::field::types::Field;
use plonky2::hash::poseidon::PoseidonHash;

pub type HashOutput = [u8; 32];

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

pub const DST_LEAF: u16 = 0x1234;
pub const DST_INTERMEDIATE: u16 = 0x5678;

/// Computes the hash of a leaf node from the value we want to insert as a leaf.
pub fn leaf_hash(value: &[u8]) -> HashOutput {
    let u32_slice = convert_u8_to_u32_slice(value);
    let f_slice = std::iter::once(F::from_canonical_u16(DST_LEAF))
        .chain(u32_slice.iter().map(|x| F::from_canonical_u32(*x)))
        .collect::<Vec<_>>();
    let hash_f = PoseidonHash::hash_no_pad(&f_slice);
    hash_f.to_bytes().try_into().unwrap()
}

/// Computes the intermediate node hash from two hash output from other intermediate
/// nodes or leaf nodes.
pub fn intermediate_node_hash(left: &HashOutput, right: &HashOutput) -> HashOutput {
    let f_slice = std::iter::once(F::from_canonical_u16(DST_INTERMEDIATE))
        .chain(HashOut::<GoldilocksField>::from_bytes(left).elements)
        .chain(HashOut::<GoldilocksField>::from_bytes(right).elements)
        .collect::<Vec<_>>();
    let hash_f = PoseidonHash::hash_no_pad(&f_slice);
    hash_f.to_bytes().try_into().unwrap()
}
