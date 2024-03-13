mod digest_equal;
mod key;
pub mod length_extract;
mod length_match;
mod lpn;
pub mod mapping;
mod merkle;
mod query2;

pub use digest_equal::PublicInputs;

pub(crate) const MAX_BRANCH_NODE_LEN: usize = 532;
pub(super) const MAX_LEAF_NODE_LEN: usize = MAX_EXTENSION_NODE_LEN;
/// rlp( rlp(max key 32b) + rlp(max value 32b) ) + 1 for compact encoding
/// see test_len()
pub(crate) const MAX_EXTENSION_NODE_LEN: usize = 69;
use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};

// Number of Goldilocks elements in CurveTarget
const CURVE_TARGET_GL_SIZE: usize = 11;

// A key is 32B-long
const KEY_GL_SIZE: usize = 32;
// A value in a leaf node is 32B wide
const LEAF_GL_SIZE: usize = 32;
// ['L', 'E', 'A', 'F'] -> 4B -> 1GL
const LEAF_MARKER_GL_SIZE: usize = 1;

#[allow(non_snake_case)]
fn LEAF_MARKER() -> GoldilocksField {
    GoldilocksField::from_canonical_u32(u32::from_be_bytes(*b"LEAF"))
}

#[allow(non_snake_case)]
fn NODE_MARKER() -> GoldilocksField {
    GoldilocksField::from_canonical_u32(u32::from_be_bytes(*b"NODE"))
}
