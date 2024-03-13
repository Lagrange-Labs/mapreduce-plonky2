mod digest_equal;
mod inclusion;
mod key;
pub mod length_extract;
mod length_match;
pub mod mapping;
mod merkle;

pub use digest_equal::PublicInputs;

pub(crate) const MAX_BRANCH_NODE_LEN: usize = 532;
pub(super) const MAX_LEAF_NODE_LEN: usize = MAX_EXTENSION_NODE_LEN;
/// rlp( rlp(max key 32b) + rlp(max value 32b) ) + 1 for compact encoding
/// see test_len()
pub(crate) const MAX_EXTENSION_NODE_LEN: usize = 69;
