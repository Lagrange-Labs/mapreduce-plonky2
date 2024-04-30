mod branch;
mod extension;
mod key;
mod leaf_mapping;
mod leaf_single;
mod public_inputs;

pub use public_inputs::PublicInputs;

pub(crate) const MAX_BRANCH_NODE_LEN: usize = 532;
/// rlp( rlp(max key 32b) + rlp(max value 32b) ) + 1 for compact encoding
/// see test_len()
pub(crate) const MAX_EXTENSION_NODE_LEN: usize = 69;
pub(crate) const MAX_LEAF_NODE_LEN: usize = MAX_EXTENSION_NODE_LEN;
