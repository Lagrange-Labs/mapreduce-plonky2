//! Circuits for v1 of Lagrange Proof Network (LPN)

// Add this to allow generic const expressions, e.g. `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]
// Add this so we don't need to always specify const generic in generic
// parameters (i.e. use "_")
#![feature(generic_arg_infer)]
use mp2_common::mpt_sequential::PAD_LEN;

pub const MAX_BRANCH_NODE_LEN: usize = 532;
pub const MAX_BRANCH_NODE_LEN_PADDED: usize = PAD_LEN(532);
/// rlp( rlp(max key 32b) + rlp(max value 32b) ) + 1 for compact encoding
/// see test_len()
pub const MAX_EXTENSION_NODE_LEN: usize = 69;
pub const MAX_EXTENSION_NODE_LEN_PADDED: usize = PAD_LEN(69);
pub const MAX_LEAF_NODE_LEN: usize = MAX_EXTENSION_NODE_LEN;

pub mod api;
pub mod block_extraction;
pub mod cells_tree;
pub mod contract_extraction;
pub mod final_extraction;
pub mod length_extraction;
pub mod values_extraction;
