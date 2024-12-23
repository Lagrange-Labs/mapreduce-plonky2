//! Circuits for v1 of Lagrange Proof Network (LPN)
#![allow(incomplete_features)]
#![allow(clippy::large_enum_variant)]
// Add this to allow generic const expressions, e.g. `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]
// Add this so we don't need to always specify const generic in generic
// parameters (i.e. use "_")
#![feature(generic_arg_infer)]
// stylistic feature
#![feature(async_closure)]
use mp2_common::{array::L32, mpt_sequential::PAD_LEN};

pub const MAX_BRANCH_NODE_LEN: usize = 532;
pub const MAX_BRANCH_NODE_LEN_PADDED: usize = PAD_LEN(532);
/// rlp( rlp(max key 32b) + rlp(max value 32b) ) + 1 for compact encoding
/// see test_len()
pub const MAX_EXTENSION_NODE_LEN: usize = 69;
pub const MAX_EXTENSION_NODE_LEN_PADDED: usize = PAD_LEN(69);
pub const MAX_LEAF_NODE_LEN: usize = MAX_EXTENSION_NODE_LEN;
pub const MAX_LEAF_NODE_LEN_PADDED: usize = PAD_LEN(MAX_LEAF_NODE_LEN);
pub const MAX_LEAF_VALUE_LEN: usize = 32;
pub const L32_LEAF_VALUE_LEN: usize = L32(MAX_LEAF_VALUE_LEN);
pub const MAX_RECEIPT_LEAF_NODE_LEN: usize = 512;

pub mod api;
pub mod block_extraction;
pub mod contract_extraction;
pub mod final_extraction;
pub mod indexing;
pub mod length_extraction;
pub mod query;
pub mod values_extraction;

#[cfg(test)]
pub(crate) mod tests {
    /// Testing maximum columns
    pub(crate) const TEST_MAX_COLUMNS: usize = 32;
}
