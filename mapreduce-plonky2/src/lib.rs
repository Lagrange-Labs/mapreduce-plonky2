//! Plonky2 documentation

// TODO: should update and enable it.
// #![warn(missing_docs)]
#![feature(generic_const_exprs)]
#![feature(generic_arg_infer)]
#![feature(const_for)]
#![feature(generic_const_items)]

// NOTE: it's convenient to only avoid changing dependencies in each source file for v0.
use mp2_common::{array, group_hashing, keccak, merkle_tree, mpt_sequential, poseidon, rlp};
pub use mp2_common::{eth, types, utils};

pub mod api;
pub mod block;
pub mod query2;
pub mod state;
pub mod storage;
