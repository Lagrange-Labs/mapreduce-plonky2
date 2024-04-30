//! Plonky2 documentation

#![feature(generic_const_exprs)]
#![feature(generic_arg_infer)]
#![feature(const_for)]
#![feature(generic_const_items)]

#[cfg(test)]
use common::benches;
use common::{array, circuit, group_hashing, keccak, merkle_tree, mpt_sequential, poseidon, rlp};
pub use common::{eth, types, utils};

pub mod api;
pub mod block;
pub mod query2;
pub mod state;
pub mod storage;
