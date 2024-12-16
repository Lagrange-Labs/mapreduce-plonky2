// Add this to allow generic const expressions, e.g. `PAD_LEN(NODE_LEN)`.
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
// Add this to allow generic const items, e.g. `const IO_LEN<const MAX_NUM: usize>`
#![feature(generic_const_items)]
#![feature(variant_count)]
#![feature(async_closure)]
pub mod api;
pub mod block_tree;
pub mod cells_tree;
pub mod extraction;
pub mod ivc;
/// Module for circuits for simple queries
pub mod query;
#[cfg(feature = "results_tree")]
pub mod results_tree;
/// Module for the query revelation circuits
pub mod revelation;
pub mod row_tree;
pub mod test_utils;
