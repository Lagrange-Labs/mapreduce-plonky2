// Add this to allow generic const expressions, e.g. `PAD_LEN(NODE_LEN)`.

#![feature(generic_const_exprs)]
// Add this to allow generic const items, e.g. `const IO_LEN<const MAX_NUM: usize>`
#![feature(generic_const_items)]
#![feature(variant_count)]
// /// Module for circuits for simple queries
// pub mod query;
//
pub mod api;
pub mod block_tree;
pub mod cells_tree;
pub mod extraction;
pub mod ivc;
pub mod row_tree;
