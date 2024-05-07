//! Utility structs and functions used for integration tests

// Used to fix the error: failed to evaluate generic const expression `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]

pub mod utils;
pub mod values_extraction;
