//! Common structs and functions used for integration tests

use verifiable_db::test_utils::MAX_NUM_ITEMS_PER_OUTPUT;

mod context;
mod io;
mod query;
pub mod utils;

pub(crate) use context::TestContext;
pub(crate) use io::{TestQueryInput, TestQueryOutput};

pub(crate) const NUM_PREPROCESSING_IO: usize = verifiable_db::ivc::NUM_IO;
pub(crate) const NUM_QUERY_IO: usize = verifiable_db::query::pi_len::<MAX_NUM_ITEMS_PER_OUTPUT>();
