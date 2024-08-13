//! Common structs and functions used for integration tests

mod context;
mod io;
mod query;
pub mod utils;

pub(crate) use context::TestContext;
pub(crate) use io::{TestQueryInput, TestQueryOutput};

pub(crate) const MAX_NUM_COLUMNS: usize = 20;
pub(crate) const VALID_NUM_COLUMNS: usize = 4;

// NOTE: These constants are associated with the length of the final revelation
// public inputs. It may cause infinite loop when building parameters if we
// increase the values (as +1 for MAX_NUM_PLACEHOLDERS).
pub(crate) const MAX_NUM_OUTPUTS: usize = 3;
pub(crate) const MAX_NUM_ITEMS_PER_OUTPUT: usize = 5;
pub(crate) const MAX_NUM_PLACEHOLDERS: usize = 14;

pub(crate) const MAX_NUM_PREDICATE_OPS: usize = 20;
pub(crate) const MAX_NUM_RESULT_OPS: usize = 20;

pub(crate) const NUM_PREPROCESSING_IO: usize = verifiable_db::ivc::NUM_IO;
pub(crate) const NUM_QUERY_IO: usize = verifiable_db::query::PI_LEN::<MAX_NUM_ITEMS_PER_OUTPUT>;
