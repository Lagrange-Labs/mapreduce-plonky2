//! Testing query input and output structs

use super::MAX_NUM_ITEMS_PER_OUTPUT;
use alloy::primitives::{B256, U256};
use serde::{Deserialize, Serialize};

/// Testing query input used to check with the public inputs in Solidity function
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct TestQueryInput {
    // Query limit parameter
    pub(crate) query_limit: u32,
    // Query offset parameter
    pub(crate) query_offset: u32,
    // Minimum block number
    pub(crate) min_block_number: u32,
    // Maximum block number
    pub(crate) max_block_number: u32,
    // Block hash
    pub(crate) block_hash: B256,
    // Computational hash
    pub(crate) computational_hash: B256,
    // User placeholder values
    pub(crate) user_placeholders: Vec<U256>,
}

/// Testing query output returned from the Solidity function
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct TestQueryOutput {
    pub(crate) total_matched_rows: u32,
    pub(crate) rows: Vec<[U256; MAX_NUM_ITEMS_PER_OUTPUT]>,
    pub(crate) error: u32,
}
