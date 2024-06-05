//! Test context used in the test cases

use super::utils::load_or_generate_public_params;
use ethers::prelude::{EIP1186ProofResponse, Http, Provider};
use log::warn;
use mp2_common::eth::ProofQuery;
use mp2_v1::api::PublicParameters;

/// Cached filename of the public parameters
const PUBLIC_PARAMS_FILE: &str = "mp2.params";

/// Retry number for the RPC request
const RETRY_NUM: usize = 3;

/// Test context
pub struct TestContext {
    params: PublicParameters,
    rpc: Provider<Http>,
}

impl TestContext {
    /// Create the test context.
    pub fn new(rpc_url: &str) -> Self {
        let params = load_or_generate_public_params(PUBLIC_PARAMS_FILE).unwrap();
        let rpc = Provider::<Http>::try_from(rpc_url).unwrap();

        Self { params, rpc }
    }

    /// Get the public parameters.
    pub fn params(&self) -> &PublicParameters {
        &self.params
    }

    /// Query the MPT proof.
    pub async fn query_mpt_proof(&self, query: &ProofQuery) -> EIP1186ProofResponse {
        // Query the MPT proof with retries.
        for i in 0..RETRY_NUM {
            if let Ok(response) = query.query_mpt_proof(&self.rpc, None).await {
                return response;
            } else {
                warn!("Failed to query the MPT proof at {i} time")
            }
        }

        panic!("Failed to query the MPT proof");
    }

    /// Reset the RPC provider. It could be used to query data from the
    /// different RPCs during testing.
    pub fn set_rpc(&mut self, rpc_url: &str) {
        self.rpc = Provider::<Http>::try_from(rpc_url).unwrap();
    }
}
