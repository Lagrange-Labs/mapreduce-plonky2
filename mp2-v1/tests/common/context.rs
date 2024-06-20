//! Test context used in the test cases

use super::utils::load_or_generate_public_params;
use ethers::prelude::{Block, BlockId, EIP1186ProofResponse, Http, Provider, TxHash};
use log::warn;
use mp2_common::eth::{query_latest_block, ProofQuery};
use mp2_v1::api::PublicParameters;

/// Cached filename of the public parameters
const PUBLIC_PARAMS_FILE: &str = "mp2.params";

/// Test context
pub(crate) struct TestContext {
    params: PublicParameters,
    rpc: Provider<Http>,
}

impl TestContext {
    /// Create the test context.
    pub(crate) fn new(rpc_url: &str) -> Self {
        let params = load_or_generate_public_params(PUBLIC_PARAMS_FILE).unwrap();
        let rpc = Provider::<Http>::try_from(rpc_url).unwrap();

        Self { params, rpc }
    }

    /// Get the public parameters.
    pub(crate) fn params(&self) -> &PublicParameters {
        &self.params
    }

    /// Query the latest block.
    pub(crate) async fn query_latest_block(&self) -> Block<TxHash> {
        query_latest_block(&self.rpc).await.unwrap()
    }

    /// Query the MPT proof.
    pub(crate) async fn query_mpt_proof(
        &self,
        query: &ProofQuery,
        block_number: Option<u64>,
    ) -> EIP1186ProofResponse {
        let block_id = block_number.map(|n| BlockId::Number(n.into()));
        query.query_mpt_proof(&self.rpc, block_id).await.unwrap()
    }

    /// Reset the RPC provider. It could be used to query data from the
    /// different RPCs during testing.
    pub(crate) fn set_rpc(&mut self, rpc_url: &str) {
        self.rpc = Provider::<Http>::try_from(rpc_url).unwrap();
    }
}
