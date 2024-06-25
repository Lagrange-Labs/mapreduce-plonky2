//! Test context used in the test cases

use super::TestCase;
use alloy::node_bindings::AnvilInstance;
use ethers::prelude::{Block, BlockId, EIP1186ProofResponse, Http, Provider, TxHash};
use log::warn;
use mp2_common::eth::{query_latest_block, ProofQuery};
use mp2_v1::api::{build_circuits_params, PublicParameters};
use std::{env, fs, path::PathBuf};

/// Test context
pub(crate) struct TestContext {
    /// HTTP provider
    /// TODO: fix to use alloy provider.
    pub(crate) rpc: Provider<Http>,
    /// Local node
    /// Should release after finishing the all tests.
    pub(crate) local_node: Option<AnvilInstance>,
    /// Parameters
    pub(crate) params: Option<PublicParameters>,
    /// Supported test cases
    pub(crate) cases: Vec<TestCase>,
}

impl TestContext {
    /// Build the parameters.
    /// NOTE: It could avoid `runtime stack overflow`, otherwise needs to set `export RUST_MIN_STACK=100000000`.
    pub(crate) fn build_params(&mut self) {
        let mut path = env::var("LPN_PARAMS").ok();
        let mut rebuild = env::var("LPN_PARAMS_REBUILD").is_ok();

        for arg in env::args() {
            if arg == "--lpn-params-rebuild" {
                rebuild = true;
            }

            let args = &mut arg.split('=');
            let a = args.next().unwrap_or_default();
            let b = args.next().unwrap_or_default();

            if a == "--lpn-params" {
                path.replace(b.to_owned());
            }
        }

        let params = match path {
            Some(path) => {
                let path = PathBuf::from(path);

                if !path.exists() || rebuild {
                    let params = build_circuits_params();
                    let file = bincode::serialize(&params).unwrap();

                    fs::write(path, file).unwrap();

                    params
                } else {
                    let file = fs::read(path).unwrap();

                    bincode::deserialize(&file).unwrap()
                }
            }
            None => build_circuits_params(),
        };

        self.params = Some(params);
    }

    /// Get the public parameters.
    pub(crate) fn params(&self) -> &PublicParameters {
        self.params.as_ref().unwrap()
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
