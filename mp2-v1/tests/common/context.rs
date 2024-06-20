//! Test context used in the test cases

use std::{env, fs, path::PathBuf};

use ethers::prelude::{EIP1186ProofResponse, Http, Provider};
use log::warn;
use mp2_common::eth::ProofQuery;
use mp2_v1::api::{build_circuits_params, PublicParameters};

/// Retry number for the RPC request
const RETRY_NUM: usize = 3;

/// Test context
pub(crate) struct TestContext {
    params: PublicParameters,
    rpc: Provider<Http>,
}

impl TestContext {
    /// Create the test context.
    pub(crate) fn new(rpc_url: &str) -> anyhow::Result<Self> {
        let params = match env::var("LAGRANGE_PPARAMS") {
            Ok(path) => {
                let path = PathBuf::from(path);

                if !path.exists() || env::var("LAGRANGE_PPARAMS_REBUILD").is_ok() {
                    let params = build_circuits_params();
                    let file = bincode::serialize(&params)?;

                    fs::write(path, file)?;

                    params
                } else {
                    let file = fs::read(path)?;

                    bincode::deserialize(&file)?
                }
            }
            _ => build_circuits_params(),
        };

        let rpc = Provider::<Http>::try_from(rpc_url)?;

        Ok(Self { params, rpc })
    }

    /// Get the public parameters.
    pub(crate) fn params(&self) -> &PublicParameters {
        &self.params
    }

    /// Query the MPT proof.
    pub(crate) async fn query_mpt_proof(&self, query: &ProofQuery) -> EIP1186ProofResponse {
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
    pub(crate) fn set_rpc(&mut self, rpc_url: &str) {
        self.rpc = Provider::<Http>::try_from(rpc_url).unwrap();
    }
}
