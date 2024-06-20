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
                    let file = bincode::serialize(&params)?;

                    fs::write(path, file)?;

                    params
                } else {
                    let file = fs::read(path)?;

                    bincode::deserialize(&file)?
                }
            }
            None => build_circuits_params(),
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
