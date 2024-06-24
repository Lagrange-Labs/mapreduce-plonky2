//! Test context used in the test cases

use ethers::{
    prelude::{Block, BlockId, EIP1186ProofResponse, Http, Provider, TxHash},
    providers::Middleware,
    types::BlockNumber,
};
use log::warn;
use mp2_common::eth::{query_latest_block, ProofQuery};
use mp2_v1::api::{build_circuits_params, PublicParameters};
use std::{env, fs, path::PathBuf};

/// Test context
pub(crate) struct TestContext {
    params: PublicParameters,
    rpc: Provider<Http>,
    block_number: BlockNumber,
}

impl TestContext {
    /// Create the test context.
    pub(crate) async fn new(rpc_url: &str) -> anyhow::Result<Self> {
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
                    log::info!("Rebuilding the parameters");
                    let params = build_circuits_params();
                    log::info!("Writing the parameters");
                    let file = bincode::serialize(&params)?;

                    fs::write(path, file)?;

                    params
                } else {
                    log::info!("Reading the parameters");
                    let file = fs::read(path)?;

                    bincode::deserialize(&file)?
                }
            }
            None => build_circuits_params(),
        };

        let rpc = Provider::<Http>::try_from(rpc_url)?;
        let bn = rpc.get_block_number().await.unwrap();
        Ok(Self {
            params,
            rpc,
            block_number: BlockNumber::Number(bn),
        })
    }

    /// Get the public parameters.
    pub(crate) fn params(&self) -> &PublicParameters {
        &self.params
    }

    /// Returns the block for which this test context is set
    pub(crate) async fn query_block(&self) -> Block<TxHash> {
        // assume there is always a block so None.unwrap() should not occur
        // and it's still a test...
        self.rpc
            .get_block(self.block_number)
            .await
            .unwrap()
            .unwrap()
    }

    /// Query the latest block.
    /// TODO: DEPRECATED: we need to use a single block number for all our proofs
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
