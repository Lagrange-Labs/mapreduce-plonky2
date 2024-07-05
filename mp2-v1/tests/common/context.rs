//! Test context used in the test cases
use alloy::node_bindings::AnvilInstance;
use anyhow::Context;
use envconfig::Envconfig;
use ethers::{
    prelude::{Block, BlockId, EIP1186ProofResponse, Http, Provider, TxHash},
    providers::Middleware,
    types::BlockNumber,
};
use log::info;
use mp2_common::eth::ProofQuery;
use mp2_v1::api::{build_circuits_params, PublicParameters};
use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::PathBuf,
};

use super::TestCase;

#[derive(Envconfig)]
struct TestContextConfig {
    #[envconfig(from = "LPN_PARAMS_DIR")]
    params_dir: Option<String>,

    #[envconfig(from = "LPN_PARAMS_REBUILD", default = "false")]
    force_rebuild: bool,
}

/// Test context
pub(crate) struct TestContext {
    /// HTTP provider
    /// TODO: fix to use alloy provider.
    pub(crate) rpc: Provider<Http>,
    pub(crate) block_number: BlockNumber,
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
    ///
    /// NOTE: It could avoid `runtime stack overflow`, otherwise needs to set
    /// `export RUST_MIN_STACK=10000000`.
    pub(crate) fn build_params(&mut self) -> anyhow::Result<()> {
        let cfg = TestContextConfig::init_from_env().context("while parsing configuration")?;

        self.params = Some(match cfg.params_dir {
            Some(params_path_str) => {
                info!("attempting to read parameters from {params_path_str}");
                let params_path = PathBuf::from(params_path_str);
                if !params_path.exists() {
                    std::fs::create_dir_all(&params_path)
                        .context("while creating parameters folder")?;
                }

                let mut mp2_filepath = params_path.clone();
                mp2_filepath.push("params_mp2");

                let mp2 = if !mp2_filepath.exists() || cfg.force_rebuild {
                    info!("rebuilding the mp2 parameters");
                    let mp2 = build_circuits_params();
                    info!("writing the mp2-v1 parameters");
                    bincode::serialize_into(
                        BufWriter::new(
                            File::create(&mp2_filepath)
                                .with_context(|| format!("while creating {mp2_filepath:?}"))?,
                        ),
                        &mp2,
                    )?;
                    mp2
                } else {
                    info!("parsing the mp2-v1 parameters");
                    bincode::deserialize_from(BufReader::new(
                        File::open(&mp2_filepath)
                            .with_context(|| format!("while opening {mp2_filepath:?}"))?,
                    ))
                    .context("while parsing MP2 parameters")?
                };

                mp2
            }
            None => {
                info!("recomputing parameters");
                build_circuits_params()
            }
        });

        Ok(())
    }

    /// Get the public parameters.
    pub(crate) fn params(&self) -> &PublicParameters {
        self.params.as_ref().unwrap()
    }

    pub(crate) fn get_block_number(&self) -> Option<u64> {
        self.block_number.as_number().map(|bn| {
            let mut bytes = [0u8; 8];
            bn.to_big_endian(&mut bytes);
            u64::from_be_bytes(bytes)
        })
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
