//! Test context used in the test cases
use alloy::{
    eips::{BlockId, BlockNumberOrTag},
    network::{EthereumWallet, Network},
    node_bindings::{Anvil, AnvilInstance},
    providers::{Provider, ProviderBuilder, RootProvider},
    rpc::types::{Block, BlockTransactionsKind, EIP1186AccountProofResponse},
    signers::local::PrivateKeySigner,
    transports::http::{Client, Http},
};
use anyhow::Context;
use envconfig::Envconfig;
use log::info;
use mp2_common::eth::ProofQuery;
use mp2_v1::api::{build_circuits_params, PublicParameters};
use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::PathBuf,
};

use super::proof_storage::ProofStorage;

#[derive(Envconfig)]
struct TestContextConfig {
    #[envconfig(from = "LPN_PARAMS_DIR")]
    params_dir: Option<String>,

    #[envconfig(from = "LPN_PARAMS_REBUILD", default = "false")]
    force_rebuild: bool,
}

/// Test context
pub(crate) struct TestContext<P: ProofStorage> {
    pub(crate) rpc_url: String,
    /// HTTP provider
    /// TODO: fix to use alloy provider.
    pub(crate) rpc: RootProvider<Http<Client>>,
    /// Local node
    /// Should release after finishing the all tests.
    pub(crate) local_node: Option<AnvilInstance>,
    /// Parameters
    pub(crate) params: Option<PublicParameters>,
    pub(crate) storage: P,
}
/// Create the test context on a local anvil chain. It also setups the local simple test cases
pub async fn new_local_chain<P: ProofStorage>(storage: P) -> TestContext<P> {
    // Spin up a local node.
    let anvil = Anvil::new().spawn();

    // Set up signer from the first default Anvil account.
    let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
    let wallet = EthereumWallet::from(signer);

    // Create a provider with the wallet for contract deployment and interaction.
    let rpc_url = anvil.endpoint();
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(rpc_url.parse().unwrap());
    info!("Anvil running at `{}`", rpc_url);

    let rpc = ProviderBuilder::new().on_http(rpc_url.parse().unwrap());

    TestContext {
        rpc_url: anvil.endpoint(),
        rpc,
        local_node: Some(anvil),
        params: None,
        storage,
    }
}

impl<P: ProofStorage> TestContext<P> {
    pub(crate) fn wallet(&self) -> EthereumWallet {
        let signer: PrivateKeySigner = self.local_node.as_ref().unwrap().keys()[0].clone().into();
        EthereumWallet::from(signer)
    }
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

    pub(crate) async fn block_number(&self) -> u64 {
        self.rpc.get_block_number().await.unwrap()
    }

    pub(crate) async fn query_current_block(&self) -> Block {
        self.query_block_at(BlockNumberOrTag::Number(self.block_number().await))
            .await
    }
    /// Returns the block
    pub(crate) async fn query_block_at(&self, bn: BlockNumberOrTag) -> Block {
        // assume there is always a block so None.unwrap() should not occur
        // and it's still a test...
        self.rpc
            .get_block(BlockId::Number(bn), BlockTransactionsKind::Hashes)
            .await
            .unwrap()
            .unwrap()
    }

    /// Query the MPT proof.
    pub(crate) async fn query_mpt_proof(
        &self,
        query: &ProofQuery,
        block_number: BlockNumberOrTag,
    ) -> EIP1186AccountProofResponse {
        query
            .query_mpt_proof(&self.rpc, block_number)
            .await
            .unwrap()
    }

    /// Reset the RPC provider. It could be used to query data from the
    /// different RPCs during testing.
    pub(crate) fn set_rpc(&mut self, rpc_url: &str) {
        self.rpc = ProviderBuilder::new().on_http(rpc_url.parse().unwrap());
    }
}
