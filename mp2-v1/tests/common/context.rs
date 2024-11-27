//! Test context used in the test cases
use alloy::{
    eips::{BlockId, BlockNumberOrTag},
    network::EthereumWallet,
    node_bindings::{Anvil, AnvilInstance},
    providers::{Provider, ProviderBuilder, RootProvider},
    rpc::types::{Block, EIP1186AccountProofResponse},
    signers::local::PrivateKeySigner,
    transports::http::{Client, Http},
};
use anyhow::{Context, Result};
use envconfig::Envconfig;
use log::info;
use mp2_common::eth::ProofQuery;
use mp2_v1::{
    api::{build_circuits_params, PublicParameters},
    block_extraction::ExtractionType,
};
use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::PathBuf,
};
use verifiable_db::api::QueryParameters;

use crate::common::mkdir_all;

use super::{
    benchmarker::Benchmarker,
    cases::{
        self,
        query::{
            INDEX_TREE_MAX_DEPTH, MAX_NUM_COLUMNS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_OUTPUTS,
            MAX_NUM_PLACEHOLDERS, MAX_NUM_PREDICATE_OPS, MAX_NUM_RESULT_OPS, NUM_CHUNKS, NUM_ROWS,
            ROW_TREE_MAX_DEPTH,
        },
    },
    proof_storage::ProofKV,
    PublicParameters,
};

#[derive(Envconfig)]
pub struct TestContextConfig {
    #[envconfig(from = "LPN_PARAMS_DIR")]
    pub params_dir: Option<String>,

    #[envconfig(from = "LPN_PARAMS_REBUILD", default = "false")]
    pub force_rebuild: bool,
}

/// Test context
pub(crate) struct TestContext {
    pub(crate) rpc_url: String,
    /// HTTP provider
    /// TODO: fix to use alloy provider.
    pub(crate) rpc: RootProvider<Http<Client>>,
    /// Local node
    /// Should release after finishing the all tests.
    pub(crate) local_node: Option<AnvilInstance>,
    /// Parameters
    pub(crate) params: Option<PublicParameters>,
    pub(crate) query_params: Option<
        verifiable_db::api::QueryParameters<
            NUM_CHUNKS,
            NUM_ROWS,
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_OUTPUTS,
            MAX_NUM_ITEMS_PER_OUTPUT,
            MAX_NUM_PLACEHOLDERS,
        >,
    >,
    pub(crate) storage: ProofKV,
    pub(crate) b: Benchmarker,
}
/// Create the test context on a local anvil chain. It also setups the local simple test cases
pub async fn new_local_chain(storage: ProofKV) -> TestContext {
    // Spin up a local node.
    let anvil = Anvil::new().spawn();
    // Create a provider with the wallet for contract deployment and interaction.
    let rpc_url = anvil.endpoint();
    info!("Anvil running at `{}`", rpc_url);
    let rpc = ProviderBuilder::new().on_http(rpc_url.parse().unwrap());

    TestContext {
        rpc_url: anvil.endpoint(),
        rpc,
        local_node: Some(anvil),
        params: None,
        query_params: None,
        storage,
        b: Benchmarker::new_from_env().expect("can't create benchmarker"),
    }
}

pub enum ParamsType {
    Indexing(ExtractionType),
    Query,
}

impl ParamsType {
    pub fn full_path(&self, mut pre: PathBuf) -> PathBuf {
        match self {
            ParamsType::Indexing(_) => pre.push("index.params"),
            ParamsType::Query => pre.push("query.params"),
        };
        pre
    }

    pub fn parse(&self, path: PathBuf, ctx: &mut TestContext) -> Result<()> {
        match self {
            ParamsType::Query => {
                info!("parsing the querying mp2-v1 parameters");
                let params = bincode::deserialize_from(BufReader::new(
                    File::open(&path).with_context(|| format!("while opening {path:?}"))?,
                ))
                .context("while parsing MP2 parameters")?;
                ctx.query_params = Some(params);
            }
            ParamsType::Indexing(_) => {
                info!("parsing the indexing mp2-v1 parameters");
                let params = bincode::deserialize_from(BufReader::new(
                    File::open(&path).with_context(|| format!("while opening {path:?}"))?,
                ))
                .context("while parsing MP2 parameters")?;
                ctx.params = Some(params);
            }
        };
        Ok(())
    }

    pub fn build(&self, ctx: &mut TestContext, path: PathBuf) -> Result<()>
    where
        [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
    {
        match self {
            ParamsType::Query => {
                // load indexing info if we can
                let mut info_path = path.clone();
                info_path.pop();
                info_path.push(INDEX_INFO_FILE);
                let index_info: Vec<u8> = bincode::deserialize_from(BufReader::new(
                    File::open(&info_path).with_context(|| format!("while opening {path:?}"))?,
                ))
                .context("while parsing MP2 parameters")?;

                info!("building the mp2 querying parameters");
                let params = QueryParameters::build_params(&index_info)?;
                ctx.query_params = Some(params);
                Ok(())
            }
            ParamsType::Indexing(et) => {
                info!("building the mp2 indexing parameters");
                let mp2 = build_circuits_params(*et);
                ctx.params = Some(mp2);
                info!("writing the mp2-v1 indexing parameters");
                Ok(())
            }
        }
    }

    pub fn build_and_save(&self, path: PathBuf, ctx: &mut TestContext) -> Result<()>
    where
        [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
    {
        self.build(ctx, path.clone())?;
        match self {
            ParamsType::Query => {
                bincode::serialize_into(
                    BufWriter::new(
                        File::create(&path).with_context(|| format!("while creating {path:?}"))?,
                    ),
                    &ctx.query_params.as_ref().unwrap(),
                )?;
                Ok(())
            }
            ParamsType::Indexing(_) => {
                bincode::serialize_into(
                    BufWriter::new(
                        File::create(&path).with_context(|| format!("while creating {path:?}"))?,
                    ),
                    &ctx.params.as_ref().unwrap(),
                )?;
                // info necessary for the query set
                let info = ctx.params.as_ref().unwrap().get_params_info()?;
                let mut info_path = path.clone();
                info_path.pop();
                info_path.push(INDEX_INFO_FILE);
                bincode::serialize_into(
                    BufWriter::new(File::create(&info_path).context("error creating info file")?),
                    &info,
                )?;
                Ok(())
            }
        }
    }
}

const INDEX_INFO_FILE: &str = "index.info";

impl TestContext {
    pub(crate) fn wallet(&self) -> EthereumWallet {
        let signer: PrivateKeySigner = self.local_node.as_ref().unwrap().keys()[0].clone().into();
        EthereumWallet::from(signer)
    }
    /// Build the parameters.
    ///
    /// NOTE: It could avoid `runtime stack overflow`, otherwise needs to set
    /// `export RUST_MIN_STACK=10000000`.
    pub(crate) fn build_params(&mut self, p: ParamsType) -> anyhow::Result<()> {
        let cfg = TestContextConfig::init_from_env().context("while parsing configuration")?;

        match cfg.params_dir {
            Some(params_path_str) => {
                info!("attempting to read parameters from {params_path_str}");
                mkdir_all(&params_path_str)?;
                let params_path = PathBuf::from(params_path_str);
                let full = p.full_path(params_path.clone());
                if !full.exists() || cfg.force_rebuild {
                    p.build_and_save(full, self)?;
                } else {
                    p.parse(full, self)?;
                };
            }
            None => {
                panic!("CI should save params on disk so tests can run faster");
            }
        }

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
            .get_block(BlockId::Number(bn), false.into())
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

    pub fn run_query_proof(
        &self,
        name: &str,
        input: cases::query::GlobalCircuitInput,
    ) -> Result<Vec<u8>> {
        self.b.bench(name, || {
            self.query_params.as_ref().unwrap().generate_proof(input)
        })
    }
}
