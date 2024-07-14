//! Test with the mainnet contracts

use super::super::{TestCase, TestContext};
use ethers::{
    prelude::{Http, Provider},
    providers::Middleware,
    types::BlockNumber,
};
use mp2_test::eth::get_mainnet_url;

impl TestContext {
    /// Create the test context with the mainnet contracts.
    pub(crate) async fn new_mainnet() -> Self {
        let rpc_url = get_mainnet_url();
        let rpc = Provider::<Http>::try_from(rpc_url.clone()).unwrap();
        let bn = rpc.get_block_number().await.unwrap();
        Self {
            rpc_url,
            rpc,
            block_number: BlockNumber::Number(bn),
            local_node: None,
            params: None,
            cases: vec![TestCase::pudgy_penguins_test_case()],
        }
    }
}
