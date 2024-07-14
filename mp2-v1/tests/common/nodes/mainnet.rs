//! Test with the mainnet contracts

use super::super::{TestCase, TestContext};
use alloy::{
    eips::BlockNumberOrTag,
    providers::{Provider, ProviderBuilder},
};
use mp2_test::eth::get_mainnet_url;

impl TestContext {
    /// Create the test context with the mainnet contracts.
    pub(crate) async fn new_mainnet() -> Self {
        let rpc_url = get_mainnet_url();
        let rpc = ProviderBuilder::new().on_http(rpc_url.parse().unwrap());
        let bn = rpc.get_block_number().await.unwrap();
        Self {
            rpc_url,
            rpc,
            block_number: BlockNumberOrTag::Number(bn),
            local_node: None,
            params: None,
            cases: vec![TestCase::pudgy_penguins_test_case()],
        }
    }
}
