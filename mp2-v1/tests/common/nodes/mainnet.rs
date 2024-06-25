//! Test with the mainnet contracts

use super::super::{TestCase, TestContext};
use ethers::prelude::{Http, Provider};
use mp2_test::eth::get_mainnet_url;

impl TestContext {
    /// Create the test context with the mainnet contracts.
    pub(crate) fn new_mainnet() -> Self {
        let rpc_url = get_mainnet_url();
        let rpc = Provider::<Http>::try_from(rpc_url).unwrap();

        Self {
            rpc,
            local_node: None,
            params: None,
            cases: vec![TestCase::pudgy_penguins_test_case()],
        }
    }
}
