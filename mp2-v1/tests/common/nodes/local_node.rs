//! Test with the local contracts interacted by Foundry

use super::super::{bindings::simple::Simple, TestCase, TestContext};
use alloy::{
    contract::private::{Network, Provider, Transport},
    eips::BlockNumberOrTag,
    network::EthereumWallet,
    node_bindings::Anvil,
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use log::info;

impl TestContext {
    /// Create the test context with the custom contracts of a local node.
    pub async fn new_local_node() -> Self {
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

        // Deploy the Simple contract and create the corresponding test case.
        let simple_case = init_simple_contract(&provider).await;

        let rpc = ProviderBuilder::new().on_http(rpc_url.parse().unwrap());

        let bn = rpc.get_block_number().await.unwrap();

        Self {
            rpc_url: anvil.endpoint(),
            rpc,
            block_number: BlockNumberOrTag::Number(bn),
            local_node: Some(anvil),
            params: None,
            cases: vec![simple_case],
        }
    }
}

/// Deploy the Simple contract and create the corresponding test case.
async fn init_simple_contract<T: Transport + Clone, P: Provider<T, N>, N: Network>(
    provider: &P,
) -> TestCase {
    // Deploy the Simple contract.
    let simple = Simple::deploy(&provider).await.unwrap();
    info!("Deployed Simple contract at address: {}", simple.address());

    // Create the Simple test case.
    TestCase::local_simple_test_case(simple).await
}
