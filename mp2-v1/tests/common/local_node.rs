//! Test with the local contracts interacted by Foundry

use super::{bindings::simple::Simple, TestContext};
use alloy::{
    network::EthereumWallet,
    node_bindings::Anvil,
    primitives::{Address, U256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use ethers::prelude::{Http, Provider};
use log::info;
use std::str::FromStr;

impl TestContext {
    /// Create the test context with a local node.
    pub async fn new_with_local_node() -> Self {
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

        // Deploy the Simple contract.
        let simple = Simple::deploy(&provider).await.unwrap();
        info!("Deployed Simple contract at address: {}", simple.address());

        let builder = simple.setSimples(true, U256::ZERO, "aaaa".to_string(), Address::ZERO);
        let _tx_hash = builder.send().await.unwrap().watch().await.unwrap();

        let builder = simple.setMapping(
            Address::from_str("0x3bf5733f695b2527acc7bd4c5350e57acfd9fbb5").unwrap(),
            U256::ZERO,
        );
        let _tx_hash = builder.send().await.unwrap().watch().await.unwrap();
        let builder = simple.setMapping(
            Address::from_str("0x6cac7190535f4908d0524e7d55b3750376ea1ef7").unwrap(),
            U256::ZERO,
        );
        let _tx_hash = builder.send().await.unwrap().watch().await.unwrap();

        let builder = simple.addToArray(U256::ZERO);
        let _tx_hash = builder.send().await.unwrap().watch().await.unwrap();

        let rpc = Provider::<Http>::try_from(rpc_url).unwrap();

        Self {
            rpc,
            local_node: Some(anvil),
            params: None,
        }
    }
}
