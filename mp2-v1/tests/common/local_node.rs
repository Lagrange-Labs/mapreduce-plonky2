//! Test with the local contracts interacted by Foundry

use super::{bindings::simple::Simple, cases::local_simple, TestContext};
use alloy::{
    contract::private::{Network, Provider, Transport},
    network::EthereumWallet,
    node_bindings::Anvil,
    primitives::{Address, U256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use ethers::prelude::{Http, Provider as EthProvider};
use log::info;
use rand::{thread_rng, Rng};
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

        // Deploy the Simple contract and set data into.
        init_simple_contract(&provider).await;

        let rpc = EthProvider::<Http>::try_from(rpc_url).unwrap();

        Self {
            rpc,
            local_node: Some(anvil),
            params: None,
        }
    }
}

/// Deploy the Simple contract and set data into.
async fn init_simple_contract<T: Transport + Clone, P: Provider<T, N>, N: Network>(provider: &P) {
    // Deploy the Simple contract.
    let simple = Simple::deploy(&provider).await.unwrap();
    info!("Deployed Simple contract at address: {}", simple.address());

    // setSimples(bool newS1, uint256 newS2, string memory newS3, address newS4)
    let b = simple.setSimples(
        true,
        U256::from(100),
        "test".to_string(),
        Address::from_str("0xb90ed61bffed1df72f2ceebd965198ad57adfcbd").unwrap(),
    );
    b.send().await.unwrap().watch().await.unwrap();

    // setMapping(address key, uint256 value)
    let mut rng = thread_rng();
    for addr in local_simple::MAPPING_ADDRESSES {
        let b = simple.setMapping(
            Address::from_str(addr).unwrap(),
            U256::from(rng.gen::<u64>()),
        );
        b.send().await.unwrap().watch().await.unwrap();
    }

    // addToArray(uint256 value)
    for _ in 0..5 {
        let b = simple.addToArray(U256::from(rng.gen::<u64>()));
        b.send().await.unwrap().watch().await.unwrap();
    }
}
