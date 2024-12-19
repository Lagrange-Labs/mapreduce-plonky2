use alloy::{
    network::Ethereum, primitives::Address, providers::RootProvider, transports::Transport,
};
use anyhow::Result;
use log::info;

use crate::common::{
    bindings::simple::Simple::{self, SimpleInstance},
    TestContext,
};

use super::indexing::{ContractUpdate, SimpleSingleValue, UpdateSimpleStorage};

pub struct Contract {
    pub address: Address,
    pub chain_id: u64,
}

impl Contract {
    /// Creates a new [`Contract`] from an [`Address`] and `chain_id`
    pub fn new(address: Address, chain_id: u64) -> Contract {
        Contract { address, chain_id }
    }
    /// Getter for `chain_id`
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
    /// Getter for [`Address`]
    pub fn address(&self) -> Address {
        self.address
    }
}

/// Trait implemented by any test contract.
pub trait TestContract<T>
where
    T: Transport + Clone,
{
    /// How this implementor ingests updates.
    type Update: ContractUpdate<T, Contract = Self::Contract>;
    /// The actual contract instance.
    type Contract;
    /// Function that generates a new instance of self given a [`Provider`] and a `chain_id`
    fn new(address: Address, provider: &RootProvider<T>) -> Self;
    /// Get an instance of the contract.
    fn get_instance(&self) -> &Self::Contract;
    /// Apply an update to the contract.
    async fn apply_update(&self, ctx: &TestContext, update: &Self::Update) -> Result<()> {
        let contract = self.get_instance();
        update.apply_to(ctx, contract).await;
        info!("Updated contract with new values {:?}", update);
        Ok(())
    }
}

pub struct SimpleContract<T: Transport + Clone> {
    pub instance: SimpleInstance<T, RootProvider<T, Ethereum>>,
}

impl<T> TestContract<T> for SimpleContract<T>
where
    T: Transport + Clone,
{
    type Update = UpdateSimpleStorage;

    type Contract = SimpleInstance<T, RootProvider<T, Ethereum>>;
    fn new(address: Address, provider: &RootProvider<T, Ethereum>) -> Self {
        Self {
            instance: Simple::new(address, provider.clone()),
        }
    }
    fn get_instance(&self) -> &Self::Contract {
        &self.instance
    }
}

impl<T> SimpleContract<T>
where
    T: Transport + Clone,
{
    pub async fn current_single_values(&self) -> Result<SimpleSingleValue> {
        let contract = self.get_instance();

        Ok(SimpleSingleValue {
            s1: contract.s1().call().await.unwrap()._0,
            s2: contract.s2().call().await.unwrap()._0,
            s3: contract.s3().call().await.unwrap()._0,
            s4: contract.s4().call().await.unwrap()._0,
        })
    }
}
