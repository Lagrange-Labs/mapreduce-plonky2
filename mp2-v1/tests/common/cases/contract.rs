use std::future::Future;

use super::slot_info::{LargeStruct, MappingInfo, StorageSlotMappingKey, StorageSlotValue};
use crate::common::{
    bindings::{
        eventemitter::EventEmitter::{self, EventEmitterInstance},
        simple::{
            Simple,
            Simple::{
                MappingChange, MappingOfSingleValueMappingsChange, MappingOfStructMappingsChange,
                MappingOperation, MappingStructChange,
            },
        },
    },
    cases::indexing::ReceiptUpdate,
    TestContext,
};
use alloy::{
    contract::private::Provider,
    network::Ethereum,
    primitives::{Address, U256},
    providers::{ProviderBuilder, RootProvider},
    transports::Transport,
};
use anyhow::Result;
use itertools::Itertools;
use log::info;

use super::indexing::ContractUpdate;

pub struct Contract {
    pub address: Address,
    pub chain_id: u64,
}

impl Contract {
    /// Deploy the simple contract.
    pub(crate) async fn deploy_simple_contract(ctx: &TestContext) -> Self {
        // Create a provider with the wallet for contract deployment and interaction.
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());

        let contract = Simple::deploy(&provider).await.unwrap();
        let address = *contract.address();
        info!("Deployed Simple contract at address: {address}");
        let chain_id = ctx.rpc.get_chain_id().await.unwrap();
        Self { address, chain_id }
    }

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

/// Common functions for a specific type to interact with the test contract
pub trait ContractController {
    /// Get the current values from the contract.
    async fn current_values(ctx: &TestContext, contract: &Contract) -> Self;

    /// Update the values to the contract.
    fn update_contract(
        &self,
        ctx: &TestContext,
        contract: &Contract,
    ) -> impl Future<Output = ()> + Send;
}

/// Single values collection
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimpleSingleValues {
    pub(crate) s1: bool,
    pub(crate) s2: U256,
    pub(crate) s3: String,
    pub(crate) s4: Address,
}

impl ContractController for SimpleSingleValues {
    async fn current_values(ctx: &TestContext, contract: &Contract) -> Self {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());
        let contract = Simple::new(contract.address, &provider);

        SimpleSingleValues {
            s1: contract.s1().call().await.unwrap()._0,
            s2: contract.s2().call().await.unwrap()._0,
            s3: contract.s3().call().await.unwrap()._0,
            s4: contract.s4().call().await.unwrap()._0,
        }
    }

    async fn update_contract(&self, ctx: &TestContext, contract: &Contract) {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());
        let simple_contract = Simple::new(contract.address, &provider);

        let call = simple_contract.setSimples(self.s1, self.s2, self.s3.clone(), self.s4);
        call.send().await.unwrap().watch().await.unwrap();
        log::info!("Updated simple contract single values");
        // Sanity check
        {
            let updated = Self::current_values(ctx, contract).await;
            assert_eq!(self, &updated);
        }
    }
}

impl ContractController for LargeStruct {
    async fn current_values(ctx: &TestContext, contract: &Contract) -> Self {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());
        let contract = Simple::new(contract.address, &provider);

        contract.simpleStruct().call().await.unwrap().into()
    }

    async fn update_contract(&self, ctx: &TestContext, contract: &Contract) {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());
        let simple_contract = Simple::new(contract.address, &provider);

        let call = simple_contract.setSimpleStruct((*self).into());
        call.send().await.unwrap().watch().await.unwrap();
        // Sanity check
        {
            let updated = Self::current_values(ctx, contract).await;
            assert_eq!(self, &updated);
        }
        log::info!("Updated simple contract for LargeStruct");
    }
}

#[derive(Clone, Debug)]
pub enum MappingUpdate<K, V> {
    // key and value
    Insertion(K, V),
    // key and value
    Deletion(K, V),
    // key, previous value and new value
    Update(K, V, V),
}

impl<K, V> MappingUpdate<K, V>
where
    K: StorageSlotMappingKey,
    V: StorageSlotValue,
{
    pub fn to_tuple(&self) -> (K, V) {
        match self {
            MappingUpdate::Insertion(key, value)
            | MappingUpdate::Deletion(key, value)
            | MappingUpdate::Update(key, _, value) => (key.clone(), value.clone()),
        }
    }
}

impl<K, V> From<&MappingUpdate<K, V>> for MappingOperation {
    fn from(update: &MappingUpdate<K, V>) -> Self {
        Self::from(match update {
            MappingUpdate::Deletion(_, _) => 0,
            MappingUpdate::Update(_, _, _) => 1,
            MappingUpdate::Insertion(_, _) => 2,
        })
    }
}

impl<T: MappingInfo> ContractController for Vec<MappingUpdate<T, T::Value>> {
    async fn current_values(_ctx: &TestContext, _contract: &Contract) -> Self {
        unimplemented!("Unimplemented for fetching the all mapping values")
    }
    async fn update_contract(&self, ctx: &TestContext, contract: &Contract) {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());
        let contract = Simple::new(contract.address, &provider);

        let changes = self.iter().map(T::to_call).collect_vec();

        T::call_contract(&contract, changes).await
    }
}
pub struct EventContract<T: Transport + Clone> {
    pub instance: EventEmitterInstance<T, RootProvider<T, Ethereum>, Ethereum>,
}

impl<T: Transport + Clone> TestContract<T> for EventContract<T> {
    type Update = ReceiptUpdate;
    type Contract = EventEmitterInstance<T, RootProvider<T, Ethereum>>;

    fn new(address: Address, provider: &RootProvider<T>) -> Self {
        Self {
            instance: EventEmitter::new(address, provider.clone()),
        }
    }

    fn get_instance(&self) -> &Self::Contract {
        &self.instance
    }
}
