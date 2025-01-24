use super::{
    indexing::MappingUpdate,
    storage_slot_value::{LargeStruct, StorageSlotValue},
    table_source::DEFAULT_ADDRESS,
};
use crate::common::{
    bindings::simple::{
        Simple,
        Simple::{MappingChange, MappingOperation, MappingStructChange},
    },
    TestContext,
};
use alloy::{
    contract::private::Provider,
    primitives::{Address, U256},
    providers::ProviderBuilder,
};
use itertools::Itertools;
use log::{debug, info};

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
}

/// Common functions for a specific type to interact with the test contract
pub trait ContractController {
    /// Get the current values from the contract.
    async fn current_values(ctx: &TestContext, contract: &Contract) -> Self;

    /// Update the values to the contract.
    async fn update_contract(&self, ctx: &TestContext, contract: &Contract);
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

        let call = simple_contract.setSimpleStruct(self.field1, self.field2, self.field3);
        call.send().await.unwrap().watch().await.unwrap();
        // Sanity check
        {
            let updated = Self::current_values(ctx, contract).await;
            assert_eq!(self, &updated);
        }
        log::info!("Updated simple contract for LargeStruct");
    }
}

impl ContractController for Vec<MappingUpdate<Address>> {
    async fn current_values(_ctx: &TestContext, _contract: &Contract) -> Self {
        unimplemented!("Unimplemented for fetching the all mapping values")
    }

    async fn update_contract(&self, ctx: &TestContext, contract: &Contract) {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());
        let contract = Simple::new(contract.address, &provider);

        let changes = self
            .iter()
            .map(|tuple| {
                let operation: MappingOperation = tuple.into();
                let operation = operation.into();
                let (key, value) = match tuple {
                    MappingUpdate::Deletion(k, _) => (*k, *DEFAULT_ADDRESS),
                    MappingUpdate::Update(k, _, v) | MappingUpdate::Insertion(k, v) => (*k, *v),
                };
                MappingChange {
                    operation,
                    key,
                    value,
                }
            })
            .collect_vec();

        let call = contract.changeMapping(changes);
        call.send().await.unwrap().watch().await.unwrap();
        // Sanity check
        for update in self.iter() {
            match update {
                MappingUpdate::Deletion(k, _) => {
                    let res = contract.m1(*k).call().await.unwrap();
                    let v: U256 = res._0.into_word().into();
                    assert_eq!(v, U256::ZERO, "Key deletion is wrong on contract");
                }
                MappingUpdate::Insertion(k, v) => {
                    let res = contract.m1(*k).call().await.unwrap();
                    let new_value: U256 = res._0.into_word().into();
                    let new_value = Address::from_u256_slice(&[new_value]);
                    assert_eq!(&new_value, v, "Key insertion is wrong on contract");
                }
                MappingUpdate::Update(k, _, v) => {
                    let res = contract.m1(*k).call().await.unwrap();
                    let new_value: U256 = res._0.into_word().into();
                    let new_value = Address::from_u256_slice(&[new_value]);
                    assert_eq!(&new_value, v, "Key update is wrong on contract");
                }
            }
        }
        log::info!("Updated simple contract single values");
    }
}

impl ContractController for Vec<MappingUpdate<LargeStruct>> {
    async fn current_values(_ctx: &TestContext, _contract: &Contract) -> Self {
        unimplemented!("Unimplemented for fetching the all mapping values")
    }

    async fn update_contract(&self, ctx: &TestContext, contract: &Contract) {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());
        let contract = Simple::new(contract.address, &provider);

        let changes = self
            .iter()
            .map(|tuple| {
                let operation: MappingOperation = tuple.into();
                let operation = operation.into();
                let (key, field1, field2, field3) = match tuple {
                    MappingUpdate::Insertion(k, v)
                    | MappingUpdate::Deletion(k, v)
                    | MappingUpdate::Update(k, _, v) => (*k, v.field1, v.field2, v.field3),
                };
                MappingStructChange {
                    operation,
                    key,
                    field1,
                    field2,
                    field3,
                }
            })
            .collect_vec();

        let call = contract.changeMappingStruct(changes);
        call.send().await.unwrap().watch().await.unwrap();
        // Sanity check
        for update in self.iter() {
            match update {
                MappingUpdate::Deletion(k, _) => {
                    let res = contract.structMapping(*k).call().await.unwrap();
                    assert_eq!(
                        LargeStruct::from(res),
                        LargeStruct::new(U256::from(0), 0, 0)
                    );
                }
                MappingUpdate::Insertion(k, v) | MappingUpdate::Update(k, _, v) => {
                    let res = contract.structMapping(*k).call().await.unwrap();
                    debug!("Set mapping struct: key = {k}, value = {v:?}");
                    assert_eq!(&LargeStruct::from(res), v);
                }
            }
        }
        log::info!("Updated simple contract for mapping values of LargeStruct");
    }
}
