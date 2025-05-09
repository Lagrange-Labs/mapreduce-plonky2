use super::{
    slot_info::{LargeStruct, MappingKey, MappingOfMappingsKey},
    table_source::DEFAULT_ADDRESS,
};
use crate::common::{
    bindings::simple::{
        Simple,
        Simple::{
            MappingChange, MappingOfSingleValueMappingsChange, MappingOfStructMappingsChange,
            MappingOperation, MappingStructChange,
        },
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
            .wallet(ctx.wallet())
            .connect_http(ctx.rpc_url.parse().unwrap());

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
            .wallet(ctx.wallet())
            .connect_http(ctx.rpc_url.parse().unwrap());
        let contract = Simple::new(contract.address, &provider);

        SimpleSingleValues {
            s1: contract.s1().call().await.unwrap(),
            s2: contract.s2().call().await.unwrap(),
            s3: contract.s3().call().await.unwrap(),
            s4: contract.s4().call().await.unwrap(),
        }
    }

    async fn update_contract(&self, ctx: &TestContext, contract: &Contract) {
        let provider = ProviderBuilder::new()
            .wallet(ctx.wallet())
            .connect_http(ctx.rpc_url.parse().unwrap());
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
            .wallet(ctx.wallet())
            .connect_http(ctx.rpc_url.parse().unwrap());
        let contract = Simple::new(contract.address, &provider);

        contract.simpleStruct().call().await.unwrap().into()
    }

    async fn update_contract(&self, ctx: &TestContext, contract: &Contract) {
        let provider = ProviderBuilder::new()
            .wallet(ctx.wallet())
            .connect_http(ctx.rpc_url.parse().unwrap());
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

#[derive(Clone, Debug)]
pub enum MappingUpdate<K, V> {
    // key and value
    Insertion(K, V),
    // key and value
    Deletion(K, V),
    // key, previous value and new value
    Update(K, V, V),
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

impl ContractController for Vec<MappingUpdate<MappingKey, Address>> {
    async fn current_values(_ctx: &TestContext, _contract: &Contract) -> Self {
        unimplemented!("Unimplemented for fetching the all mapping values")
    }

    async fn update_contract(&self, ctx: &TestContext, contract: &Contract) {
        let provider = ProviderBuilder::new()
            .wallet(ctx.wallet())
            .connect_http(ctx.rpc_url.parse().unwrap());
        let contract = Simple::new(contract.address, &provider);

        let changes = self
            .iter()
            .map(|tuple| {
                let operation: MappingOperation = tuple.into();
                let (key, value) = match tuple {
                    MappingUpdate::Deletion(k, _) => (*k, *DEFAULT_ADDRESS),
                    MappingUpdate::Update(k, _, v) | MappingUpdate::Insertion(k, v) => (*k, *v),
                };
                MappingChange {
                    operation: operation.into(),
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
                    let v: Address = res.0.into();
                    assert_eq!(v, Address::ZERO, "Key deletion is wrong on contract");
                }
                MappingUpdate::Insertion(k, v) => {
                    let res = contract.m1(*k).call().await.unwrap();
                    let new_value: Address = res.0.into();
                    assert_eq!(&new_value, v, "Key insertion is wrong on contract");
                }
                MappingUpdate::Update(k, _, v) => {
                    let res = contract.m1(*k).call().await.unwrap();
                    let new_value: Address = res.0.into();
                    assert_eq!(&new_value, v, "Key update is wrong on contract");
                }
            }
        }
        log::info!("Updated simple contract single values");
    }
}

impl ContractController for Vec<MappingUpdate<MappingKey, LargeStruct>> {
    async fn current_values(_ctx: &TestContext, _contract: &Contract) -> Self {
        unimplemented!("Unimplemented for fetching the all mapping values")
    }

    async fn update_contract(&self, ctx: &TestContext, contract: &Contract) {
        let provider = ProviderBuilder::new()
            .wallet(ctx.wallet())
            .connect_http(ctx.rpc_url.parse().unwrap());
        let contract = Simple::new(contract.address, &provider);

        let changes = self
            .iter()
            .map(|tuple| {
                let operation: MappingOperation = tuple.into();
                let (key, field1, field2, field3) = match tuple {
                    MappingUpdate::Insertion(k, v)
                    | MappingUpdate::Deletion(k, v)
                    | MappingUpdate::Update(k, _, v) => (*k, v.field1, v.field2, v.field3),
                };
                MappingStructChange {
                    operation: operation.into(),
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

impl ContractController for Vec<MappingUpdate<MappingOfMappingsKey, U256>> {
    async fn current_values(_ctx: &TestContext, _contract: &Contract) -> Self {
        unimplemented!("Unimplemented for fetching the all mapping of mappings")
    }

    async fn update_contract(&self, ctx: &TestContext, contract: &Contract) {
        let provider = ProviderBuilder::new()
            .wallet(ctx.wallet())
            .connect_http(ctx.rpc_url.parse().unwrap());
        let contract = Simple::new(contract.address, &provider);

        let changes = self
            .iter()
            .map(|tuple| {
                let operation: MappingOperation = tuple.into();
                let (k, v) = match tuple {
                    MappingUpdate::Insertion(k, v)
                    | MappingUpdate::Deletion(k, v)
                    | MappingUpdate::Update(k, _, v) => (k, v),
                };

                MappingOfSingleValueMappingsChange {
                    operation: operation.into(),
                    outerKey: k.outer_key,
                    innerKey: k.inner_key,
                    value: *v,
                }
            })
            .collect_vec();

        let call = contract.changeMappingOfSingleValueMappings(changes);
        call.send().await.unwrap().watch().await.unwrap();
        // Sanity check
        for update in self.iter() {
            match update {
                MappingUpdate::Insertion(k, v) => {
                    let res = contract
                        .mappingOfSingleValueMappings(k.outer_key, k.inner_key)
                        .call()
                        .await
                        .unwrap();
                    assert_eq!(&res, v, "Insertion is wrong on contract");
                }
                MappingUpdate::Deletion(k, _) => {
                    let res = contract
                        .mappingOfSingleValueMappings(k.outer_key, k.inner_key)
                        .call()
                        .await
                        .unwrap();
                    assert_eq!(res, U256::ZERO, "Deletion is wrong on contract");
                }
                MappingUpdate::Update(k, _, v) => {
                    let res = contract
                        .mappingOfSingleValueMappings(k.outer_key, k.inner_key)
                        .call()
                        .await
                        .unwrap();
                    assert_eq!(&res, v, "Update is wrong on contract");
                }
            }
        }
        log::info!("Updated simple contract for mapping of single value mappings");
    }
}

impl ContractController for Vec<MappingUpdate<MappingOfMappingsKey, LargeStruct>> {
    async fn current_values(_ctx: &TestContext, _contract: &Contract) -> Self {
        unimplemented!("Unimplemented for fetching the all mapping of mappings")
    }

    async fn update_contract(&self, ctx: &TestContext, contract: &Contract) {
        let provider = ProviderBuilder::new()
            .wallet(ctx.wallet())
            .connect_http(ctx.rpc_url.parse().unwrap());
        let contract = Simple::new(contract.address, &provider);

        let changes = self
            .iter()
            .map(|tuple| {
                let operation: MappingOperation = tuple.into();
                let (k, v) = match tuple {
                    MappingUpdate::Insertion(k, v)
                    | MappingUpdate::Deletion(k, v)
                    | MappingUpdate::Update(k, _, v) => (k, v),
                };

                MappingOfStructMappingsChange {
                    operation: operation.into(),
                    outerKey: k.outer_key,
                    innerKey: k.inner_key,
                    field1: v.field1,
                    field2: v.field2,
                    field3: v.field3,
                }
            })
            .collect_vec();

        let call = contract.changeMappingOfStructMappings(changes);
        call.send().await.unwrap().watch().await.unwrap();
        // Sanity check
        for update in self.iter() {
            match update {
                MappingUpdate::Insertion(k, v) => {
                    let res = contract
                        .mappingOfStructMappings(k.outer_key, k.inner_key)
                        .call()
                        .await
                        .unwrap();
                    let res = LargeStruct::from(res);
                    assert_eq!(&res, v, "Insertion is wrong on contract");
                }
                MappingUpdate::Deletion(k, _) => {
                    let res = contract
                        .mappingOfStructMappings(k.outer_key, k.inner_key)
                        .call()
                        .await
                        .unwrap();
                    let res = LargeStruct::from(res);
                    assert_eq!(res, LargeStruct::default(), "Deletion is wrong on contract");
                }
                MappingUpdate::Update(k, _, v) => {
                    let res = contract
                        .mappingOfStructMappings(k.outer_key, k.inner_key)
                        .call()
                        .await
                        .unwrap();
                    let res = LargeStruct::from(res);
                    assert_eq!(&res, v, "Update is wrong on contract");
                }
            }
        }
        log::info!("Updated simple contract for mapping of LargeStruct mappings");
    }
}
