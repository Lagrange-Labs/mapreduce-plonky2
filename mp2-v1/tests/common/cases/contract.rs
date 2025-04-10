use alloy::{primitives::Address, providers::ProviderBuilder};
use anyhow::Result;
use log::info;

use crate::common::{bindings::simple::Simple, TestContext};

use super::indexing::{SimpleSingleValue, UpdateSimpleStorage};

pub struct Contract {
    pub address: Address,
    pub chain_id: u64,
}

impl Contract {
    pub async fn current_single_values(&self, ctx: &TestContext) -> Result<SimpleSingleValue> {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());

        let contract = Simple::new(self.address, &provider);

        Ok(SimpleSingleValue {
            s1: contract.s1().call().await.unwrap()._0,
            s2: contract.s2().call().await.unwrap()._0,
            s3: contract.s3().call().await.unwrap()._0,
            s4: contract.s4().call().await.unwrap()._0,
        })
    }
    // Returns the table updated
    pub async fn apply_update(
        &self,
        ctx: &TestContext,
        update: &UpdateSimpleStorage,
    ) -> Result<()> {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());

        let contract = Simple::new(self.address, &provider);
        update.apply_to(&contract).await;
        info!("Updated contract with new values {:?}", update);
        Ok(())
    }
}
