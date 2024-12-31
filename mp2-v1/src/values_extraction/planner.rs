//! This code returns an [`UpdateTree`] used to plan how we prove a series of values was extracted from a Merkle Patricia Trie.
use alloy::{
    network::Ethereum,
    primitives::{keccak256, Address, B256},
    providers::RootProvider,
    transports::Transport,
};
use anyhow::Result;
use mp2_common::eth::{EventLogInfo, ReceiptQuery};
use ryhope::storage::updatetree::UpdateTree;
use std::future::Future;

/// Trait that is implemented for all data that we can provably extract.
pub trait Extractable {
    fn create_update_tree<T: Transport + Clone>(
        &self,
        contract: Address,
        epoch: u64,
        provider: &RootProvider<T, Ethereum>,
    ) -> impl Future<Output = Result<UpdateTree<B256>>>;
}

impl<const NO_TOPICS: usize, const MAX_DATA: usize> Extractable
    for EventLogInfo<NO_TOPICS, MAX_DATA>
{
    async fn create_update_tree<T: Transport + Clone>(
        &self,
        contract: Address,
        epoch: u64,
        provider: &RootProvider<T, Ethereum>,
    ) -> Result<UpdateTree<B256>> {
        let query = ReceiptQuery::<NO_TOPICS, MAX_DATA> {
            contract,
            event: *self,
        };

        let proofs = query.query_receipt_proofs(provider, epoch.into()).await?;

        // Convert the paths into their keys using keccak
        let key_paths = proofs
            .iter()
            .map(|input| input.mpt_proof.iter().map(keccak256).collect::<Vec<B256>>())
            .collect::<Vec<Vec<B256>>>();

        // Now we make the UpdateTree
        Ok(UpdateTree::<B256>::from_paths(key_paths, epoch as i64))
    }
}

#[cfg(test)]
pub mod tests {

    use alloy::{eips::BlockNumberOrTag, primitives::Address, providers::ProviderBuilder, sol};
    use anyhow::anyhow;
    use mp2_common::eth::BlockUtil;
    use mp2_test::eth::get_mainnet_url;
    use std::str::FromStr;

    use super::*;

    #[tokio::test]
    async fn test_receipt_update_tree() -> Result<()> {
        // First get the info we will feed in to our function
        let event_info = test_receipt_trie_helper().await?;

        let contract = Address::from_str("0xbd3531da5cf5857e7cfaa92426877b022e612cf8")?;
        let epoch: u64 = 21362445;

        let url = get_mainnet_url();
        // get some tx and receipt
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());

        let update_tree = event_info
            .create_update_tree(contract, epoch, &provider)
            .await?;

        let block_util = build_test_data().await;

        assert_eq!(*update_tree.root(), block_util.block.header.receipts_root);
        Ok(())
    }

    /// Function that fetches a block together with its transaction trie and receipt trie for testing purposes.
    async fn build_test_data() -> BlockUtil {
        let url = get_mainnet_url();
        // get some tx and receipt
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());

        // We fetch a specific block which we know includes transactions relating to the PudgyPenguins contract.
        BlockUtil::fetch(&provider, BlockNumberOrTag::Number(21362445))
            .await
            .unwrap()
    }

    /// Function to build a list of [`ReceiptProofInfo`] for a set block.
    async fn test_receipt_trie_helper() -> Result<EventLogInfo<2, 1>> {
        // First we choose the contract and event we are going to monitor.
        // We use the mainnet PudgyPenguins contract at address 0xbd3531da5cf5857e7cfaa92426877b022e612cf8
        // and monitor for the `Approval` event.
        let address = Address::from_str("0xbd3531da5cf5857e7cfaa92426877b022e612cf8")?;

        // We have to create what the event abi looks like
        sol! {
            #[allow(missing_docs)]
            #[sol(rpc, abi)]
            contract EventTest {
            #[derive(Debug)]
            event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

            }
        };

        let approval_event = EventTest::abi::events()
            .get("ApprovalForAll")
            .ok_or(anyhow!("No ApprovalForAll event exists"))?[0]
            .clone();

        Ok(EventLogInfo::<2, 1>::new(
            address,
            &approval_event.signature(),
        ))
    }
}
