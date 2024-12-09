//! This code returns an [`UpdateTree`] used to plan how we prove a series of values was extracted from a Merkle Patricia Trie.

use super::ports::input::Extractable;
use alloy::{
    consensus::Header,
    primitives::{keccak256, B256},
};
use anyhow::{anyhow, Result};
use mp2_common::eth::Rlpable;
use ryhope::storage::updatetree::UpdateTree;
use std::iter;

/// Given a list MPT proofs, a block [`Header`] and an epoch, this function produces an [`UpdateTree`]
/// for proving correct value extraction. The leaves of the tree represent proofs that have no dependencies.
pub fn produce_update_tree<E: Extractable>(
    data: &[E],
    block_header: &Header,
    epoch: i64,
) -> Result<UpdateTree<B256>> {
    // First check that paths is not empty, even if there are no relevant paths we still prove emptiness of the Block.
    if data.is_empty() {
        return Err(anyhow!("No paths were provided, there is nothing to prove"));
    }

    // Now we make a node for the block proof
    let block_hash: [u8; 32] = block_header
        .block_hash()
        .try_into()
        .map_err(|_| anyhow!("Could not convert block hash to fixed length array"))?;
    let block_proof_key = B256::from_slice(&block_hash);

    // All of the paths should be from root to leaf, so we append the hash of the trie root and the block as the first element, this corresponds to the final extraction proof
    // we also make a two element path consisting of this final key and the block hash.
    let final_key = keccak256([keccak256(&data[0].to_path()[0]).0, block_hash].concat());

    // Convert the paths into their keys using keccak
    let key_paths = data
        .iter()
        .map(|input| {
            iter::once(final_key)
                .chain(input.to_path().iter().map(keccak256))
                .collect::<Vec<B256>>()
        })
        .chain(vec![vec![final_key, block_proof_key]])
        .collect::<Vec<Vec<B256>>>();

    // Now we make the UpdateTree
    Ok(UpdateTree::<B256>::from_paths(key_paths, epoch))
}

#[cfg(test)]
pub mod tests {

    use std::str::FromStr;

    use alloy::{eips::BlockNumberOrTag, primitives::Address, providers::ProviderBuilder, sol};
    use mp2_common::eth::{BlockUtil, ReceiptProofInfo, ReceiptQuery};
    use mp2_test::eth::get_mainnet_url;

    use super::*;

    #[tokio::test]
    async fn test_receipt_update_tree() -> Result<()> {
        // First get the info we will feed in to our function
        let receipt_proofs = test_receipt_trie_helper().await?;

        let block_info = build_test_data().await;

        let header = block_info.block.header.inner.clone();
        let epoch: i64 = 21362445;

        let update_tree = produce_update_tree(&receipt_proofs, &header, epoch)?;

        // The root of the update tree should be the ahsh of the block hash and the root of the receipt trie.
        let block_hash: [u8; 32] = header
            .block_hash()
            .try_into()
            .map_err(|_| anyhow!("Could not convert block hash to fixed length array"))?;
        let block_proof_key = B256::from_slice(&block_hash);

        // All of the paths should be from root to leaf, so we append the hash of the trie root and the block as the first element, this corresponds to the final extraction proof
        // we also make a two element path consisting of this final key and the block hash.
        let final_key = keccak256([header.receipts_root.0, block_hash].concat());

        assert_eq!(*update_tree.root(), final_key);

        // We check that the immediate children of the root are correct.
        update_tree
            .node(0)
            .children()
            .iter()
            .for_each(|&child_index| {
                let node = update_tree.node(child_index);

                let is_block_hash = *node.key() == block_proof_key;
                let is_receipt_hash = *node.key() == header.receipts_root;

                // perform an or on the above two
                assert!(is_block_hash || is_receipt_hash);
            });

        // We iterate up the paths from leaf to root to check that each node has the correct parent.
        // First we return an iterator over all the nodes
        let mut all_nodes = update_tree.descendants(0);
        receipt_proofs
            .iter()
            .map(Extractable::to_path)
            .try_for_each(|path| {
                // Find the intial state we need for the scan
                let leaf_key = keccak256(path.last().ok_or(anyhow!("Path was empty!"))?);
                let leaf_node_index = all_nodes
                    .find(|index| *update_tree.node(*index).key() == leaf_key)
                    .ok_or(anyhow!("Leaf key did not exist in tree"))?;
                // Since in the `produce_update_tree` function we append a node to each of these paths at the start if all the nodes are included the following shoult return `0usize`.
                let final_parent = path
                    .iter()
                    .rev()
                    .try_fold(leaf_node_index, |state, node| {
                        let tree_node = update_tree.node(state);
                        if *tree_node.key() == keccak256(node) {
                            tree_node.parent()
                        } else {
                            None
                        }
                    })
                    .ok_or(anyhow!("final parent was a None value"))?;

                assert_eq!(final_parent, 0usize);
                Ok(())
            })
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
    async fn test_receipt_trie_helper() -> Result<Vec<ReceiptProofInfo>> {
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

        let query = ReceiptQuery::new(address, approval_event);

        // Spin up a RootProvider
        let url = get_mainnet_url();

        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());

        // fetch the list of proofs
        query
            .query_receipt_proofs(&provider, BlockNumberOrTag::Number(21362445))
            .await
    }
}
