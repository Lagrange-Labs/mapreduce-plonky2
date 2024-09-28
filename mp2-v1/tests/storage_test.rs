mod bindings;
use crate::bindings::simple::Simple;
use alloy::{
    network::EthereumWallet,
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder, RootProvider},
    rpc::types::EIP1186AccountProofResponse,
    signers::local::PrivateKeySigner,
    transports::{
        http::{Client, Http},
        Transport,
    },
};
use anyhow::Result;
use mp2_common::eth::{left_pad32, ProofQuery, StorageSlot, StructSlot};

struct LocalChain {
    pub(crate) local_node: AnvilInstance,
    pub(crate) rpc_url: String,
}

impl LocalChain {
    pub(crate) fn new() -> Self {
        let anvil = Anvil::new().spawn();
        let rpc_url = anvil.endpoint();
        Self {
            local_node: anvil,
            rpc_url,
        }
    }
    pub(crate) fn wallet(&self) -> EthereumWallet {
        let signer: PrivateKeySigner = self.local_node.keys()[0].clone().into();
        EthereumWallet::from(signer)
    }
    pub(crate) async fn run_query_proof(
        &self,
        address: Address,
        slot: StorageSlot,
    ) -> Result<EIP1186AccountProofResponse> {
        let query = ProofQuery::new(address, slot);
        let provider = ProviderBuilder::new().on_http(self.rpc_url.parse().unwrap());
        query
            .query_mpt_proof(&provider, alloy::eips::BlockNumberOrTag::Latest)
            .await
    }
}

const STRUCT_SIMPLE_SLOT: usize = 6;

/// This test shows that fields in struct are encoded using RLP as MPT leafs and are packed from
/// right to left
#[tokio::test]
async fn test_storage_word_struct() -> Result<()> {
    println!("Hello Struct");
    let local_chain = LocalChain::new();
    // TODO: how to make that into a func ?
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(local_chain.wallet())
        .on_http(local_chain.rpc_url.parse().unwrap());

    let contract = Simple::deploy(&provider).await.unwrap();
    let (field1, field2, field3) = (U256::from(112233), 11223344, 44332211);
    contract
        .setLargeStruct(field1, field2, field3)
        .send()
        .await
        .unwrap()
        .watch()
        .await
        .unwrap();
    let struct_slot = StorageSlot::Struct(StructSlot {
        inner: Box::new(StorageSlot::Simple(6)),
        evm_word_idx: 0,
    });
    // test if the value is correct
    let found = local_chain
        .run_query_proof(*contract.address(), struct_slot)
        .await?
        .storage_proof[0]
        .value;
    let expected = contract.myStruct().call().await?.field1;
    assert_eq!(found, expected);
    // test for second field and third, they should be given together
    let struct_slot = StorageSlot::Struct(StructSlot {
        inner: Box::new(StorageSlot::Simple(6)),
        evm_word_idx: 1,
    });
    let found = local_chain
        .run_query_proof(*contract.address(), struct_slot)
        .await?
        .storage_proof[0]
        .proof
        .last()
        .clone()
        .unwrap()
        .to_vec();
    println!("found : {:?}", found);
    let list: Vec<Vec<u8>> = rlp::decode_list(&found);
    let integer_part: Vec<u8> = rlp::decode(&list[1])?;
    // not all fields are padded, the "last" one is not to save space i guess so we should always
    // pad in circuit
    let integer_part = left_pad32(&integer_part).to_vec();
    assert_eq!(integer_part.len(), 32);
    let field2_size = 128 / 8;
    let ff2_slice = take_right_to_left(integer_part.clone(), 0, field2_size);
    let ff2 = U256::from_be_slice(&ff2_slice);
    let expected = U256::from(contract.myStruct().call().await?.field2);
    assert_eq!(ff2, expected,);

    let field3_size = field2_size;
    let ff3_slice = take_right_to_left(integer_part, field2_size, field2_size + field3_size);
    let ff3 = U256::from_be_slice(&ff3_slice);
    let expected = U256::from(contract.myStruct().call().await?.field3);
    assert_eq!(
        ff3,
        expected,
        "ff3 extracted {:?} - field 3 expected {:?}",
        ff3.to_be_bytes_vec(),
        expected.to_be_bytes_vec()
    );

    Ok(())
}

fn take_right_to_left(mut buff: Vec<u8>, min: usize, max: usize) -> Vec<u8> {
    buff.reverse();
    let mut slice = buff.into_iter().skip(min).take(max).collect::<Vec<_>>();
    slice.reverse();
    slice
}
