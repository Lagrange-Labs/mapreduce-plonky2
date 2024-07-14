//! Database creation integration test
// Used to fix the error: failed to evaluate generic const expression `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]
use std::str::FromStr;

use alloy::{
    eips::BlockNumberOrTag,
    primitives::Address,
    providers::{Provider, ProviderBuilder},
};
use anyhow::Result;
use common::{proof_storage::TableID, TestCase, TestContext};
use log::info;
use mp2_common::{
    eth::BlockUtil,
    proof::{serialize_proof, ProofWithVK},
};
use test_log::test;

pub(crate) mod common;

async fn prove_scalar_values<P: common::proof_storage::ProofStorage>(
    ctx: &TestContext,
    t: &TestCase,
    contract_proof: &ProofWithVK,
    block_proof: &[u8],
    storage: &mut P,
) {
    let contract_address = Address::from_str(&t.contract_address).unwrap();
    let table_id = TableID::new(&contract_address, &t.values_extraction_single.slots);
    let single_values_proof = ctx
        .prove_single_values_extraction(&t.contract_address, &t.values_extraction_single.slots)
        .await;
    info!("Generated Values Extraction (C.1) proof for single variables");

    // final extraction for single variables
    let _ = ctx
        .prove_final_extraction(
            contract_proof.serialize().unwrap(),
            single_values_proof.serialize().unwrap(),
            block_proof.to_vec(),
            false,
            None,
        )
        .await;
    info!("Generated Final Extraction (C.5.1) proof for single variables");

    let row = ctx
        .build_and_prove_celltree(
            &table_id,
            &contract_address,
            // NOTE: the 0th column is assumed to be the secondary index.
            &t.values_extraction_single.slots,
            storage,
        )
        .await;

    // In the case of the scalars slots, there is a single node in the row tree.
    let rows = vec![row];
    let _row_tree_proof = ctx.build_and_prove_rowtree(&table_id, &rows, storage).await;
}

async fn prove_mappings_with_length(
    ctx: &TestContext,
    t: &TestCase,
    contract_proof: &ProofWithVK,
    block_proof: &[u8],
    mapping_values_proof: &ProofWithVK,
) {
    let length_proof = ctx
        .prove_length_extraction(
            &t.contract_address,
            t.length_extraction.slot,
            t.length_extraction.value,
        )
        .await;
    info!("Generated Length Extraction (C.2) proof");

    let _ = ctx.prove_final_extraction(
        contract_proof.serialize().unwrap(),
        mapping_values_proof.serialize().unwrap(),
        block_proof.to_vec(),
        true,
        Some(length_proof.serialize().unwrap()),
    );
    info!("Generated Final Extraction (C.5.1) proof for mapping (with length slot check)");
}

async fn prove_mappings_without_length(
    ctx: &TestContext,
    _t: &TestCase,
    contract_proof: &ProofWithVK,
    block_proof: &[u8],
    mapping_values_proof: &ProofWithVK,
) {
    // final extraction for mappings without length slots
    let _ = ctx.prove_final_extraction(
        contract_proof.serialize().unwrap(),
        mapping_values_proof.serialize().unwrap(),
        block_proof.to_vec(),
        true,
        None,
    );
    info!("Generated Final Extraction (C.5.1) proof for mapping (without length slot check)");
}

#[test(tokio::test)]
async fn db_creation_integrated_tests() {
    // Create the test context for mainnet.
    // let ctx = &mut TestContext::new_mainet();
    let _ = env_logger::try_init();
    // Create the test context for the local node.
    let ctx = &mut TestContext::new_local_node().await;
    info!("Building params");
    // Build the parameters.
    ctx.build_params().unwrap();

    info!("Params built");

    // Prove for each test case.
    for t in &ctx.cases {
        let contract_proof = ctx
            .prove_contract_extraction(&t.contract_address, t.contract_extraction.slot.clone())
            .await;
        info!("Generated Contract Extraction (C.3) proof");

        let block_proof = ctx.prove_block_extraction().await.unwrap();
        info!("Generated Block Extraction (C.4) proof");

        //
        // Prove scalar slots
        //
        let mut scalar_proof_storage = common::proof_storage::MemoryProofStorage::default();
        prove_scalar_values(
            ctx,
            t,
            &contract_proof,
            &serialize_proof(&block_proof).unwrap(),
            &mut scalar_proof_storage,
        )
        .await;
        info!("Generated Single Variables table");

        //
        // Prove mapping slots
        //
        let mapping_values_proof = ctx
            .prove_mapping_values_extraction(
                &t.contract_address,
                t.values_extraction_mapping.slot,
                t.values_extraction_mapping.mapping_keys.clone(),
            )
            .await;
        info!("Generated Values Extraction (C.1) proof for mapping variable");

        // // Prove mappings slots with length check
        prove_mappings_with_length(
            ctx,
            t,
            &contract_proof,
            &serialize_proof(&block_proof).unwrap(),
            &mapping_values_proof,
        )
        .await;

        // // Prove mappings slots without length check
        prove_mappings_without_length(
            ctx,
            t,
            &contract_proof,
            &serialize_proof(&block_proof).unwrap(),
            &mapping_values_proof,
        )
        .await;
    }
}

#[tokio::test]
async fn anvil_block_hash() -> Result<()> {
    // Create the test context for mainnet.
    // let ctx = &mut TestContext::new_mainet();
    let _ = env_logger::try_init();
    // Create the test context for the local node.
    let ctx = &mut TestContext::new_local_node().await;
    let provider = ProviderBuilder::new().on_http(ctx.rpc_url.parse().unwrap());
    let latest = ctx.rpc.get_block_number().await.unwrap();
    let previous_block = provider
        .get_block_by_number(BlockNumberOrTag::Number(latest - 1), true)
        .await
        .unwrap()
        .unwrap();

    let previous_computed_hash = previous_block.block_hash();

    let next_block = provider
        .get_block_by_number(BlockNumberOrTag::Number(latest), true)
        .await
        .unwrap()
        .unwrap();

    // check if the way we compute hash is compatible with the way hash is
    // computed onchain
    let given_next_previous_hash = next_block.header.parent_hash.as_slice();
    // PASS now that we compute everything from alloy
    assert_eq!(&previous_computed_hash, given_next_previous_hash);
    Ok(())
}
