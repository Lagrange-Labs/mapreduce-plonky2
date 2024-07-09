//! Database creation integration test
// Used to fix the error: failed to evaluate generic const expression `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]
use common::{ProofKey, TestCase, TestContext};
use ethers::types::Address;
use log::info;
use mp2_common::proof::{serialize_proof, ProofWithVK};
use std::{collections::HashMap, str::FromStr};
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

    let single_values_proof = ctx
        .prove_single_values_extraction(&t.contract_address, &t.values_extraction_single.slots)
        .await;
    info!("Generated Values Extraction (C.1) proof for single variables");

    // final extraction for single variables
    let _ = ctx.prove_final_extraction(
        contract_proof.serialize().unwrap(),
        single_values_proof.serialize().unwrap(),
        block_proof.to_vec(),
        false,
        None,
    );
    info!("Generated Final Extraction (C.5.1) proof for single variables");

    let row = ctx
        .build_and_prove_celltree(
            &contract_address,
            // NOTE: the 0th column is assumed to be the secondary index.
            &t.values_extraction_single.slots,
            storage,
        )
        .await;

    // In the case of the scalars slots, there is a single node in the row tree.
    let rows = vec![row];
    let _row_tree_proof = ctx.build_and_prove_rowtree(&rows, storage).await;
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
        let mut scalar_proof_storage =
            common::proof_storage::MemoryProofStorage::namespaced_from(format!(
                "{:?} - {:?}- {:?}",
                ctx.block_number, t.contract_address, t.values_extraction_single,
            ));
        prove_scalar_values(
            ctx,
            t,
            &contract_proof,
            &serialize_proof(&block_proof).unwrap(),
            &mut scalar_proof_storage,
        )
        .await;

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
