//! Database creation integration test
// Used to fix the error: failed to evaluate generic const expression `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]
use anyhow::Result;

use common::{
    context,
    proof_storage::{KeyValueDB, MemoryProofStorage, ProofKey},
    TestCase, TestContext,
};
use log::info;
use test_log::test;

pub(crate) mod common;

// TODO: move to local_simple logic
//async fn prove_mappings_with_length(
//    ctx: &TestContext,
//    t: &TestCase,
//    contract_proof: &ProofWithVK,
//    block_proof: &[u8],
//    mapping_values_proof: &ProofWithVK,
//) {
//    let length_proof = ctx
//        .prove_length_extraction(
//            &t.contract_address,
//            t.length_extraction.slot,
//            t.length_extraction.value,
//        )
//        .await;
//    info!("Generated Length Extraction (C.2) proof");
//
//    let _ = ctx.prove_final_extraction(
//        contract_proof.serialize().unwrap(),
//        mapping_values_proof.serialize().unwrap(),
//        block_proof.to_vec(),
//        true,
//        Some(length_proof.serialize().unwrap()),
//    );
//    info!("Generated Final Extraction (C.5.1) proof for mapping (with length slot check)");
//}
//
//async fn prove_mappings_without_length(
//    ctx: &TestContext,
//    _t: &TestCase,
//    contract_proof: &ProofWithVK,
//    block_proof: &[u8],
//    mapping_values_proof: &ProofWithVK,
//) {
//    // final extraction for mappings without length slots
//    let _ = ctx.prove_final_extraction(
//        contract_proof.serialize().unwrap(),
//        mapping_values_proof.serialize().unwrap(),
//        block_proof.to_vec(),
//        true,
//        None,
//    );
//    info!("Generated Final Extraction (C.5.1) proof for mapping (without length slot check)");
//}

#[test(tokio::test)]
async fn db_creation_integrated_tests() -> Result<()> {
    // Create the test context for mainnet.
    // let ctx = &mut TestContext::new_mainet();
    let _ = env_logger::try_init();
    // Create the test context for the local node.
    //let storage = MemoryProofStorage::default();
    info!("Loading proof storage");
    let storage = KeyValueDB::new_from_env("test_proofs.store")?;
    info!("Loading Anvil and contract");
    let mut ctx = context::new_local_chain(storage).await;
    info!("Building params");
    // Build the parameters.
    ctx.build_params().unwrap();

    info!("Params built");
    let cases = TestCase::new_local_simple_contract(&ctx).await?;
    info!("Test Cases deployed");
    // Prove for each test case.
    for mut case in cases.into_iter() {
        case.run(&mut ctx).await?;
    }
    ////
    //// Prove mapping slots
    ////
    //let mapping_values_proof = ctx
    //    .prove_mapping_values_extraction(
    //        &t.contract_address,
    //        t.values_extraction_mapping.slot,
    //        t.values_extraction_mapping.mapping_keys.clone(),
    //    )
    //    .await;
    //info!("Generated Values Extraction (C.1) proof for mapping variable");

    //// // Prove mappings slots with length check
    //prove_mappings_with_length(
    //    ctx,
    //    t,
    //    &contract_proof,
    //    &serialize_proof(&block_proof).unwrap(),
    //    &mapping_values_proof,
    //)
    //.await;

    //// // Prove mappings slots without length check
    //prove_mappings_without_length(
    //    ctx,
    //    t,
    //    &contract_proof,
    //    &serialize_proof(&block_proof).unwrap(),
    //    &mapping_values_proof,
    //)
    //.await;
    Ok(())
}
