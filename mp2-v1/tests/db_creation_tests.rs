//! Database creation integration test
// Used to fix the error: failed to evaluate generic const expression `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]
#![feature(assert_matches)]
use std::future::Future;

use anyhow::Result;

use common::{
    cases::local_simple::{ChangeType, UpdateType},
    context,
    proof_storage::{KeyValueDB, MemoryProofStorage, ProofKey},
    TestCase, TestContext,
};
use log::info;
use test_log::test;

pub(crate) mod common;

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
    info!("Initial Anvil block: {}", ctx.block_number().await);
    info!("Building params");
    // Build the parameters.
    ctx.build_params().unwrap();

    info!("Params built");
    //let mut single = TestCase::single_value_test_case(&ctx).await?;
    //let changes = vec![
    //    ChangeType::Update(UpdateType::Rest),
    //    ChangeType::Update(UpdateType::SecondaryIndex),
    //];
    //single.run(&mut ctx, changes.clone()).await?;
    let mut mapping = TestCase::mapping_test_case(&ctx).await?;
    let changes = vec![
        ChangeType::Insertion,
        //ChangeType::Update(UpdateType::Rest),
        //ChangeType::Update(UpdateType::SecondaryIndex),
    ];
    mapping.run(&mut ctx, changes).await?;
    Ok(())
}
