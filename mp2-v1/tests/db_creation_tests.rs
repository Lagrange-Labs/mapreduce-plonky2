//! Database creation integration test

// Used to fix the error: failed to evaluate generic const expression `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]

use common::{TestCase, TestContext};
use log::info;

mod common;

#[tokio::test]
async fn db_creation_integrated_tests() {
    // Create the test case, for Simple local contract or Pudgy Penguins mainnet contract.
    // let t = TestCase::pudgy_penguins_test_case();
    let t = TestCase::local_simple_test_case();

    // Create the test context.
    let mut ctx = &mut TestContext::new_with_local_node().await;
    ctx.build_params();

    // Run the proving steps.

    let _proof = ctx
        .prove_single_values_extraction(&t.contract_address, &t.values_extraction_single.slots)
        .await;
    info!("Generated Values Extraction (C.1) proof for single variables");

    let _proof = ctx
        .prove_mapping_values_extraction(
            &t.contract_address,
            t.values_extraction_mapping.slot,
            t.values_extraction_mapping.mapping_keys,
        )
        .await;
    info!("Generated Values Extraction (C.1) proof for mapping variables");

    let _proof = ctx
        .prove_length_extraction(
            &t.contract_address,
            t.length_extraction.slot,
            t.length_extraction.value,
        )
        .await;
    info!("Generated Length Extraction (C.2) proof");

    let _proof = ctx
        .prove_contract_extraction(&t.contract_address, t.contract_extraction.slot)
        .await;
    info!("Generated Contract Extraction (C.3) proof");
}
