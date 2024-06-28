//! Database creation integration test

// Used to fix the error: failed to evaluate generic const expression `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]

use common::{TestCase, TestContext};
use log::info;
use mp2_common::proof::serialize_proof;

mod common;

#[tokio::test]
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
        let single_values_proof = ctx
            .prove_single_values_extraction(&t.contract_address, &t.values_extraction_single.slots)
            .await;
        info!("Generated Values Extraction (C.1) proof for single variables");

        let mapping_values_proof = ctx
            .prove_mapping_values_extraction(
                &t.contract_address,
                t.values_extraction_mapping.slot,
                t.values_extraction_mapping.mapping_keys.clone(),
            )
            .await;
        info!("Generated Values Extraction (C.1) proof for mapping variable");

        let length_proof = ctx
            .prove_length_extraction(
                &t.contract_address,
                t.length_extraction.slot,
                t.length_extraction.value,
            )
            .await;
        info!("Generated Length Extraction (C.2) proof");

        let contract_proof = ctx
            .prove_contract_extraction(&t.contract_address, t.contract_extraction.slot.clone())
            .await;
        info!("Generated Contract Extraction (C.3) proof");

        let block_proof = ctx.prove_block_extraction().await.unwrap();
        info!("Generated Block Extraction (C.4) proof");

        // final extraction for single variables
        let _ = ctx.prove_final_extraction(
            contract_proof.serialize().unwrap(),
            single_values_proof.serialize().unwrap(),
            serialize_proof(&block_proof).unwrap(),
            false,
            None,
        );
        info!("Generated Final Extraction (C.5.1) proof for single variables");

        // final extraction for mappings without length slots
        let _ = ctx.prove_final_extraction(
            contract_proof.serialize().unwrap(),
            mapping_values_proof.serialize().unwrap(),
            serialize_proof(&block_proof).unwrap(),
            true,
            None,
        );
        info!("Generated Final Extraction (C.5.1) proof for mapping (without length slot check)");

        let _ = ctx.prove_final_extraction(
            contract_proof.serialize().unwrap(),
            mapping_values_proof.serialize().unwrap(),
            serialize_proof(&block_proof).unwrap(),
            true,
            Some(length_proof.serialize().unwrap()),
        );

        info!("Generated Final Extraction (C.5.1) proof for mapping (with length slot check)");
    }
}
