//! Database creation test cases

// Used to fix the error: failed to evaluate generic const expression `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]

use integration_tests::TestContext;
use mp2_common::eth::left_pad32;
use mp2_test::eth::get_mainnet_url;
use mp2_v1::api::ProofWithVK;
use serial_test::serial;

// Pidgy pinguins contract address for testing
const PIDGY_ADDRESS: &str = "0xbd3531da5cf5857e7cfaa92426877b022e612cf8";

/// Test the database creation for single variables.
#[tokio::test]
#[serial]
async fn test_db_creation_for_single_variables() {
    // Build the test context.
    let rpc_url = get_mainnet_url();
    let ctx = TestContext::new(&rpc_url);

    // Generate the proof of Values Extraction (C.1).
    let _proof = prove_single_values_extraction(&ctx).await;

    // TODO: add further steps of database creation.
}

/// Test the database creation for mapping variables.
#[tokio::test]
#[serial]
async fn test_db_creation_for_mapping_variables() {
    // Build the test context.
    let rpc_url = get_mainnet_url();
    let ctx = TestContext::new(&rpc_url);

    // Generate the proof of Values Extraction (C.1).
    let _proof = prove_mapping_values_extraction(&ctx).await;

    // TODO: add further steps of database creation.
}

/// Generate the Values Extraction (C.1) proof for single variables.
async fn prove_single_values_extraction(ctx: &TestContext) -> ProofWithVK {
    const TEST_SLOT: u8 = 8;

    ctx.prove_single_values_extraction(PIDGY_ADDRESS, TEST_SLOT)
        .await
}

/// Generate the Values Extraction (C.1) proof for mapping variables.
async fn prove_mapping_values_extraction(ctx: &TestContext) -> ProofWithVK {
    // Extract from
    // <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol>.
    // Assume it's using ERC731Enumerable that inherits ERC721.
    const TEST_SLOT: u8 = 2;

    // Frist pinguin holder <https://dune.com/queries/2450476/4027653>
    // holder: 0x188b264aa1456b869c3a92eeed32117ebb835f47
    // NFT ID: <https://opensea.io/assets/ethereum/0xbd3531da5cf5857e7cfaa92426877b022e612cf8/1116>
    const NFT_ID: u32 = 1116;
    let mapping_key = left_pad32(&NFT_ID.to_be_bytes()).to_vec();

    ctx.prove_mapping_values_extraction(PIDGY_ADDRESS, TEST_SLOT, mapping_key)
        .await
}
