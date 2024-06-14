//! Database creation test cases

// Used to fix the error: failed to evaluate generic const expression `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]

use common::TestContext;
use log::info;
use mp2_common::eth::left_pad32;
use mp2_test::eth::get_mainnet_url;
use mp2_v1::api::ProofWithVK;
use serial_test::serial;

mod common;

// Pudgy Penguins contract address for testing
const PUDGY_PENGUINS_ADDRESS: &str = "0xbd3531da5cf5857e7cfaa92426877b022e612cf8";

/// Test the database creation for single variables.
#[tokio::test]
#[serial]
async fn test_db_creation_for_single_variables() {
    info!("Start to test Database Creation for single variables");

    // Initialize the test context.
    let rpc_url = get_mainnet_url();
    let ctx = TestContext::new(&rpc_url);
    info!("Initialized the test context");

    // Generate the proof of Values Extraction (C.1).
    let _proof = prove_single_values_extraction(&ctx).await;
    info!("Generated Values Extraction (C.1) proof");

    // TODO: add further steps of database creation.

    info!("Finish testing Database Creation for single variables");
}

/// Test the database creation for mapping variables.
#[tokio::test]
#[serial]
async fn test_db_creation_for_mapping_variables() {
    info!("Start to test Database Creation for mapping variables");

    // Initialize the test context.
    let rpc_url = get_mainnet_url();
    let ctx = TestContext::new(&rpc_url);
    info!("Initialized the test context");

    // Generate the proof of Values Extraction (C.1).
    let _proof = prove_mapping_values_extraction(&ctx).await;
    info!("Generated Values Extraction (C.1) proof");

    // TODO: add further steps of database creation.

    info!("Finish testing Database Creation for single variables");
}

/// Generate the Values Extraction (C.1) proof for single variables.
async fn prove_single_values_extraction(ctx: &TestContext) -> ProofWithVK {
    // Pudgy Penguins simple slots:
    // slot-0: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L23>
    // slot-1: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#L26>
    // slot-8: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/extensions/ERC721Enumerable.sol#L21>
    // slot-10: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol#L21>
    const TEST_SLOTS: [u8; 4] = [0, 1, 8, 10];

    ctx.prove_single_values_extraction(PUDGY_PENGUINS_ADDRESS, &TEST_SLOTS)
        .await
}

/// Test the database creation for length extraction.
#[tokio::test]
#[serial]
async fn test_db_creation_for_leaf_extraction() {
    info!("Start to test Database Creation for length extraction");

    // Initialize the test context.
    let rpc_url = get_mainnet_url();
    let ctx = TestContext::new(&rpc_url);
    info!("Initialized the test context");

    // Generate the proof of Values Extraction (C.2).
    let _proof = prove_length_extraction(&ctx).await;
    info!("Generated Length Extraction (C.2) proof");

    info!("Finish testing Database Creation for length extraction");
}

/// Generate the Values Extraction (C.1) proof for mapping variables.
async fn prove_mapping_values_extraction(ctx: &TestContext) -> ProofWithVK {
    // Extract from
    // <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol>.
    // Assume it's using ERC731Enumerable that inherits ERC721.
    const TEST_SLOT: u8 = 2;

    // Pudgy Penguins holders <https://dune.com/queries/2450476/4027653>
    // 0x188b264aa1456b869c3a92eeed32117ebb835f47: <https://opensea.io/assets/ethereum/0xbd3531da5cf5857e7cfaa92426877b022e612cf8/1116>
    // 0x29469395eaf6f95920e59f858042f0e28d98a20b: <https://opensea.io/assets/ethereum/0xbd3531da5cf5857e7cfaa92426877b022e612cf8/1191>
    // 0x3f22fc93143790a1bd11c37c65a0a0f7e7875ea2: <https://opensea.io/assets/ethereum/0xbd3531da5cf5857e7cfaa92426877b022e612cf8/4291>
    // 0x9020974187aaccc6bd94fb3c952f029215b4fa9f: <https://opensea.io/assets/ethereum/0xbd3531da5cf5857e7cfaa92426877b022e612cf8/6960>
    // 0x4182a46c61c3ee40e61304f8b419f813eeced3b4: <https://opensea.io/assets/ethereum/0xbd3531da5cf5857e7cfaa92426877b022e612cf8/7655>
    // 0xfdd6cc8f6849e82f5e0102057fa74941024d11b6: <https://opensea.io/assets/ethereum/0xbd3531da5cf5857e7cfaa92426877b022e612cf8/8562>
    const NFT_IDS: [u32; 6] = [1116, 1191, 4291, 6960, 7655, 8562];

    let mapping_keys = NFT_IDS
        .iter()
        .map(|id| left_pad32(&id.to_be_bytes()).to_vec())
        .collect();

    ctx.prove_mapping_values_extraction(PUDGY_PENGUINS_ADDRESS, TEST_SLOT, mapping_keys)
        .await
}

/// Generate the Length Extraction (C.2) proof.
async fn prove_length_extraction(ctx: &TestContext) -> ProofWithVK {
    // Pudgy Penguins simple slots:
    // slot-8: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/extensions/ERC721Enumerable.sol#L21>
    const TEST_SLOTS: [u8; 1] = [8];

    ctx.prove_length_extraction(PUDGY_PENGUINS_ADDRESS, &TEST_SLOTS)
        .await
}
