//! Database creation tests

// Used to fix the error: failed to evaluate generic const expression `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]

use ethers::prelude::Address;
use integration_tests::{
    utils::load_or_generate_public_params, values_extraction::TestStorageTrie,
};
use mp2_common::eth::StorageSlot;
use mp2_test::utils::random_vector;
use mp2_v1::api::{ProofWithVK, PublicParameters};
use std::str::FromStr;

/// Cached filename of the public parameters
const PUBLIC_PARAMS_FILE: &str = "mp2.params";

const TEST_SLOT: usize = 10;
const TEST_CONTRACT_ADDRESS: &str = "0x00000000000000000000000000000000000000fe";

/// Test the database creation for single variables.
#[test]
fn test_db_creation_for_single_variables() {
    // Load the public parameters from a file, or generate a new one.
    let params = load_or_generate_public_params(PUBLIC_PARAMS_FILE).unwrap();

    // Generate the values extraction proof (C.1) for single variables.
    let _proof = prove_single_values_extraction(&params);

    // TODO: add further steps of database creation.
}

/// Test the database creation for mapping variables.
#[test]
fn test_db_creation_for_mapping_variables() {
    // Load the public parameters from a file, or generate a new one.
    let params = load_or_generate_public_params(PUBLIC_PARAMS_FILE).unwrap();

    // Generate the values extraction proof (C.1) for mapping variables.
    let _proof = prove_mapping_values_extraction(&params);

    // TODO: add further steps of database creation.
}

/// Generate the Values Extraction (C.1) proof for single variables.
fn prove_single_values_extraction(params: &PublicParameters) -> ProofWithVK {
    // Create a test contract address.
    let contract_address = Address::from_str(TEST_CONTRACT_ADDRESS).unwrap();

    // Create the test simple slots.
    let slots: Vec<_> = (TEST_SLOT..TEST_SLOT + 6)
        .map(StorageSlot::Simple)
        .collect();

    // Generate the test trie.
    let mut trie = TestStorageTrie::new(contract_address, slots);

    // Generate the proof.
    trie.prove_all(params)
}

/// Generate the Values Extraction (C.1) proof for single variables.
fn prove_mapping_values_extraction(params: &PublicParameters) -> ProofWithVK {
    // Create a test contract address.
    let contract_address = Address::from_str(TEST_CONTRACT_ADDRESS).unwrap();

    // Create the test mapping slots.
    let slots = [TEST_SLOT; 4]
        .map(|slot| {
            // Must be the same slot value for mapping variables.
            StorageSlot::Mapping(random_vector(4), slot)
        })
        .to_vec();

    // Generate the test trie.
    let mut trie = TestStorageTrie::new(contract_address, slots);

    // Generate the proof.
    trie.prove_all(params)
}
