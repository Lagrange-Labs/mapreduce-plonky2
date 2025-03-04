//! Utility functions used for testing

use super::{TestQueryInput, TestQueryOutput};
use alloy::primitives::U256;
use groth16_framework::utils::{read_file, write_file};
use sha2::{Digest, Sha256};
use std::path::Path;

/// The byte offset of the last Groth16 input in the full proof
const LAST_GROTH16_INPUT_OFFSET: usize = 9 * 32;
/// The start byte offset of the public inputs in the full proof
const PI_OFFSET: usize = 10 * 32;

const FULL_PROOF_FILENAME: &str = "full_proof.bin";
const PLONKY2_PROOF_FILENAME: &str = "plonky2_proof.bin";
const QUERY_INPUT_FILENAME: &str = "query_input.json";
const QUERY_OUTPUT_FILENAME: &str = "query_output.json";

/// Check if the sha256 of encoded public inputs equals to the last Groth16 input.
/// This is the Rust version of Solidity function `verifyPlonky2Inputs`.
pub(crate) fn verify_pi_sha256(full_proof: &[u8]) {
    // Convert the last Groth16 input to an Uint256.
    let last_groth16_input: [_; 32] = full_proof
        [LAST_GROTH16_INPUT_OFFSET..LAST_GROTH16_INPUT_OFFSET + 32]
        .try_into()
        .unwrap();
    let last_groth16_input = U256::from_be_bytes(last_groth16_input);

    // Calculate the sha256 of public inputs.
    let pi = &full_proof[PI_OFFSET..];
    let mut hasher = Sha256::new();
    hasher.update(pi);
    let pi_sha256 = hasher.finalize();
    let pi_sha256 = U256::from_be_bytes(pi_sha256.into());
    // Calculate the top `3` bit mask of Uint256.
    let top_three_bit_mask: U256 = U256::from(7) << 253;
    let top_three_bit_mask = !top_three_bit_mask;
    let encoded_pi = pi_sha256 & top_three_bit_mask;

    assert_eq!(encoded_pi, last_groth16_input);
}

/// Read the combined full proof (Groth16 proof + plonky2 proof) from file.
pub(crate) fn read_full_proof(asset_dir: &str) -> Option<Vec<u8>> {
    let path = Path::new(asset_dir).join(FULL_PROOF_FILENAME);
    read_file(path).ok()
}

/// Save the plonky2 proof to file.
pub(crate) fn write_plonky2_proof(asset_dir: &str, proof: &[u8]) {
    let path = Path::new(asset_dir).join(PLONKY2_PROOF_FILENAME);
    write_file(path, proof).unwrap();
}

/// Read the testing query input from file.
pub(crate) fn read_query_input(asset_dir: &str) -> Option<TestQueryInput> {
    let path = Path::new(asset_dir).join(QUERY_INPUT_FILENAME);
    read_file(path)
        .ok()
        .and_then(|data| serde_json::from_slice(&data).ok())
}

/// Save the testing query input to file.
pub(crate) fn write_query_input(asset_dir: &str, input: &TestQueryInput) {
    let data = serde_json::to_vec(input).unwrap();
    let path = Path::new(asset_dir).join(QUERY_INPUT_FILENAME);
    write_file(path, &data).unwrap();
}

/// Read the testing query output from file.
pub(crate) fn read_query_output(asset_dir: &str) -> Option<TestQueryOutput> {
    let path = Path::new(asset_dir).join(QUERY_OUTPUT_FILENAME);
    read_file(path)
        .ok()
        .and_then(|data| serde_json::from_slice(&data).ok())
}

/// Save the testing query output to file.
pub(crate) fn write_query_output(asset_dir: &str, output: &TestQueryOutput) {
    let data = serde_json::to_vec(output).unwrap();
    let path = Path::new(asset_dir).join(QUERY_OUTPUT_FILENAME);
    write_file(path, &data).unwrap();
}
