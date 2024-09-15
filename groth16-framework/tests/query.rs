//! Test the Groth16 proving process for the query circuits.

#![feature(generic_const_exprs)]

mod common;

use alloy::{
    contract::Interface,
    dyn_abi::DynSolValue,
    json_abi::JsonAbi,
    primitives::{B256, U256},
};
use common::{
    utils::{read_full_proof, read_query_input, read_query_output, verify_pi_sha256},
    TestContext,
};
use groth16_framework::{test_utils::test_groth16_proving_and_verification, EVMVerifier};
use itertools::Itertools;
use serial_test::serial;
use std::path::Path;

/// Test proving for the query circuits.
// #[ignore] // Ignore for long running time in CI.
#[serial]
#[test]
fn test_groth16_proving_for_query() {
    env_logger::init();

    const ASSET_DIR: &str = "groth16_query";

    /*
        // Create the testing context.
        let ctx = TestContext::new();

        // Generate the Groth16 asset files.
        ctx.generate_assets(ASSET_DIR);

        // Generate the plonky2 query proof.
        let proof = ctx.generate_query_proof(ASSET_DIR);

        // Test Groth16 proving, verification and Solidity verification.
        test_groth16_proving_and_verification(ASSET_DIR, &proof);
    */
    // Verify the query in the Solidity function.
    // The editing Solidity code is saved in `test_data/TestGroth16Verifier.sol`.
    // TODO: In practice, the separate `Groth16VerifierExtensions.sol` and
    // `verifier.sol` should be used, but the `revm` (Rust EVM) cannot support
    // compilated contract deployment (as inheritance) for now.
    verify_query_in_solidity(ASSET_DIR);
}

/// Verify the query in Solidity function.
fn verify_query_in_solidity(asset_dir: &str) {
    // Read the testing query input and output from files.
    let query_input = read_query_input(asset_dir).unwrap();
    let query_output = read_query_output(asset_dir).unwrap();

    // Build the contract interface for encoding the verification input.
    let abi = JsonAbi::parse(["function processQuery( \
            bytes32[], \
            tuple(uint32, uint32, uint64, uint64, bytes32, bytes32, uint256[]) \
        ) public view returns (tuple(uint256, bytes[]))"])
    .unwrap();
    let contract = Interface::new(abi);

    // Read the combined full proof.
    let mut proof = read_full_proof(asset_dir).unwrap();
    // Verify the sha256 of public inputs.
    verify_pi_sha256(&proof);
    // Extend the proof length to a multiple of `32` for encoding to `bytes32`.
    let proof_len = proof.len();
    let new_proof_len = (proof_len + 31) / 32 * 32;
    proof.resize(new_proof_len, 0);

    // Encode to a `bytes32` array.
    let data = DynSolValue::Array(
        proof
            .chunks(32)
            .map(|b| DynSolValue::FixedBytes(B256::from_slice(b), 32))
            .collect(),
    );

    // Construct the testing query input argument.
    let query_input = DynSolValue::Tuple(vec![
        DynSolValue::Uint(U256::from(query_input.query_limit), 32),
        DynSolValue::Uint(U256::from(query_input.query_offset), 32),
        DynSolValue::Uint(U256::from(query_input.min_block_number), 64),
        DynSolValue::Uint(U256::from(query_input.max_block_number), 64),
        DynSolValue::FixedBytes(query_input.block_hash, 32),
        DynSolValue::FixedBytes(query_input.computational_hash, 32),
        DynSolValue::Array(
            query_input
                .user_placeholders
                .into_iter()
                .map(|u| DynSolValue::Uint(u, 256))
                .collect(),
        ),
    ]);

    // Encode the arguments for contract function call.
    let calldata = contract
        .encode_input("processQuery", &[data, query_input])
        .expect("Failed to encode the inputs of Solidity function processQuery");

    // Initialize the EVM verifier.
    let solidity_file_path = Path::new("test_data")
        .join("TestGroth16Verifier.sol")
        .to_string_lossy()
        .to_string();
    let verifier =
        EVMVerifier::new(&solidity_file_path).expect("Failed to initialize the EVM verifier");

    // Verify in Solidity.
    let output = verifier
        .verify(calldata)
        .expect("Failed to verify in Solidity")
        .1;

    // Parse the output returned from the Solidity function.
    let mut output = contract
        .decode_output("processQuery", &output, true)
        .expect("Failed to decode the Solidity output");
    // Should return one query output struct.
    assert_eq!(output.len(), 1);
    if let DynSolValue::Tuple(mut output) = output.pop().unwrap() {
        assert_eq!(
            output.len(),
            2,
            "Query output must have `total_matched_rows` and `rows`."
        );
        let rows = output.pop().unwrap();
        let total_matched_rows = output.pop().unwrap();

        // Check the total matched rows.
        assert_eq!(
            total_matched_rows,
            DynSolValue::Uint(U256::from(query_output.total_matched_rows), 256),
        );

        // Check the returned rows.
        if let DynSolValue::Array(rows) = rows {
            rows.into_iter()
                .zip_eq(query_output.rows)
                .for_each(|(sol_bytes, u256s)| {
                    let encoded_bytes =
                        DynSolValue::Array(u256s.map(|u| DynSolValue::Uint(u, 256)).to_vec())
                            .abi_encode();

                    assert_eq!(sol_bytes, DynSolValue::Bytes(encoded_bytes));
                });
        } else {
            panic!("Wrong `rows` of query output returned from processQuery function: {output:?}");
        }
    } else {
        panic!("Wrong query output returned from processQuery function: {output:?}");
    }
}
