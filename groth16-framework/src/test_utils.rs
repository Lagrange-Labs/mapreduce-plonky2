//! Utility functions used for testing

use crate::{
    prover::groth16::combine_proofs,
    utils::{hex_to_u256, read_file, write_file},
    EVMVerifier, Groth16Proof, Groth16Prover, Groth16Verifier, C, D, F,
};
use ethers::abi::{Contract, Token};
use mapreduce_plonky2::api::deserialize_proof;
use plonky2::{field::types::PrimeField64, plonk::proof::ProofWithPublicInputs};
use std::path::Path;

/// Convert the plonky2 proof public inputs to bytes and save to a file
/// `plonky2_proof_pis.bin` in the specified dir.
pub fn save_plonky2_proof_pis(dir: &str, proof: &ProofWithPublicInputs<F, C, D>) {
    let file_path = Path::new(dir).join("plonky2_proof_pis.bin");

    let bytes: Vec<_> = proof
        .public_inputs
        .iter()
        .flat_map(|f| f.to_canonical_u64().to_le_bytes())
        .collect();

    write_file(file_path, &bytes).unwrap();
}

/// Test Groth16 proving, verification and Solidity verification.
pub fn test_groth16_proving_and_verification(asset_dir: &str, plonky2_proof: &[u8]) {
    // Generate the Groth16 proof.
    let groth16_proof = groth16_prove(asset_dir, &plonky2_proof);

    // Verify the proof off-chain.
    groth16_verify(asset_dir, &groth16_proof);

    // Verify the proof on-chain.
    evm_verify(asset_dir, &groth16_proof);
}

/// Test to generate the proof.
fn groth16_prove(asset_dir: &str, plonky2_proof: &[u8]) -> Groth16Proof {
    // Initialize the Groth16 prover.
    let prover = Groth16Prover::new(asset_dir).expect("Failed to initialize the prover");

    // Construct the file paths to save the Groth16 and full proofs.
    let groth16_proof_path = Path::new(asset_dir).join("groth16_proof.json");
    let full_proof_path = Path::new(asset_dir).join("full_proof.bin");

    // Generate the Groth16 proof.
    let plonky2_proof = deserialize_proof(plonky2_proof).unwrap();
    let groth16_proof = prover
        .generate_groth16_proof(&plonky2_proof)
        .expect("Failed to generate the proof");
    write_file(
        groth16_proof_path,
        serde_json::to_string(&groth16_proof).unwrap().as_bytes(),
    )
    .unwrap();

    // Generate the full proof.
    let full_proof = combine_proofs(groth16_proof.clone(), plonky2_proof).unwrap();
    write_file(full_proof_path, &full_proof).unwrap();

    groth16_proof
}

/// Test to verify the proof.
fn groth16_verify(asset_dir: &str, proof: &Groth16Proof) {
    let verifier = Groth16Verifier::new(asset_dir).expect("Failed to initialize the verifier");

    verifier.verify(proof).expect("Failed to verify the proof")
}

/// Test the Solidity verification.
fn evm_verify(asset_dir: &str, proof: &Groth16Proof) {
    let solidity_file_path = Path::new(asset_dir)
        .join("verifier.sol")
        .to_string_lossy()
        .to_string();

    let contract = Contract::load(
        read_file(Path::new("test_data").join("verifier.abi"))
            .unwrap()
            .as_slice(),
    )
    .expect("Failed to load the Solidity verifier contract from ABI");

    let [proofs, inputs] = [&proof.proofs, &proof.inputs].map(|ss| {
        ss.iter()
            .map(|s| Token::Uint(hex_to_u256(s).unwrap()))
            .collect()
    });
    let input = vec![Token::FixedArray(proofs), Token::FixedArray(inputs)];
    let verify_fun = &contract.functions["verifyProof"][0];
    let calldata = verify_fun
        .encode_input(&input)
        .expect("Failed to encode the inputs of Solidity contract function verifyProof");

    let verifier =
        EVMVerifier::new(&solidity_file_path).expect("Failed to initialize the EVM verifier");

    let verified = verifier.verify(calldata);
    assert!(verified);
}
