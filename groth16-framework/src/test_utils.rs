//! Utility functions used for testing
//! TODO: may move this code and the simple unit test of `lib.rs` to `tests/common`.

use crate::{
    prover::groth16::combine_proofs,
    utils::{hex_to_u256, read_file, write_file},
    EVMVerifier, Groth16Proof, Groth16Prover, Groth16Verifier, C,
};
use alloy::{contract::Interface, dyn_abi::DynSolValue, json_abi::JsonAbi};
use mp2_common::{proof::deserialize_proof, D, F};
use plonky2::plonk::proof::ProofWithPublicInputs;
use std::path::Path;

const R1CS_FILENAME: &str = "r1cs.bin";
const PK_FILENAME: &str = "pk.bin";
const CIRCUIT_FILENAME: &str = "circuit.bin";
pub(crate) const GROTH16_PROOF_FILENAME: &str = "groth16_proof.json";

/// Test Groth16 proving, verification and Solidity verification.
pub fn test_groth16_proving_and_verification(asset_dir: &str, plonky2_proof: &[u8]) {
    // Generate the Groth16 proof.
    let plonky2_proof = deserialize_proof(plonky2_proof).unwrap();
    let groth16_proof = groth16_prove(asset_dir, &plonky2_proof);

    // Save the combined full proof.
    let full_proof_path = Path::new(asset_dir).join("full_proof.bin");
    let full_proof = combine_proofs(groth16_proof.clone(), plonky2_proof).unwrap();
    write_file(full_proof_path, &full_proof).unwrap();

    // Verify the proof off-chain.
    groth16_verify(asset_dir, &groth16_proof);

    // Verify the proof on-chain.
    evm_verify(asset_dir, &groth16_proof);
}

/// Test to generate the proof.
fn groth16_prove(asset_dir: &str, plonky2_proof: &ProofWithPublicInputs<F, C, D>) -> Groth16Proof {
    // Read r1cs, pk and circuit bytes from asset dir.
    let r1cs = read_file(Path::new(asset_dir).join(R1CS_FILENAME)).unwrap();
    let pk = read_file(Path::new(asset_dir).join(PK_FILENAME)).unwrap();
    let circuit = read_file(Path::new(asset_dir).join(CIRCUIT_FILENAME)).unwrap();

    // Initialize the Groth16 prover.
    let prover =
        Groth16Prover::from_bytes(r1cs, pk, circuit).expect("Failed to initialize the prover");

    // Construct the file paths to save the Groth16 and full proofs.
    let groth16_proof_path = Path::new(asset_dir).join(GROTH16_PROOF_FILENAME);

    // Generate the Groth16 proof.
    let groth16_proof = prover
        .generate_groth16_proof(plonky2_proof)
        .expect("Failed to generate the proof");
    write_file(
        groth16_proof_path,
        serde_json::to_string(&groth16_proof).unwrap().as_bytes(),
    )
    .unwrap();

    groth16_proof
}

/// Test to verify the proof.
fn groth16_verify(asset_dir: &str, proof: &Groth16Proof) {
    let verifier = Groth16Verifier::new(asset_dir).expect("Failed to initialize the verifier");

    verifier.verify(proof).expect("Failed to verify the proof")
}

/// Test the Solidity verification.
pub(crate) fn evm_verify(asset_dir: &str, proof: &Groth16Proof) {
    let solidity_file_path = Path::new(asset_dir)
        .join("Verifier.sol")
        .to_string_lossy()
        .to_string();

    // Build the contract interface for encoding the arguments of verification function.
    let abi = JsonAbi::parse([
        "function verifyProof(uint256[8] calldata proof, uint256[2] calldata input)",
    ])
    .unwrap();
    let contract = Interface::new(abi);

    let input = [&proof.proofs, &proof.inputs].map(|s| {
        DynSolValue::FixedArray(
            s.iter()
                .map(|s| DynSolValue::Uint(hex_to_u256(s).unwrap(), 256))
                .collect(),
        )
    });
    let calldata = contract
        .encode_input("verifyProof", &input)
        .expect("Failed to encode the inputs of Solidity contract function verifyProof");

    let verifier =
        EVMVerifier::new(&solidity_file_path).expect("Failed to initialize the EVM verifier");

    let verified = verifier.verify(calldata);
    assert!(verified.is_ok());
}
