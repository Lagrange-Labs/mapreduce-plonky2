//! Compile the circuit data and generate the asset files

use crate::{
    utils::{
        serialize_circuit_data, write_file, CIRCUIT_DATA_FILENAME, SOLIDITY_VERIFIER_FILENAME,
    },
    C, D, F,
};
use anyhow::{anyhow, Result};
use plonky2::plonk::{circuit_data::CircuitData, config::GenericHashOut};
use plonky2x::backend::{
    circuit::{DefaultParameters, Groth16WrapperParameters},
    wrapper::wrap::WrappedCircuit,
};
use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

type WrapCircuit = WrappedCircuit<DefaultParameters, Groth16WrapperParameters, D>;

/// Compile the circuit data and generate the asset files of `r1cs.bin`,
/// `pk.bin`, `vk.bin` and `verifier.sol`.
/// This function returns the full file path of the Solidity verifier contract.
pub fn compile_and_generate_assets(
    circuit_data: CircuitData<F, C, D>,
    dst_asset_dir: &str,
) -> Result<String> {
    // Save the circuit data to file `circuit.bin` in the asset dir. It could be
    // reused in proving.
    save_circuit_data(&circuit_data, dst_asset_dir)?;

    // Create the wrapped circuit.
    let wrapper = WrapCircuit::build_from_raw_circuit(circuit_data);

    // Serialize the circuit data, verifier data and public inputs to JSON.
    let common_data = serde_json::to_string(&wrapper.wrapper_circuit.data.common)?;
    let verifier_data = serde_json::to_string(&wrapper.wrapper_circuit.data.verifier_only)?;

    // Generate these asset files by gnark-utils.
    gnark_utils::compile_and_generate_assets(&common_data, &verifier_data, dst_asset_dir)?;

    // Generate the full file path of the Solidity verifier contract.
    let verifier_contract_file_path = Path::new(dst_asset_dir)
        .join(SOLIDITY_VERIFIER_FILENAME)
        .to_string_lossy()
        .to_string();

    // Add a constant of circuit digest to the verifier contract file.
    add_circuit_digest_to_verifier_contract(&verifier_contract_file_path, &wrapper)?;

    Ok(verifier_contract_file_path)
}

/// Save the circuit data to file `circuit.bin` in the asset dir.
fn save_circuit_data(circuit_data: &CircuitData<F, C, D>, dst_asset_dir: &str) -> Result<()> {
    // Serialize the circuit data.
    let data = serialize_circuit_data(circuit_data)?;

    // Write to file.
    let file_path = Path::new(dst_asset_dir).join(CIRCUIT_DATA_FILENAME);
    write_file(file_path, &data)
}

/// Get the wrapped circuit digest.
/// <https://github.com/succinctlabs/succinctx/blob/9df6a9db651507d60ffa2d75eda3fe526d13f90a/plonky2x/core/src/backend/function/mod.rs#L97>
fn wrapped_circuit_digest(wrapper: &WrapCircuit) -> String {
    // to_bytes() returns the representation as LE, but we want to save it on-chain as BE
    // because that is the format of the public input to the gnark plonky2 verifier.
    let mut circuit_digest_bytes = wrapper
        .wrapper_circuit
        .data
        .verifier_only
        .circuit_digest
        .to_bytes();
    circuit_digest_bytes.reverse();

    // The VerifierDigest is stored onchain as a bytes32, so we need to pad it with 0s
    // to store it in the solidity smart contract.
    //
    // Note that we don't need to do any sort of truncation of the most significant bits
    // because the circuit digest already lives in the bn254 field because the prover config
    // uses the Poseidon bn254 hasher.
    //
    // In the solidity smart contract we should not truncate the 3 most significant bits
    // like we do with input_hash and output_hash as the circuit digest has a small
    // probability of being greater than 2^253 given that the field modulus is 254 bits.
    let mut padded = vec![0u8; 32];
    let digest_len = circuit_digest_bytes.len();
    padded[(32 - digest_len)..].copy_from_slice(&circuit_digest_bytes);
    format!("0x{}", hex::encode(padded))
}

/// Add a constant of circuit digest to the verifier contract file.
fn add_circuit_digest_to_verifier_contract(
    contract_file_path: &str,
    wrapper: &WrapCircuit,
) -> Result<()> {
    // Get the wrapped circuit digest.
    let circuit_digest = wrapped_circuit_digest(wrapper);

    let mut fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open(contract_file_path)?;

    // Read the contract file.
    let mut content = String::new();
    fd.read_to_string(&mut content)?;

    // Find the location of last `}`.
    let offset = content
        .rfind('}')
        .ok_or(anyhow!("No '}}' found in the verifier contract file"))?;

    // Write the constant of circuit digest to the file.
    fd.seek(SeekFrom::Start(offset as u64))?;
    fd.write_all(
        format!("\n    bytes32 constant CIRCUIT_DIGEST = {circuit_digest};\n}}").as_bytes(),
    )?;

    Ok(())
}
