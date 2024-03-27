//! Compile the circuit data and generate the asset files

use crate::{
    utils::{
        serialize_circuit_data, write_file, CIRCUIT_DATA_FILENAME, SOLIDITY_VERIFIER_FILENAME,
    },
    C, D, F,
};
use anyhow::Result;
use mapreduce_plonky2::api::deserialize_proof;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2x::backend::{
    circuit::{DefaultParameters, Groth16WrapperParameters},
    wrapper::wrap::WrappedCircuit,
};
use std::path::Path;

/// Compile the circuit data and generate the asset files of `r1cs.bin`,
/// `pk.bin`, `vk.bin` and `verifier.sol`.
/// This function returns the full file path of the Solidity verifier contract.
pub fn compile_and_generate_assets(
    circuit_data: CircuitData<F, C, D>,
    proof: &[u8],
    dst_asset_dir: &str,
) -> Result<String> {
    // Deserialize the proof.
    let proof = deserialize_proof(proof)?;

    // Save the circuit data to file `circuit.bin` in the asset dir. It could be
    // reused in proving.
    save_circuit_data(&circuit_data, dst_asset_dir)?;

    // Create the wrapped circuit.
    let wrapper =
        WrappedCircuit::<DefaultParameters, Groth16WrapperParameters, D>::build_from_raw_circuit(
            circuit_data,
        );

    // Generate the wrapped proof.
    let wrapped_output = wrapper.prove(&proof)?;

    // Serialize the circuit data, verifier data and public inputs to JSON.
    let common_data = serde_json::to_string(&wrapped_output.common_data)?;
    let verifier_data = serde_json::to_string(&wrapped_output.verifier_data)?;
    let proof = serde_json::to_string(&wrapped_output.proof)?;

    // Generate these asset files by gnark-utils.
    gnark_utils::compile_and_generate_assets(&common_data, &verifier_data, &proof, dst_asset_dir)?;

    // Generate the full file path of the Solidity verifier contract.
    let verifier_contract_file_path = Path::new(dst_asset_dir)
        .join(SOLIDITY_VERIFIER_FILENAME)
        .to_string_lossy()
        .to_string();

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
