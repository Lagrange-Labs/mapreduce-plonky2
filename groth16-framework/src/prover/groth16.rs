//! The prover used to generate the Groth16 proof.

use crate::{
    utils::{deserialize_circuit_data, read_file, CIRCUIT_DATA_FILENAME},
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

/// Groth16 prover
#[derive(Debug)]
pub struct Groth16Prover {
    /// Wrapped circuit instance
    wrapper: WrappedCircuit<DefaultParameters, Groth16WrapperParameters, D>,
}

impl Groth16Prover {
    pub fn new(asset_dir: &str) -> Result<Self> {
        // Initialize the Go prover.
        gnark_utils::init_prover(asset_dir)?;

        // Read the circuit data from asset dir.
        let circuit_data = load_circuit_data(asset_dir)?;

        // Build the wrapped circuit.
        let wrapper = WrappedCircuit::build_from_raw_circuit(circuit_data);

        Ok(Self { wrapper })
    }

    /// Generate the proof. Return the bytes of serialized JSON Groth16 proof.
    pub fn prove(&self, proof: &[u8]) -> Result<Vec<u8>> {
        // Deserialize the proof.
        let proof = deserialize_proof(proof)?;

        // Generate the wrapped proof.
        let wrapped_output = self.wrapper.prove(&proof)?;

        // Note this verifier data is from the wrapped proof. However the wrapped proof hardcodes the
        // specific mapreduce-plonky2 proof verification key in its circuit, so indirectly, verifier knows the
        // Groth16 proof is for the correct mapreduce-plonky2 proof.
        // This hardcoding is done here https://github.com/Lagrange-Labs/succinctx/blob/main/plonky2x/core/src/backend/wrapper/wrap.rs#L100
        let verifier_data = serde_json::to_string(&wrapped_output.verifier_data)?;
        let proof = serde_json::to_string(&wrapped_output.proof)?;

        // Generate the Groth16 proof.
        let groth16_proof = gnark_utils::prove(&verifier_data, &proof)?;

        Ok(groth16_proof.as_bytes().to_vec())
    }
}

/// Read the circuit data from file `circuit.bin` in the asset dir. This is
/// the circuit data of the final wrapped proof.
fn load_circuit_data(asset_dir: &str) -> Result<CircuitData<F, C, D>> {
    // Read from file.
    let file_path = Path::new(asset_dir).join(CIRCUIT_DATA_FILENAME);
    let bytes = read_file(file_path)?;

    // Deserialize the circuit data.
    deserialize_circuit_data(&bytes)
}
