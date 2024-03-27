//! The prover used to generate the Groth16 proof.

use crate::{
    proof::Groth16Proof,
    utils::{deserialize_circuit_data, read_file, write_file, CIRCUIT_DATA_FILENAME},
    C, D, F,
};
use anyhow::Result;
use plonky2::plonk::{circuit_data::CircuitData, proof::ProofWithPublicInputs};
use plonky2x::backend::{
    circuit::{DefaultParameters, Groth16WrapperParameters},
    wrapper::wrap::WrappedCircuit,
};
use std::path::Path;

/// Groth16 prover configuration
#[derive(Debug)]
pub struct Groth16ProverConfig {
    pub asset_dir: String,
}

/// Groth16 prover
#[derive(Debug)]
pub struct Groth16Prover {
    /// Wrapped circuit instance
    wrapper: WrappedCircuit<DefaultParameters, Groth16WrapperParameters, D>,
}

impl Groth16Prover {
    pub fn new(config: Groth16ProverConfig) -> Result<Self> {
        // Initialize the Go prover.
        gnark_utils::init_prover(&config.asset_dir)?;

        // Read the circuit data from asset dir.
        let circuit_data = load_circuit_data(&config.asset_dir)?;

        // Build the wrapped circuit.
        let wrapper = WrappedCircuit::build_from_raw_circuit(circuit_data);

        Ok(Self { wrapper })
    }

    /// Generate the proof.
    /// This function saves the groth16 proof of JSON format to a file and
    /// creates the missing dirs if the parameter `proof_file_path` is not None.
    pub fn prove(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
        proof_file_path: Option<&str>,
    ) -> Result<Groth16Proof> {
        // Generate the wrapped proof.
        let wrapped_output = self.wrapper.prove(proof)?;

        // Note this verifier data is from the wrapped proof. However the wrapped proof hardcodes the
        // specific mapreduce-plonky2 proof verification key in its circuit, so indirectly, verifier knows the
        // Groth16 proof is for the correct mapreduce-plonky2 proof.
        // This hardcoding is done here https://github.com/Lagrange-Labs/succinctx/blob/main/plonky2x/core/src/backend/wrapper/wrap.rs#L100
        let verifier_data = serde_json::to_string(&wrapped_output.verifier_data)?;
        let proof = serde_json::to_string(&wrapped_output.proof)?;

        // Generate the Groth16 proof.
        let groth16_proof = gnark_utils::prove(&verifier_data, &proof)?;

        // Save the groth16 proof of JSON format to a file if the parameter
        // `proof_file_path` is not None.
        if let Some(proof_file_path) = proof_file_path {
            // It also creates the missing dirs.
            write_file(proof_file_path, groth16_proof.as_bytes())?;
        }

        Ok(serde_json::from_str(&groth16_proof)?)
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
