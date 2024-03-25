//! The prover used to generate the Groth16 proof.

use crate::{proof::Groth16Proof, C, D, F};
use anyhow::Result;
use plonky2::{plonk::circuit_data::CircuitData, plonk::proof::ProofWithPublicInputs};
use plonky2x::backend::{
    circuit::{DefaultParameters, Groth16WrapperParameters},
    wrapper::wrap::WrappedCircuit,
};

/// Groth16 prover configuration
#[derive(Debug)]
pub struct Groth16ProverConfig {
    pub asset_dir: String,
    // Circuit data could be read from the bytes, but only the caller knows
    // gate_serializer and generator_serializer.
    // <https://docs.rs/plonky2/0.1.4/plonky2/plonk/circuit_data/struct.CircuitData.html#method.from_bytes>
    // It should be read from a file when initializing this configuration.
    pub circuit_data: Option<CircuitData<F, C, D>>,
}

/// Groth16 prover
#[derive(Debug)]
pub struct Groth16Prover {
    /// Wrapped circuit instance
    wrapper: WrappedCircuit<DefaultParameters, Groth16WrapperParameters, D>,
}

impl Groth16Prover {
    pub fn new(mut config: Groth16ProverConfig) -> Result<Self> {
        // Initialize the Go prover.
        gnark_utils::init_prover(&config.asset_dir)?;

        // Build the wrapped circuit.
        let circuit_data = config.circuit_data.take().expect("Must have circuit-data");
        let wrapper = WrappedCircuit::build_from_raw_circuit(circuit_data);

        Ok(Self { wrapper })
    }

    /// Generate the proof.
    pub fn prove(&self, proof: &ProofWithPublicInputs<F, C, D>) -> Result<Groth16Proof> {
        // Generate the wrapped proof.
        let wrapped_output = self.wrapper.prove(proof)?;

        let verifier_data = serde_json::to_string(&wrapped_output.verifier_data)?;
        let proof = serde_json::to_string(&wrapped_output.proof)?;

        // Generate the Groth16 proof.
        let groth16_proof = gnark_utils::prove(&verifier_data, &proof)?;

        Ok(serde_json::from_str(&groth16_proof)?)
    }
}
