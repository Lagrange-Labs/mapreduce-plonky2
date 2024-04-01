//! The prover used to generate the Groth16 proof.

use crate::{
    debug::get_debug_output_dir,
    proof::Groth16Proof,
    utils::{deserialize_circuit_data, hex_to_u256, read_file, write_file, CIRCUIT_DATA_FILENAME},
    C, D, F,
};
use anyhow::Result;
use chrono::Utc;
use mapreduce_plonky2::api::deserialize_proof;
use plonky2::{
    field::types::PrimeField64,
    plonk::{circuit_data::CircuitData, proof::ProofWithPublicInputs},
};
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

    /// Generate the Groth16 proof from the plonky2 proof. It returns the
    /// little-endian bytes as:
    /// `groth16_proof.proofs + groth16_proof.inputs + plonky2_proof.public_inputs`.
    /// In the combined bytes, each part has number as:
    /// - groth16_proof.proofs: 8 * U256 = 256 bytes
    /// - groth16_proof.inputs: 3 * U256 = 96 bytes
    /// - plonky2_proof.public_inputs: the little-endian bytes of public inputs exported by user
    pub fn prove(&self, plonky2_proof: &[u8]) -> Result<Vec<u8>> {
        // Generate the Groth16 proof.
        let groth16_proof = self.prove_impl(plonky2_proof);

        // Check if needs to save the proofs for debugging.
        might_save_proofs(plonky2_proof, &groth16_proof);

        groth16_proof
    }

    pub(crate) fn generate_groth16_proof(
        &self,
        plonky2_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<Groth16Proof> {
        // Generate the wrapped proof.
        let wrapped_output = self.wrapper.prove(plonky2_proof)?;

        // Note this verifier data is from the wrapped proof. However the wrapped proof hardcodes the
        // specific mapreduce-plonky2 proof verification key in its circuit, so indirectly, verifier knows the
        // Groth16 proof is for the correct mapreduce-plonky2 proof.
        // This hardcoding is done here https://github.com/Lagrange-Labs/succinctx/blob/main/plonky2x/core/src/backend/wrapper/wrap.rs#L100
        let verifier_data = serde_json::to_string(&wrapped_output.verifier_data)?;
        let proof = serde_json::to_string(&wrapped_output.proof)?;

        // Generate the Groth16 proof.
        let groth16_proof_str = gnark_utils::prove(&verifier_data, &proof)?;
        let groth16_proof = serde_json::from_str(&groth16_proof_str)?;

        Ok(groth16_proof)
    }

    /// The detailed implementation to generate the Groth16 proof
    fn prove_impl(&self, plonky2_proof: &[u8]) -> Result<Vec<u8>> {
        // Deserialize the plonky2 proof.
        let plonky2_proof = deserialize_proof(plonky2_proof)?;

        // Generate the groth16 proof.
        let groth16_proof = self.generate_groth16_proof(&plonky2_proof)?;

        // Combine the two proofs and return expected bytes.
        combine_proofs(groth16_proof, plonky2_proof)
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

/// Combine the Groth16 proof and the plonky2 proof to little-endian bytes as:
/// `groth16_proof.proofs + groth16_proof.inputs + plonky2_proof.public_inputs`.
/// In the combined bytes, each part has number as:
/// - groth16_proof.proofs: 8 * U256 = 256 bytes
/// - groth16_proof.inputs: 3 * U256 = 96 bytes
/// - plonky2_proof.public_inputs: the little-endian bytes of public inputs exported by user
pub fn combine_proofs(
    groth16_proof: Groth16Proof,
    plonky2_proof: ProofWithPublicInputs<F, C, D>,
) -> Result<Vec<u8>> {
    // Connect the proofs and inputs of the Groth16 proof, and convert to U256s.
    let groth16_u256s = groth16_proof
        .proofs
        .into_iter()
        .chain(groth16_proof.inputs)
        .map(|s| hex_to_u256(&s))
        .collect::<Result<Vec<_>>>()?;

    // Convert the Groth16 U256s to bytes.
    let groth16_bytes = groth16_u256s.iter().flat_map(|u| {
        let mut bytes = [0u8; 32];
        u.to_little_endian(&mut bytes);

        bytes
    });

    // Convert the plonky2 public inputs to bytes.
    let plonky2_pi_bytes = plonky2_proof
        .public_inputs
        .iter()
        .flat_map(|f| f.to_canonical_u64().to_le_bytes());

    // Connect the Groth16 bytes with the plonky2 public inputs bytes.
    let bytes = groth16_bytes.chain(plonky2_pi_bytes).collect();

    Ok(bytes)
}

/// Try to save the plonky2 proof and the Groth16 proof if debugging.
fn might_save_proofs(plonky2_proof: &[u8], groth16_proof: &Result<Vec<u8>>) {
    if let Some(output_dir) = get_debug_output_dir(groth16_proof) {
        let filename = Utc::now().format("%Y-%m-%d_%H-%M-%S");

        // Save the plonky2 proof.
        let path = Path::new(&output_dir).join(format!("{filename}_plonky2.proof"));
        if let Err(err) = write_file(&path, plonky2_proof) {
            log::error!("Failed to save the plonky2 proof to `{path:?}`: {err}");
        }

        if let Ok(groth16_proof) = groth16_proof {
            // Save the Groth16 proof.
            let path = Path::new(&output_dir).join(format!("{filename}_groth16.proof"));
            if let Err(err) = write_file(&path, groth16_proof) {
                log::error!("Failed to save the Groth16 proof to '{path:?}': {err}");
            }
        }
    }
}
