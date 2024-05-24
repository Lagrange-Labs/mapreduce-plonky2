//! The prover used to generate the Groth16 proof.

use crate::{
    proof::Groth16Proof,
    utils::{deserialize_circuit_data, hex_to_u256, read_file, CIRCUIT_DATA_FILENAME},
    C, D, F,
};
use anyhow::Result;
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

    /// Initialize the Groth16 prover from bytes.
    pub fn from_bytes(r1cs: Vec<u8>, pk: Vec<u8>, circuit: Vec<u8>) -> Result<Self> {
        // Deserialize the circuit data.
        let circuit_data = deserialize_circuit_data(&circuit)?;

        // Manual drop the Vec of big memory before calling the Go function in
        // gnark-utils.
        drop(circuit);

        // Initialize the Go prover from bytes.
        gnark_utils::init_prover_from_bytes(r1cs, pk)?;

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
        // Deserialize the plonky2 proof.
        let plonky2_proof = deserialize_proof(plonky2_proof)?;

        // Generate the groth16 proof.
        let groth16_proof = self.generate_groth16_proof(&plonky2_proof)?;

        // Combine the two proofs and return expected bytes.
        combine_proofs(groth16_proof, plonky2_proof)
    }

    pub(crate) fn generate_groth16_proof(
        &self,
        plonky2_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<Groth16Proof> {
        // Generate the wrapped proof.
        let now = std::time::Instant::now();
        let wrapped_output = self.wrapper.prove(plonky2_proof)?;
        println!(
            "succinctx wrapping proving time elapsed {}",
            now.elapsed().in_millis()
        );

        // Note this verifier data is from the wrapped proof. However the wrapped proof hardcodes the
        // specific mapreduce-plonky2 proof verification key in its circuit, so indirectly, verifier knows the
        // Groth16 proof is for the correct mapreduce-plonky2 proof.
        // This hardcoding is done here https://github.com/Lagrange-Labs/succinctx/blob/main/plonky2x/core/src/backend/wrapper/wrap.rs#L100
        let verifier_data = serde_json::to_string(&wrapped_output.verifier_data)?;
        let proof = serde_json::to_string(&wrapped_output.proof)?;

        // Generate the Groth16 proof.
        let now = std::time::Instant::now();
        let groth16_proof_str = gnark_utils::prove(&verifier_data, &proof)?;
        println!("groth16 proving time elapsed {}", now.elapsed().in_millis());

        let groth16_proof = serde_json::from_str(&groth16_proof_str)?;

        Ok(groth16_proof)
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
