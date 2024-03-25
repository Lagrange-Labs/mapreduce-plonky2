//! Compile the circuit data and generate the asset files

use crate::{C, D, F};
use anyhow::Result;
use plonky2::{plonk::circuit_data::CircuitData, plonk::proof::ProofWithPublicInputs};
use plonky2x::backend::{
    circuit::{DefaultParameters, Groth16WrapperParameters},
    wrapper::wrap::WrappedCircuit,
};

/// Compile the circuit data and generate the asset files of `r1cs.bin`,
/// `pk.bin`, `vk.bin` and `verifier.sol`.
pub fn compile_and_generate_assets(
    // Circuit data could be read from the bytes, but only the caller knows
    // gate_serializer and generator_serializer.
    // <https://docs.rs/plonky2/0.1.4/plonky2/plonk/circuit_data/struct.CircuitData.html#method.from_bytes>
    // It should be read from a file.
    circuit_data: CircuitData<F, C, D>,
    proof: &ProofWithPublicInputs<F, C, D>,
    dst_asset_dir: &str,
) -> Result<()> {
    // Create the wrapped circuit.
    let wrapper =
        WrappedCircuit::<DefaultParameters, Groth16WrapperParameters, D>::build_from_raw_circuit(
            circuit_data,
        );

    // Generate the wrapped proof.
    let wrapped_output = wrapper.prove(proof)?;

    // Serialize the circuit data, verifier data and public inputs to JSON.
    let common_data = serde_json::to_string(&wrapped_output.common_data)?;
    let verifier_data = serde_json::to_string(&wrapped_output.verifier_data)?;
    let proof = serde_json::to_string(&wrapped_output.proof)?;

    // Generate these asset files by gnark-utils.
    gnark_utils::compile_and_generate_assets(&common_data, &verifier_data, &proof, dst_asset_dir)
}
