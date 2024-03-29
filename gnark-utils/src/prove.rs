//! Initialize the prover and generate the proofs.

use crate::{go, utils::handle_c_result};
use anyhow::{bail, Result};
use std::ffi::{CStr, CString};

/// Initialize the prover.
pub fn init_prover(asset_dir: &str) -> Result<()> {
    let asset_dir = CString::new(asset_dir)?;

    let result = unsafe { go::InitProver(asset_dir.as_ptr()) };

    handle_c_result(result)
}

/// Generate the proof.
pub fn prove(verifier_only_circuit_data: &str, proof_with_public_inputs: &str) -> Result<String> {
    let [verifier_only_circuit_data, proof_with_public_inputs] =
        [verifier_only_circuit_data, proof_with_public_inputs].map(CString::new);

    let result = unsafe {
        go::Prove(
            verifier_only_circuit_data?.as_ptr(),
            proof_with_public_inputs?.as_ptr(),
        )
    };

    if result.is_null() {
        bail!("Failed to generate the proof");
    }

    let c_proof = unsafe { CStr::from_ptr(result) };
    let proof = c_proof.to_str()?.to_string();

    unsafe { go::FreeString(c_proof.as_ptr()) };

    Ok(proof)
}
