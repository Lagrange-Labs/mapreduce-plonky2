//! Initialize the prover and generate proofs.

use crate::go;
use anyhow::{bail, Result};
use std::ffi::{CStr, CString};

/// Initialize the prover.
pub fn init_prover(asset_dir: &str) -> Result<()> {
    let asset_dir = CString::new(asset_dir)?;

    let result = unsafe { go::InitProver(asset_dir.as_ptr()) };

    if result.is_null() {
        return Ok(());
    }

    let c_result = unsafe { CStr::from_ptr(result) };
    let error = c_result.to_str()?.to_string();

    unsafe { go::FreeString(c_result.as_ptr()) };

    bail!(error);
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

    if result.1.is_null() {
        let c_proof = unsafe { CStr::from_ptr(result.0) };
        let proof = c_proof.to_str()?.to_string();

        unsafe { go::FreeString(c_proof.as_ptr()) };

        return Ok(proof);
    }

    let c_error = unsafe { CStr::from_ptr(result.1) };
    let error = c_error.to_str()?.to_string();

    unsafe { go::FreeString(c_error.as_ptr()) };

    bail!(error);
}
