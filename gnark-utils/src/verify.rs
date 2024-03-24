//! Initialize the verifier and verify proofs.

use crate::go;
use anyhow::{bail, Result};
use std::ffi::{CStr, CString};

/// Initialize the verifier.
pub fn init_verifier(asset_dir: &str) -> Result<()> {
    let asset_dir = CString::new(asset_dir)?;

    let result = unsafe { go::InitVerifier(asset_dir.as_ptr()) };

    if result.is_null() {
        return Ok(());
    }

    let c_result = unsafe { CStr::from_ptr(result) };
    let error = c_result.to_str()?.to_string();

    unsafe { go::FreeString(c_result.as_ptr()) };

    bail!(error);
}

/// Verify the proof.
pub fn verify(proof: &str) -> Result<()> {
    let proof = CString::new(proof)?;

    let result = unsafe { go::Verify(proof.as_ptr()) };

    if result.is_null() {
        return Ok(());
    }

    let c_error = unsafe { CStr::from_ptr(result) };
    let error = c_error.to_str()?.to_string();

    unsafe { go::FreeString(c_error.as_ptr()) };

    bail!(error);
}
