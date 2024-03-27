//! Initialize the verifier and verify the proofs.

use crate::{go, utils::handle_c_result};
use anyhow::Result;
use std::ffi::CString;

/// Initialize the verifier.
pub fn init_verifier(asset_dir: &str) -> Result<()> {
    let asset_dir = CString::new(asset_dir)?;

    let result = unsafe { go::InitVerifier(asset_dir.as_ptr()) };

    handle_c_result(result)
}

/// Verify the proof.
pub fn verify(proof: &str) -> Result<()> {
    let proof = CString::new(proof)?;

    let result = unsafe { go::Verify(proof.as_ptr()) };

    handle_c_result(result)
}
