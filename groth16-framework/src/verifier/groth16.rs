//! The verifier used to verify the Groth16 proof.

use crate::proof::Groth16Proof;
use anyhow::Result;

/// Groth16 verifier configuration
#[derive(Debug)]
pub struct Groth16VerifierConfig {
    pub asset_dir: String,
}

/// Groth16 verifier
#[derive(Debug)]
pub struct Groth16Verifier;

impl Groth16Verifier {
    pub fn new(config: Groth16VerifierConfig) -> Result<Self> {
        gnark_utils::init_verifier(&config.asset_dir)?;

        Ok(Self)
    }

    /// Verify the proof. Return Ok if it's verified successfully, otherwise
    /// it returns an error.
    pub fn verify(&self, proof: &Groth16Proof) -> Result<()> {
        let proof = serde_json::to_string(proof)?;

        gnark_utils::verify(&proof)
    }
}
