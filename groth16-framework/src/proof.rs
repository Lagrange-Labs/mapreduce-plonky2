//! Groth16 proof struct

use serde::{Deserialize, Serialize};

/// Groth16 proof
#[derive(Debug, Serialize, Deserialize)]
pub struct Groth16Proof {
    /// Proofs
    pub proofs: Vec<String>,
    /// Public inputs
    pub inputs: Vec<String>,
    /// Raw proof data
    pub raw_proof: String,
    /// Raw public witness data
    pub raw_public_witness: String,
}
