//! Groth16 proof data

use crate::utils::read_json;
use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

/// Groth16 proof
#[derive(Debug, Deserialize)]
pub struct Groth16Proof {
    /// Proof data
    pub proofs: Vec<String>,
    /// Public inputs
    pub inputs: Vec<String>,
}

impl Groth16Proof {
    /// Read the Groth16 proof from a file.
    pub fn from_file<P: AsRef<Path>>(file_path: P) -> Result<Self> {
        read_json(file_path)
    }
}
