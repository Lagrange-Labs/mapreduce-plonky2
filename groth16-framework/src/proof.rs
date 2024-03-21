//! Groth16 proof data

use crate::utils::read_file;
use anyhow::Result;
use std::path::Path;

/// Groth16 proof
#[derive(Debug)]
pub struct Groth16Proof {
    /// The proof data
    pub proof: Vec<u8>,
}

impl Groth16Proof {
    /// Read the Groth16 proof from a file.
    pub fn from_file<P: AsRef<Path>>(file_path: P) -> Result<Self> {
        let proof = read_file(file_path)?;

        Ok(Self { proof })
    }
}
