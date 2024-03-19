//! Groth16 proof data

use anyhow::Result;
use std::{fs::File, io::Read, path::Path};

/// Groth16 proof
#[derive(Debug)]
pub struct Groth16Proof {
    /// The proof data
    pub proof: Vec<u8>,
}

impl Groth16Proof {
    /// Read the Groth16 proof from a file.
    pub fn from_file<P: AsRef<Path>>(file_path: P) -> Result<Self> {
        let mut proof = vec![];
        let mut fd = File::open(file_path)?;
        fd.read_to_end(&mut proof)?;

        Ok(Self { proof })
    }
}
