//! The Groth16 proof struct

use serde::{Deserialize, Serialize};

/// Groth16 proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Groth16Proof {
    /// The proofs item is an array of [U256; 8], which should be passed to the
    /// `verifyProof` function of the Solidity verifier contract.
    pub proofs: Vec<String>,
    /// The inputs item is an array of [U256; 3], which should be passed to the
    /// `verifyProof` function of the Solidity verifier contract.
    pub inputs: Vec<String>,
    /// The original raw proof data is used to be verified off-chain.
    pub raw_proof: String,
    /// The original raw public witness data is used to be verified off-chain.
    pub raw_public_witness: String,
}
