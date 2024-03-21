//! The verifier used to test Groth16 proof verification on EVM

use crate::{
    evm::{compile_solidity, deploy_and_call},
    utils::read_file,
};
use anyhow::Result;

/// EVM verifier configuration
#[derive(Debug)]
pub struct EVMVerifierConfig {
    /// The file path of Solidity verifier contract
    pub solidity_path: String,
}

/// EVM verifier
#[derive(Debug)]
pub struct EVMVerifier {
    /// The compiled deployment code of Solidity verifier contract
    deployment_code: Vec<u8>,
}

impl EVMVerifier {
    pub fn new(config: EVMVerifierConfig) -> Result<Self> {
        // Read Solidity code from the file.
        let solidity_code = read_file(config.solidity_path)?;

        // Compile the Solidity code.
        let deployment_code = compile_solidity(&solidity_code);

        Ok(Self { deployment_code })
    }

    /// Verify the calldata with Solidity verifier contract.
    pub fn verify(&self, calldata: Vec<u8>) -> bool {
        match deploy_and_call(self.deployment_code.clone(), calldata) {
            Ok(gas_used) => {
                log::info!("Succeeded to do EVM verification: gas_used = {gas_used}");
                true
            }
            Err(error) => {
                log::info!("Failed to do EVM verification: {error}");
                false
            }
        }
    }
}
