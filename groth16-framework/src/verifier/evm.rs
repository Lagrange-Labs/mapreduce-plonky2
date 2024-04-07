//! The verifier used to test the Solidity verification.

use crate::{
    evm::{executor::deploy_and_call, utils::compile_solidity},
    utils::read_file,
};
use anyhow::Result;

/// EVM verifier
#[derive(Debug)]
pub struct EVMVerifier {
    /// The compiled deployment code of Solidity verifier contract
    deployment_code: Vec<u8>,
}

impl EVMVerifier {
    pub fn new(solidity_file_path: &str) -> Result<Self> {
        // Read the Solidity code from file.
        let solidity_code = read_file(solidity_file_path)?;

        // Compile the Solidity code.
        let deployment_code = compile_solidity(&solidity_code);

        Ok(Self { deployment_code })
    }

    /// Verify the calldata with Solidity verifier contract.
    /// Return the gas_used and the output bytes if success.
    pub fn verify(&self, calldata: Vec<u8>) -> Result<(u64, Vec<u8>)> {
        match deploy_and_call(self.deployment_code.clone(), calldata) {
            Ok(result) => {
                log::debug!(
                    "Succeeded to do EVM verification: gas_used = {}, output = {:?}",
                    result.0,
                    result.1
                );
                Ok(result)
            }
            Err(error) => {
                log::error!("Failed to do EVM verification: {error}");
                Err(error)
            }
        }
    }
}
