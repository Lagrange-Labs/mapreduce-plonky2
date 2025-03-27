//! Compile and generate asset files from the circuit data.

use crate::{go, utils::handle_c_result};
use anyhow::Result;
use std::ffi::CString;

/// Compile the circuit data and generate the asset files of `r1cs.bin`,
/// `pk.bin`, `vk.bin` and `Verifier.sol`.
pub fn compile_and_generate_assets(
    common_circuit_data: &str,
    verifier_only_circuit_data: &str,
    dst_asset_dir: &str,
) -> Result<()> {
    let [common_circuit_data, verifier_only_circuit_data, dst_asset_dir] = [
        common_circuit_data,
        verifier_only_circuit_data,
        dst_asset_dir,
    ]
    .map(CString::new);

    let result = unsafe {
        go::CompileAndGenerateAssets(
            common_circuit_data?.as_ptr(),
            verifier_only_circuit_data?.as_ptr(),
            dst_asset_dir?.as_ptr(),
        )
    };

    handle_c_result(result)
}

/// Compile the circuit data to an `r1cs.bin` file
pub fn build_verifier_circuit(
    common_circuit_data: &str,
    verifier_only_circuit_data: &str,
    dst_asset_dir: &str,
) -> Result<()> {
    let [common_circuit_data, verifier_only_circuit_data, dst_asset_dir] = [
        common_circuit_data,
        verifier_only_circuit_data,
        dst_asset_dir,
    ]
    .map(CString::new);

    let result = unsafe {
        go::BuildAndSaveVerifierCircuit(
            common_circuit_data?.as_ptr(),
            verifier_only_circuit_data?.as_ptr(),
            dst_asset_dir?.as_ptr(),
        )
    };

    handle_c_result(result)
}

/// Generate a Solidity verifier for the verification key found in file `vk.bin`
/// of the specified `dst_asset_dir`. The Solidity verifier is written to `Verifier.sol`
/// in the same asset directory
pub fn generate_solidity_verifier(dst_asset_dir: &str) -> Result<()> {
    let dst_asset_dir = CString::new(dst_asset_dir);
    let result = unsafe { go::GenerateSolidityVerifier(dst_asset_dir?.as_ptr()) };

    handle_c_result(result)
}
