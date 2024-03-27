//! Compile and generate asset files from the circuit data.

use crate::{go, utils::handle_c_result};
use anyhow::Result;
use std::ffi::CString;

/// Compile the circuit data and generate the asset files of `r1cs.bin`,
/// `pk.bin`, `vk.bin` and `verifier.sol`.
pub fn compile_and_generate_assets(
    common_circuit_data: &str,
    verifier_only_circuit_data: &str,
    proof_with_public_inputs: &str,
    dst_asset_dir: &str,
) -> Result<()> {
    let [common_circuit_data, verifier_only_circuit_data, proof_with_public_inputs, dst_asset_dir] =
        [
            common_circuit_data,
            verifier_only_circuit_data,
            proof_with_public_inputs,
            dst_asset_dir,
        ]
        .map(CString::new);

    let result = unsafe {
        go::CompileAndGenerateAssets(
            common_circuit_data?.as_ptr(),
            verifier_only_circuit_data?.as_ptr(),
            proof_with_public_inputs?.as_ptr(),
            dst_asset_dir?.as_ptr(),
        )
    };

    handle_c_result(result)
}
