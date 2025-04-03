//! Utility functions

use crate::C;
use alloy::primitives::U256;
use anyhow::{anyhow, Result};
use mp2_common::{
    serialization::{FromBytes, ToBytes},
    D, F,
};
use plonky2::plonk::circuit_data::CircuitData;
use std::{
    fs::{create_dir_all, File},
    io::{Read, Write},
    path::Path,
};

/// The filename of the cached circuit data. This is the circuit data of the final wrapped proof.
/// The actual mapreduce-plonky2 proof being verified has already been hardcoded in the wrapped proof.
pub const CIRCUIT_DATA_FILENAME: &str = "circuit.bin";

/// The filename of the exported Solidity verifier contract.
pub const SOLIDITY_VERIFIER_FILENAME: &str = "Verifier.sol";

/// The filename of the Groth16 proving key
pub const PK_FILENAME: &str = "pk.bin";

/// The filename of the Groth16 verification key
pub const VK_FILENAME: &str = "vk.bin";

/// Convert a string with `0x` prefix to an U256.
pub fn hex_to_u256(s: &str) -> Result<U256> {
    let s = s
        .strip_prefix("0x")
        .ok_or(anyhow!("The hex string must have `0x` prefix: {s}"))?;
    let u = U256::from_str_radix(s, 16)?;

    Ok(u)
}

/// Read the data from a file.
pub fn read_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>> {
    let mut data = vec![];
    let mut fd = File::open(file_path)?;
    fd.read_to_end(&mut data)?;

    Ok(data)
}

/// Read the data from a file as a String
pub fn read_file_to_string<P: AsRef<Path>>(file_path: P) -> Result<String> {
    let mut data = String::new();
    let mut fd = File::open(file_path)?;
    fd.read_to_string(&mut data)?;

    Ok(data)
}

/// Write the data to a file.
pub fn write_file<P: AsRef<Path>>(file_path: P, data: &[u8]) -> Result<()> {
    // Try to create the parent dir if not exists.
    if let Some(parent_dir) = file_path.as_ref().parent() {
        create_dir_all(parent_dir)?;
    }

    // Write the file.
    let mut fd = File::create(file_path)?;
    fd.write_all(data)?;

    Ok(())
}

/// Serialize the circuit data to bytes.
pub fn serialize_circuit_data(circuit_data: &CircuitData<F, C, D>) -> Result<Vec<u8>> {
    // Assume that the circuit data could always be serialized by the custom
    // gate and generator serializers of recursive-framework.
    Ok(ToBytes::to_bytes(circuit_data))
}

/// Deserialize bytes to the circuit data.
pub fn deserialize_circuit_data(bytes: &[u8]) -> Result<CircuitData<F, C, D>> {
    // Assume that the circuit data could always be deserialized by the custom
    // gate and generator serializers of recursive-framework.
    <CircuitData<F, C, D> as FromBytes>::from_bytes(bytes)
        .map_err(|err| anyhow::Error::msg(err.to_string()))
}

/// Serialize reference of circuit data, then deserialize to implement clone.
pub fn clone_circuit_data(circuit_data: &CircuitData<F, C, D>) -> Result<CircuitData<F, C, D>> {
    deserialize_circuit_data(&serialize_circuit_data(circuit_data)?)
}

/// Read the circuit data from file `circuit.bin` in the asset dir. This is
/// the circuit data of the final wrapped proof.
pub(crate) fn load_circuit_data(asset_dir: &str) -> Result<CircuitData<F, C, D>> {
    // Read from file.
    let file_path = Path::new(asset_dir).join(CIRCUIT_DATA_FILENAME);
    let bytes = read_file(file_path)?;

    // Deserialize the circuit data.
    deserialize_circuit_data(&bytes)
}

/// Save the circuit data to file `circuit.bin` in the asset dir.
pub(crate) fn save_circuit_data(
    circuit_data: &CircuitData<F, C, D>,
    dst_asset_dir: &str,
) -> Result<()> {
    // Serialize the circuit data.
    let data = serialize_circuit_data(circuit_data)?;

    // Write to file.
    let file_path = Path::new(dst_asset_dir).join(CIRCUIT_DATA_FILENAME);
    write_file(file_path, &data)
}
