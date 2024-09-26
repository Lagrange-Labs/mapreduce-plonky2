//! Utility functions

use crate::C;
use alloy::primitives::U256;
use anyhow::{anyhow, Result};
use mp2_common::{
    serialization::{FromBytes, ToBytes},
    D, F,
};
use plonky2::plonk::circuit_data::CircuitData;
use serde::Deserialize;
use std::{
    fs::{create_dir_all, File},
    io::{BufReader, Read, Write},
    path::Path,
};

/// The filename of the cached circuit data. This is the circuit data of the final wrapped proof.
/// The actual mapreduce-plonky2 proof being verified has already been hardcoded in the wrapped proof.
pub const CIRCUIT_DATA_FILENAME: &str = "circuit.bin";

/// The filename of the exported Solidity verifier contract.
pub const SOLIDITY_VERIFIER_FILENAME: &str = "verifier.sol";

/// Convert a string with `0x` prefix to an U256.
pub fn hex_to_u256(s: &str) -> Result<U256> {
    let s = s
        .strip_prefix("0x")
        .ok_or(anyhow!("The hex string must have `0x` prefix: {s}"))?;
    let u = U256::from_str_radix(s, 16)?;

    Ok(u)
}

/// Deserialize from a JSON file.
pub fn deserialize_json_file<P: AsRef<Path>, T: for<'de> Deserialize<'de>>(
    file_path: P,
) -> Result<T> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    Ok(serde_json::from_reader(reader)?)
}

/// Read the data from a file.
pub fn read_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>> {
    let mut data = vec![];
    let mut fd = File::open(file_path)?;
    fd.read_to_end(&mut data)?;

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
