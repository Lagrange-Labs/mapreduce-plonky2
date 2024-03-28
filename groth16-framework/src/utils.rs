//! Utility functions

use crate::{C, D, F};
use anyhow::{anyhow, Result};
use ethers::types::U256;
use plonky2::plonk::circuit_data::CircuitData;
use recursion_framework::serialization::circuit_data_serialization::{
    CustomGateSerializer, CustomGeneratorSerializer,
};
use std::{
    fs::{create_dir_all, File},
    io::{Read, Write},
    marker::PhantomData,
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
    circuit_data
        .to_bytes(
            &CustomGateSerializer,
            &CustomGeneratorSerializer::<C, D> {
                _phantom: PhantomData,
            },
        )
        .map_err(|err| anyhow!("Failed to serialize circuit data: {err:?}"))
}

/// Deserialize bytes to the circuit data.
pub fn deserialize_circuit_data(bytes: &[u8]) -> Result<CircuitData<F, C, D>> {
    // Assume that the circuit data could always be deserialized by the custom
    // gate and generator serializers of recursive-framework.
    CircuitData::from_bytes(
        bytes,
        &CustomGateSerializer,
        &CustomGeneratorSerializer::<C, D> {
            _phantom: PhantomData,
        },
    )
    .map_err(|err| anyhow!("Failed to deserialize circuit data: {err:?}"))
}

/// Serialize reference of circuit data, then deserialize to implement clone.
pub fn clone_circuit_data(circuit_data: &CircuitData<F, C, D>) -> Result<CircuitData<F, C, D>> {
    deserialize_circuit_data(&serialize_circuit_data(circuit_data)?)
}
