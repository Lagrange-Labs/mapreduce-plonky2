//! Utility functions

use crate::{C, D, F};
use anyhow::{anyhow, Result};
use plonky2::plonk::circuit_data::CircuitData;
use recursion_framework::serialization::circuit_data_serialization::{
    CustomGateSerializer, CustomGeneratorSerializer,
};
use std::{
    fs::File,
    io::{Read, Write},
    marker::PhantomData,
    path::Path,
};

/// The filename of the cached circuit data
pub const CIRCUIT_DATA_FILENAME: &str = "circuit.bin";

/// Read the data from a file.
pub fn read_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>> {
    let mut data = vec![];
    let mut fd = File::open(file_path)?;
    fd.read_to_end(&mut data)?;

    Ok(data)
}

/// Write the data to a file.
pub fn write_file<P: AsRef<Path>>(file_path: P, data: &[u8]) -> Result<()> {
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
                _phantom: PhantomData::default(),
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
            _phantom: PhantomData::default(),
        },
    )
    .map_err(|err| anyhow!("Failed to deserialize circuit data: {err:?}"))
}
