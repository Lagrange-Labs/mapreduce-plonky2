//! Utility functions

use anyhow::Result;
use serde::de::DeserializeOwned;
use std::{
    fs::File,
    io::{BufReader, Read},
    path::Path,
};

/// Read the data from the file.
pub fn read_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>> {
    let mut data = vec![];
    let mut fd = File::open(file_path)?;
    fd.read_to_end(&mut data)?;

    Ok(data)
}

/// Read the JSON file to an instance.
pub fn read_json<T: DeserializeOwned, P: AsRef<Path>>(file_path: P) -> Result<T> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    Ok(serde_json::from_reader(reader)?)
}
