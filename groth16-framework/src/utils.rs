//! Utility functions

use anyhow::Result;
use std::{fs::File, io::Read, path::Path};

/// Read the data from the file.
pub fn read_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>> {
    let mut data = vec![];
    let mut fd = File::open(file_path)?;
    fd.read_to_end(&mut data)?;

    Ok(data)
}
