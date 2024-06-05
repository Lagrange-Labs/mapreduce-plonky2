//! Test utility functions

use anyhow::Result;
use log::info;
use mp2_v1::api::{build_circuits_params, PublicParameters};
use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::Path,
};

/// Load or generate the public parameters.
pub fn load_or_generate_public_params<P: AsRef<Path>>(file_path: P) -> Result<PublicParameters> {
    if file_path.as_ref().exists() {
        let file = File::open(&file_path)?;
        let reader = BufReader::new(file);

        let public_params = bincode::deserialize_from(reader)?;

        info!("Read the public parameters from the cached file");

        return Ok(public_params);
    }

    let public_params = build_circuits_params();

    let file = File::create(&file_path)?;
    let writer = BufWriter::new(file);

    bincode::serialize_into(writer, &public_params)?;

    info!("Build the public parameters and save to the cached file");

    Ok(public_params)
}
