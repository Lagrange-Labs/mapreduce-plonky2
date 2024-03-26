//! The CLI used to generate the asset files for the Groth16 prover and verifier

use clap::Parser;
use groth16_framework::utils::{clone_circuit_data, file_exists, read_file};
use mapreduce_plonky2::query2::PublicParameters;
use std::time::Instant;

/// The circuit related constants need to be updated if they're changed in the
/// query2 parameters.
const L: usize = 5;
const BLOCK_DB_DEPTH: usize = 2;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// The destination dir used to generate the asset files
    #[arg(short, long)]
    assets: String,
    /// The data file of block DB circuit info to build the query2 parameters
    #[arg(short, long)]
    query2: String,
}

fn main() {
    env_logger::init();

    // Parse the CLI arguments.
    let args = Args::parse();

    // Build the query2 parameters from the file.
    let q2_params = build_query2_parameters(&args.query2);

    // Get the final circuit data of the query2 parameters.
    let circuit_data = q2_params.final_proof_circuit_data();
    let circuit_data = clone_circuit_data(circuit_data)
        .unwrap_or_else(|err| panic!("Failed to clone the circuit data: {}", err));

    // Compile and generate the Groth16 asset files.
    let now = Instant::now();
    groth16_framework::compile_and_generate_assets(circuit_data, &args.assets)
        .unwrap_or_else(|err| panic!("Failed to generate the asset files: {}", err));
    log::info!(
        "Finish generating the asset files, elapsed: {:?}",
        now.elapsed()
    );
}

/// Build the query2 parameters from a data file of block DB circuit info.
fn build_query2_parameters(circuit_info_file_path: &str) -> PublicParameters<BLOCK_DB_DEPTH, L> {
    if !file_exists(circuit_info_file_path) {
        panic!(
            "The file of block DB circuit info doesn't exist: {}",
            circuit_info_file_path
        )
    }

    let circuit_info = read_file(circuit_info_file_path).unwrap_or_else(|err| {
        panic!(
            "Failed to read the file '{}': {}",
            circuit_info_file_path, err
        )
    });

    PublicParameters::build(&circuit_info)
        .unwrap_or_else(|err| panic!("Failed to build the query2 parameters: {}", err))
}
