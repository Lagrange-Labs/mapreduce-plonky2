#![feature(generic_const_exprs)]
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::{Parser, Subcommand};
use groth16_framework::utils::{clone_circuit_data, PK_FILENAME, VK_FILENAME};
use groth16_framework::{
    build_verifier_circuit, compile_and_generate_assets, generate_solidity_verifier,
};
use mp2_v1::api::{build_circuits_params, PublicParameters};
use tools::{INDEX_TREE_MAX_DEPTH, MAX_NUM_COLUMNS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_OUTPUTS, 
    MAX_NUM_PLACEHOLDERS, MAX_NUM_PREDICATE_OPS, MAX_NUM_RESULT_OPS, NUM_CHUNKS, NUM_ROWS, 
    PARAMS_CHECKSUM_FILENAME, PP_BIN_KEY, QP_BIN_KEY, ROW_TREE_MAX_DEPTH, GROTH16_ASSETS_PREFIX,
};
use verifiable_db::api::QueryParameters;

type QueryParams = QueryParameters<
    NUM_CHUNKS,
    NUM_ROWS,
    ROW_TREE_MAX_DEPTH,
    INDEX_TREE_MAX_DEPTH,
    MAX_NUM_COLUMNS,
    MAX_NUM_PREDICATE_OPS,
    MAX_NUM_RESULT_OPS,
    MAX_NUM_OUTPUTS,
    MAX_NUM_ITEMS_PER_OUTPUT,
    MAX_NUM_PLACEHOLDERS,
>;
type PreprocessingParameters = PublicParameters;

/// Generate the public parameters for the current version of MR2.
#[derive(Debug, Parser)]
struct Args {
    /// Where to serialize the public parameters.
    #[arg(short, long, default_value = "./zkmr_params")]
    params_root_dir: String,

    /// Generate Groth16 parameters from existing query parameters
    #[arg(long, default_value_t = false)]
    only_groth16: bool,

    /// If this flag is true, then only the R1CS file is generated for Groth16
    /// instead of all the Groth16 assets; useful when the proving and verification
    /// keys must be generated with a trusted setup ceremony
    #[arg(long, default_value_t = false)]
    only_r1cs: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    GenSolidityCmd {
        /// Path to the proving key file; if no path is provided, the proving key is assumed
        /// to be already in the asset dir directory
        #[arg(short, long)]
        pk_path: Option<String>,

        /// Path to the verification key file; if no path is provided, the proving key is assumed
        /// to be already in the asset dir directory
        #[arg(short, long)]
        vk_path: Option<String>,
    },
}

/// Build the params directory with a sub-path of mp2 version.
fn params_dir(params_dir: &str) -> String {
    let path = Path::new(params_dir);
    let mp2_version_str = verifiable_db::version();
    let version = semver::Version::parse(mp2_version_str).unwrap();

    path.join(version.major.to_string())
        .to_string_lossy()
        .to_string()
}

/// Given a config, walk its PPs direct and write the list of the relative path
/// of the contained files and their B3 hash to the target hash file.
fn write_hashes(params_root_dir: &str) {
    let hash_file_path =
        Path::new(params_dir(params_root_dir).as_str()).join(PARAMS_CHECKSUM_FILENAME);
    let mut out_file = File::create(hash_file_path).expect("failed to create hash file");

    for entry in walkdir::WalkDir::new(params_root_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .map(|e| e.path().to_path_buf())
        .filter(|p| p.is_file())
    {
        println!("hashing {}", entry.display());
        let mut hasher = blake3::Hasher::new();
        hasher
            .update_mmap_rayon(entry.as_path())
            .expect("hashing failed");
        let hash_str = hasher.finalize().to_hex();
        out_file
            .write_all(
                format!(
                    "{} {}\n",
                    entry
                        .strip_prefix(params_dir(params_root_dir))
                        .unwrap()
                        .display(),
                    hash_str
                )
                .as_bytes(),
            )
            .expect("failed to write to hash file");
    }
}

#[tokio::main]
/// Main entry point for the parameter generation tool
async fn main() {
    env_logger::init();
    // Parse the CLI arguments.
    let args = Args::parse();
    println!("serializing parameters to `{}`", args.params_root_dir);
    
    match &args.command {
        Some(Commands::GenSolidityCmd { pk_path, vk_path }) => {
            generate_solidity_cmd(&args.params_root_dir, pk_path, vk_path)
        }
        None => {
            let query_params = if args.only_groth16 {
                load_query_params_from_disk(&args.params_root_dir)
            } else {
                // TRICKY: The parameters have large size, we suppose to generate and drop it in a local
                // scope to avoid stack overflow, and also need to avoid passing into an async function.
                let preprocessing_params = build_preprocessing_params();
                let query_params = build_query_parameters(&preprocessing_params);

                let _ = store_preprocessing_params(&args.params_root_dir, &preprocessing_params);
                let _ = store_query_params(&args.params_root_dir, &query_params);

                query_params
            };
            generate_groth16_assets(&args.params_root_dir, &query_params, args.only_r1cs);
        }
    }

    write_hashes(&args.params_root_dir);
}

/// Build preprocessing parameters
fn build_preprocessing_params() -> PreprocessingParameters {
    let now = Instant::now();

    println!("Start to generate the preprocessing parameters");

    let params = build_circuits_params();

    println!(
        "Finish generating the preprocessing parameters, elapsed: {:?}",
        now.elapsed()
    );

    params
}

/// Store preprocessing parameters on disk and return the saved file path
fn store_preprocessing_params(
    params_root_dir: &str,
    preprocessing_params: &PreprocessingParameters,
) -> PathBuf {
    let _now = Instant::now();

    // Serialize the preprocessing parameters.
    println!("Start to serialize the preprocessing parameters");
    let data = bincode::serialize(&preprocessing_params).unwrap();
    println!("Finish serializing the preprocessing parameters");

    // Store on disk
    println!("Start to store the preprocessing parameters on disk");

    let file_path = Path::new(params_dir(params_root_dir).as_str()).join(PP_BIN_KEY);
    println!("Writing to file: {:?}", file_path);

    // Try to create the parent dir if not exists.
    if let Some(parent_dir) = file_path.parent() {
        std::fs::create_dir_all(parent_dir).expect("Parent dirs should be created");
    }

    let mut buffer = File::create(file_path.clone()).unwrap();
    buffer.write_all(&data).unwrap();
    println!("Finish storing the preprocessing parameters on disk");

    file_path
}

/// Build query parameters from preprocessing parameters
fn build_query_parameters(indexing_params: &PublicParameters) -> QueryParams {
    QueryParameters::build_params(&indexing_params.get_params_info().unwrap()).unwrap()
}

/// Store query parameters on disk and return the saved file path
fn store_query_params(params_root_dir: &str, query_params: &QueryParams) -> PathBuf {
    let _now = Instant::now();

    // Serialize the preprocessing parameters.
    println!("Start to serialize the query parameters");
    let data = bincode::serialize(query_params).unwrap();
    println!("Finish serializing the query parameters");

    // Store on disk
    println!("Start to store the query parameters on disk");
    let file_path = Path::new(params_dir(params_root_dir).as_str()).join(QP_BIN_KEY);
    println!("Writing to file: {:?}", file_path);

    // Try to create the parent dir if not exists.
    if let Some(parent_dir) = file_path.parent() {
        std::fs::create_dir_all(parent_dir).expect("Parent dirs should be created");
    }

    let mut buffer = File::create(file_path.clone()).unwrap();
    buffer.write_all(&data).unwrap();
    println!("Finish storing the query parameters on disk");

    file_path
}

/// Load query parameters from disk
fn load_query_params_from_disk(params_root_dir: &str) -> QueryParams {
    let now = Instant::now();
    println!("Start loading query parameters from disk");

    let file_path = Path::new(params_dir(params_root_dir).as_str()).join(QP_BIN_KEY);
    let mut file = File::open(file_path).unwrap_or_else(|_| panic!("Failed to open {QP_BIN_KEY}"));
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read file");

    let query_params: QueryParams =
        bincode::deserialize(&buffer).expect("Failed to deserialize query parameters");

    println!(
        "Finished loading query parameters from disk, elapsed: {:?}",
        now.elapsed()
    );

    query_params
}

fn groth16_assets_dir(params_root_dir: &str) -> String {
    format!("{}/{GROTH16_ASSETS_PREFIX}", params_dir(params_root_dir))
}

/// Generate Groth16 asset files and save to disk; if `only_r1cs` flag is true, only the R1CS
/// circuit is compiled and saved in asset directory
fn generate_groth16_assets(params_root_dir: &str, query_params: &QueryParams, only_r1cs: bool) {
    let now = Instant::now();

    println!("Start to generate the Groth16 asset files");

    // Get the final circuit data of the query parameters.
    let circuit_data = query_params.final_proof_circuit_data();
    let circuit_data = clone_circuit_data(circuit_data)
        .unwrap_or_else(|err| panic!("Failed to clone the circuit data: {}", err));

    // Compile and generate the Groth16 asset files.
    let assets_dir = groth16_assets_dir(params_root_dir);
    if only_r1cs {
        build_verifier_circuit(circuit_data, &assets_dir).unwrap()
    } else {
        compile_and_generate_assets(circuit_data, &assets_dir).unwrap();
    }

    println!(
        "Finish generating the Groth16 asset files, elapsed: {:?}",
        now.elapsed()
    );
}

fn generate_solidity_cmd(
    params_root_dir: &str,
    pk_path: &Option<String>,
    vk_path: &Option<String>,
) {
    let assets_dir = groth16_assets_dir(params_root_dir);
    // if a path to a proving key file is provided, then copy the proving key from `pk_path` to `assets_dir/PK_FILENAME`;
    // otherwise, it is assumed that the proving key has already been saved in `assets_dir/PK_FILENAME`
    if let Some(path) = pk_path {
        let pk_file = Path::new(&assets_dir)
            .join(PK_FILENAME)
            .to_string_lossy()
            .to_string();
        std::fs::hard_link(path, pk_file).unwrap()
    }

    // if a path to a verification key file is provided, then copy the verification key from `vk_path` to
    // `assets_dir/VK_FILENAME`; otherwise, it is assumed that the verification key has already been saved in
    // `assets_dir/VK_FILENAME`
    if let Some(path) = vk_path {
        let vk_file = Path::new(&assets_dir)
            .join(VK_FILENAME)
            .to_string_lossy()
            .to_string();
        std::fs::hard_link(path, vk_file).unwrap()
    }

    generate_solidity_verifier(&assets_dir).unwrap();
}
