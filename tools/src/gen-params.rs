#![feature(generic_const_exprs)]
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::Parser;
use groth16_framework::compile_and_generate_assets;
use groth16_framework::utils::clone_circuit_data;
use mp2_v1::api::{build_circuits_params, PublicParameters};
use verifiable_db::api::QueryParameters;

use lgn_messages::types::v1::query::{NUM_CHUNKS, NUM_ROWS};
use lgn_provers::params::PARAMS_CHECKSUM_FILENAME;
use lgn_provers::provers::v1::query::MAX_NUM_OUTPUTS;
use lgn_provers::provers::v1::query::MAX_NUM_PLACEHOLDERS;
use lgn_provers::provers::v1::query::MAX_NUM_PREDICATE_OPS;
use lgn_provers::provers::v1::query::MAX_NUM_RESULT_OPS;
use lgn_provers::provers::v1::query::{INDEX_TREE_MAX_DEPTH, MAX_NUM_ITEMS_PER_OUTPUT};
use lgn_provers::provers::v1::query::{MAX_NUM_COLUMNS, ROW_TREE_MAX_DEPTH};

const GROTH16_ASSETS_PREFIX: &str = "groth16_assets";
const PP_BIN_KEY: &str = "preprocessing_params.bin";
const QP_BIN_KEY: &str = "query_params.bin";

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

/// The settings required to determine the location of the PP files on disk.
struct ParamGenerationSettings {
    /// Under which directory the PPs shall be saved
    root_dir: String,
    /// Whether PPs should be addressed by MP2 major version or git hash.
    mode: String,
}
impl ParamGenerationSettings {
    /// Build the params directory as a sub-path of mp2 major version or hash.
    fn params_dir(&self) -> String {
        let path = Path::new(&self.root_dir);
        let root = match self.mode.as_str() {
            "major" => {
                let mp2_version_str = verifiable_db::version();
                semver::Version::parse(mp2_version_str)
                    .unwrap()
                    .major
                    .to_string()
            }
            "hash" => verifiable_db::short_git_version(),
            _ => unreachable!("ensured by clap"),
        };

        path.join(root).to_string_lossy().to_string()
    }
}

/// Generate the public parameters for the current version of MR2.
#[derive(Debug, Parser)]
struct Args {
    /// Where to serialize the public parameters.
    #[arg(short, long, default_value = "./zkmr_params")]
    params_root_dir: String,

    /// Generate Groth16 parameters from existing query parameters
    #[arg(long)]
    only_groth16: bool,

    #[arg(short, long, value_parser = ["major", "hash"])]
    mode: String,
}

/// Given a config, walk its PPs direct and write the list of the relative path
/// of the contained files and their B3 hash to the target hash file.
fn write_hashes(param_settings: &ParamGenerationSettings) {
    let hash_file_path =
        Path::new(param_settings.params_dir().as_str()).join(PARAMS_CHECKSUM_FILENAME);
    let mut out_file = File::create(hash_file_path).expect("failed to create hash file");

    for entry in walkdir::WalkDir::new(&param_settings.root_dir)
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
                        .strip_prefix(param_settings.params_dir())
                        .unwrap()
                        .display(),
                    hash_str
                )
                .as_bytes(),
            )
            .expect("failed to write to hash file");
    }
}

/// Main entry point for the parameter generation tool
#[tokio::main]
async fn main() {
    // Parse the CLI arguments.
    let args = Args::parse();
    let param_storage_settings = ParamGenerationSettings {
        root_dir: args.params_root_dir.clone(),
        mode: args.mode.clone(),
    };

    println!("serializing parameters to `{}`", args.params_root_dir);

    let query_params = if args.only_groth16 {
        load_query_params_from_disk(&param_storage_settings)
    } else {
        // TRICKY: The parameters have large size, we suppose to generate and drop it in a local
        // scope to avoid stack overflow, and also need to avoid passing into an async function.

        let preprocessing_params = build_preprocessing_params();
        let query_params = build_query_parameters(&preprocessing_params);
        generate_groth16_assets(&param_storage_settings, &query_params);

        let _ = store_preprocessing_params(&param_storage_settings, &preprocessing_params);
        let _ = store_query_params(&param_storage_settings, &query_params);

        query_params
    };
    generate_groth16_assets(&param_storage_settings, &query_params);

    write_hashes(&param_storage_settings);
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
    param_settings: &ParamGenerationSettings,
    preprocessing_params: &PreprocessingParameters,
) -> PathBuf {
    let _now = Instant::now();

    // Serialize the preprocessing parameters.
    println!("Start to serialize the preprocessing parameters");
    let data = bincode::serialize(&preprocessing_params).unwrap();
    println!("Finish serializing the preprocessing parameters");

    // Store on disk
    println!("Start to store the preprocessing parameters on disk");

    let file_path = Path::new(param_settings.params_dir().as_str()).join(PP_BIN_KEY);
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
fn store_query_params(
    param_settings: &ParamGenerationSettings,
    query_params: &QueryParams,
) -> PathBuf {
    let _now = Instant::now();

    // Serialize the preprocessing parameters.
    println!("Start to serialize the query parameters");
    let data = bincode::serialize(query_params).unwrap();
    println!("Finish serializing the query parameters");

    // Store on disk
    println!("Start to store the query parameters on disk");
    let file_path = Path::new(param_settings.params_dir().as_str()).join(QP_BIN_KEY);
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
fn load_query_params_from_disk(param_settings: &ParamGenerationSettings) -> QueryParams {
    let now = Instant::now();
    println!("Start loading query parameters from disk");

    let file_path = Path::new(param_settings.params_dir().as_str()).join(QP_BIN_KEY);
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

/// Generate Groth16 asset files and save to disk
fn generate_groth16_assets(param_settings: &ParamGenerationSettings, query_params: &QueryParams) {
    let now = Instant::now();

    println!("Start to generate the Groth16 asset files");

    // Get the final circuit data of the query parameters.
    let circuit_data = query_params.final_proof_circuit_data();
    let circuit_data = clone_circuit_data(circuit_data)
        .unwrap_or_else(|err| panic!("Failed to clone the circuit data: {}", err));

    // Compile and generate the Groth16 asset files.
    let assets_dir = format!("{}/{GROTH16_ASSETS_PREFIX}", param_settings.params_dir());
    compile_and_generate_assets(circuit_data, &assets_dir).unwrap();

    println!(
        "Finish generating the Groth16 asset files, elapsed: {:?}",
        now.elapsed()
    );
}
