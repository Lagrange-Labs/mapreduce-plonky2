//! The CLI used to generate the asset files for the Groth16 prover and verifier

use std::iter::once;

use anyhow::Result;
use clap::Parser;
use ethers::types::Address;
use groth16_framework::utils::clone_circuit_data;
use itertools::Itertools;
use mapreduce_plonky2::{
    api::{deserialize_proof, serialize_proof, ProofWithVK},
    block::{empty_merkle_root, PublicInputs as BlockDbPublicInputs, NUM_IVC_PUBLIC_INPUTS},
    eth::{left_pad, left_pad32},
    group_hashing,
    keccak::PACKED_HASH_LEN,
    query2::{
        block::BlockPublicInputs,
        revelation::{Parameters, RevelationRecursiveInput},
        CircuitInput, PublicParameters,
    },
    types::MAPPING_KEY_LEN,
    utils::{Packer, ToFields},
};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64, Sample},
    },
    hash::hash_types::{HashOut, NUM_HASH_OUT_ELTS},
    plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
};
use rand::{thread_rng, Rng};
use recursion_framework::framework_testing::TestingRecursiveCircuits;
use std::{
    fs::{metadata, File},
    io::Read,
    path::Path,
    time::Instant,
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

const QUERY2_BLOCK_NUM_IO: usize = mapreduce_plonky2::query2::block::NUM_IO;
const BLOCK_DB_NUM_IO: usize = NUM_IVC_PUBLIC_INPUTS;

// TODO: the constants need to be updated.
const L: usize = 2;
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
    // gupeng
    // let q2_params = build_query2_parameters(&args.query2);

    // Generate the test inputs. It's used in the generation, but should not be
    // related with the generated assets.
    let (inputs, q2_params) = generate_test_inputs();

    // Get the final circuit data of query2 parameters.
    // let circuit_data = q2_params.final_proof_circuit_data();
    let circuit_data = q2_params.circuit_data();
    let circuit_data = clone_circuit_data(circuit_data)
        .unwrap_or_else(|err| panic!("Failed to clone the circuit data: {}", err));

    // Generate the query2 proof.
    let proof = q2_params
        .generate_proof(inputs)
        .unwrap_or_else(|err| panic!("Failed to generate the query2 proof: {}", err));
    let proof = deserialize_proof(&proof)
        .unwrap_or_else(|err| panic!("Failed to deserialize the query2 proof: {}", err));

    // Generate the Groth16 assets.
    let now = Instant::now();
    groth16_framework::compile_and_generate_assets(circuit_data, &proof, &args.assets)
        .unwrap_or_else(|err| panic!("Failed to generate the assets: {}", err));
    log::info!(
        "Finish generating the asset files, elapsed: {:?}",
        now.elapsed()
    );
}

/// Build the query2 parameters from a data file of block DB circuit info.
fn build_query2_parameters(circuit_info_file_path: &str) -> PublicParameters<BLOCK_DB_DEPTH, L> {
    // Check if the circuit info file exists.
    metadata(circuit_info_file_path).unwrap_or_else(|err| {
        panic!(
            "The file of block DB circuit info '{}' doesn't exist: {}",
            circuit_info_file_path, err
        )
    });

    let circuit_info = read_file(circuit_info_file_path).unwrap_or_else(|err| {
        panic!(
            "Failed to read the file '{}': {}",
            circuit_info_file_path, err
        )
    });

    PublicParameters::build(&circuit_info)
        .unwrap_or_else(|err| panic!("Failed to build the query2 parameters: {}", err))
}

/// Generate the test inputs.
// fn generate_test_inputs() -> (CircuitInput<L>, Parameters::<BLOCK_DB_DEPTH, L>)  {
fn generate_test_inputs() -> (RevelationRecursiveInput<L>, Parameters<BLOCK_DB_DEPTH, L>) {
    // Generate a fake query2/block circuit set
    let query2_testing_framework =
        TestingRecursiveCircuits::<F, C, D, QUERY2_BLOCK_NUM_IO>::default();
    let query2_block_circuit_set = query2_testing_framework.get_recursive_circuit_set();

    // Generate a fake block/ verification key
    let block_db_testing_framework =
        TestingRecursiveCircuits::<F, C, D, BLOCK_DB_NUM_IO>::default();
    let block_db_circuit_set = block_db_testing_framework.get_recursive_circuit_set();
    let block_db_vk = block_db_testing_framework.verifier_data_for_input_proofs::<1>()[0];

    let params = Parameters::<BLOCK_DB_DEPTH, L>::build(
        query2_block_circuit_set,
        block_db_circuit_set,
        block_db_vk,
    );

    // Generate a fake block db proof
    let init_root = empty_merkle_root::<GoldilocksField, 2, BLOCK_DB_DEPTH>();
    let last_root = HashOut {
        elements: F::rand_vec(NUM_HASH_OUT_ELTS).try_into().unwrap(),
    };
    let init_block_number = F::from_canonical_u32(thread_rng().gen::<u32>());
    let db_range = 555;
    let last_block_number = init_block_number + F::from_canonical_usize(db_range);
    let last_block_hash = F::rand_vec(PACKED_HASH_LEN);

    let block_db_inputs: [F; BLOCK_DB_NUM_IO] = BlockDbPublicInputs::from_parts(
        &init_root.elements,
        &last_root.elements,
        init_block_number,
        last_block_number,
        &last_block_hash.try_into().unwrap(),
    )
    .into_iter()
    .chain(once(F::ONE))
    .collect_vec()
    .try_into()
    .unwrap();
    let block_db_pi = BlockDbPublicInputs::<GoldilocksField>::from(&block_db_inputs);
    let block_db_proof = &block_db_testing_framework
        .generate_input_proofs::<1>([block_db_inputs.clone()])
        .unwrap()[0];

    // Generate a fake query2/block proof, taking some inputs from the block db
    // block range asked is just one block less than latest block in db
    let query_max_number = block_db_pi.block_number_data() - F::ONE;
    let query_range = F::from_canonical_usize(10);
    let query_min_number = query_max_number - query_range;
    let query_root = HashOut {
        elements: block_db_pi.root_data().try_into().unwrap(),
    };
    let smc_address = Address::random();
    let user_address = Address::random();
    let mapping_slot = F::rand();
    let length_slot = F::rand();
    let mapping_keys = (0..L)
        .map(|_| left_pad::<MAPPING_KEY_LEN>(&[thread_rng().gen::<u8>()]))
        .collect::<Vec<_>>();
    let packed_field_mks = mapping_keys
        .iter()
        .map(|x| x.pack().to_fields())
        .collect::<Vec<_>>();
    let digests = packed_field_mks
        .iter()
        .map(|i| group_hashing::map_to_curve_point(i))
        .collect::<Vec<_>>();
    let single_digest = group_hashing::add_curve_point(&digests);
    let pis = BlockPublicInputs::from_parts(
        query_max_number,
        query_range,
        query_root,
        &smc_address
            .as_fixed_bytes()
            .pack()
            .to_fields()
            .try_into()
            .unwrap(),
        &left_pad32(user_address.as_fixed_bytes())
            .pack()
            .to_fields()
            .try_into()
            .unwrap(),
        mapping_slot,
        length_slot,
        single_digest.to_weierstrass(),
    );
    let query2_block_proof = query2_testing_framework
        .generate_input_proofs([pis])
        .unwrap();
    let query2_block_vd = query2_testing_framework.verifier_data_for_input_proofs::<1>();
    let q2_proof_buff = ProofWithVK {
        proof: query2_block_proof[0].clone(),
        vk: query2_block_vd[0].clone(),
    }
    .serialize()
    .unwrap();
    let block_db_buff = serialize_proof(block_db_proof).unwrap();

    // Create the revelation input.
    let revelation_input = RevelationRecursiveInput::<L>::new(
        mapping_keys.into_iter().map(|x| x.to_vec()).collect(),
        query_min_number.to_canonical_u64() as usize,
        query_max_number.to_canonical_u64() as usize,
        q2_proof_buff,
        block_db_buff,
    )
    .unwrap_or_else(|err| panic!("Failed to create RevelationRecursiveInput: {}", err));

    return (revelation_input, params);
    // CircuitInput::Revelation(revelation_input)
}

/// Read the data from a file.
fn read_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>> {
    let mut data = vec![];
    let mut fd = File::open(file_path)?;
    fd.read_to_end(&mut data)?;

    Ok(data)
}
