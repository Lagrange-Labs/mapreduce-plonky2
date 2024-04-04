//! Test the Groth16 proving process for the query2 circuit.

use anyhow::Result;
use ethers::abi::{Contract, Token};
use ethers::types::{Address, U256};
use groth16_framework::{
    compile_and_generate_assets,
    test_utils::{save_plonky2_proof_pis, test_groth16_proving_and_verification},
    utils::{clone_circuit_data, read_file},
    EVMVerifier, C, D, F,
};
use itertools::Itertools;
use mapreduce_plonky2::{
    api::{deserialize_proof, serialize_proof, ProofWithVK},
    block::{
        empty_merkle_root, PublicInputs as BlockDbPublicInputs,
        NUM_IVC_PUBLIC_INPUTS as BLOCK_DB_NUM_IO,
    },
    eth::{left_pad, left_pad32},
    group_hashing,
    keccak::PACKED_HASH_LEN,
    query2::{
        block::BlockPublicInputs,
        block::NUM_IO as QUERY2_BLOCK_NUM_IO,
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
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitData},
};
use rand::{thread_rng, Rng};
use recursion_framework::framework_testing::TestingRecursiveCircuits;
use serial_test::serial;
use std::{iter::once, path::Path, str::FromStr};

/// Set the number of NFT IDs and block DB depth.
const L: usize = 5;
const BLOCK_DB_DEPTH: usize = 2;

/// The query struct used to check with the plonky2 public inputs in Solidity.
struct Query {
    contract_address: Address,
    user_address: Address,
    client_address: Address,
    min_block_number: u32,
    max_block_number: u32,
    block_hash: U256,
}

impl Query {
    /// Create the test Query data.
    fn new_test() -> Self {
        Self {
            contract_address: Address::repeat_byte(1),
            user_address: Address::repeat_byte(2),
            client_address: Address::repeat_byte(3),
            min_block_number: 100,
            max_block_number: 1000,
            block_hash: U256::MAX,
        }
    }
}

/// Test proving for the query2 circuit.
#[ignore] // Ignore for long running time in CI.
#[serial]
#[test]
fn test_groth16_proving_for_query2() {
    env_logger::init();

    const ASSET_DIR: &str = "groth16_query2";

    // Create the test Query data.
    let query = Query::new_test();

    // Build for the query2 circuit and generate the plonky2 proof.
    let (circuit_data, proof) = plonky2_build_and_prove(ASSET_DIR, &query);

    // Generate the Groth16 asset files.
    compile_and_generate_assets(circuit_data, ASSET_DIR)
        .expect("Failed to generate the Groth16 asset files");

    // Test Groth16 proving, verification and Solidity verification.
    test_groth16_proving_and_verification(ASSET_DIR, &proof);

    // Verify with the Solidity function `respond`.
    // The editing Solidity code is saved in `test_data/query2_verifier.sol`.
    verify_solidity_respond_fun(ASSET_DIR, &query);
}

/// Build for the plonky2 circuit and generate the proof.
fn plonky2_build_and_prove(asset_dir: &str, query: &Query) -> (CircuitData<F, C, D>, Vec<u8>) {
    // Generate a fake query2/block circuit set.
    let query2_testing_framework =
        TestingRecursiveCircuits::<F, C, D, QUERY2_BLOCK_NUM_IO>::default();
    let query2_block_circuit_set = query2_testing_framework.get_recursive_circuit_set();

    // Generate a fake block verification key.
    let block_db_testing_framework =
        TestingRecursiveCircuits::<F, C, D, BLOCK_DB_NUM_IO>::default();
    let block_db_circuit_set = block_db_testing_framework.get_recursive_circuit_set();
    let block_db_vk = block_db_testing_framework.verifier_data_for_input_proofs::<1>()[0];

    // Build the parameters.
    let params = Parameters::<BLOCK_DB_DEPTH, L>::build(
        query2_block_circuit_set,
        block_db_circuit_set,
        block_db_vk,
    );

    // Generate a fake block db proof.
    let init_root = empty_merkle_root::<GoldilocksField, 2, BLOCK_DB_DEPTH>();
    let last_root = HashOut {
        elements: F::rand_vec(NUM_HASH_OUT_ELTS).try_into().unwrap(),
    };
    let init_block_number = F::ONE;
    let last_block_number = F::from_canonical_u32(query.max_block_number + 1);
    let last_block_hash = query
        .block_hash
        .0
        .iter()
        .flat_map(|u| [*u as u32, (u >> 32) as u32].map(F::from_canonical_u32))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let block_db_inputs: [F; BLOCK_DB_NUM_IO] = BlockDbPublicInputs::from_parts(
        &init_root.elements,
        &last_root.elements,
        init_block_number,
        last_block_number,
        &last_block_hash,
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
    // block range asked is just one block less than latest block in db.
    let query_max_number = F::from_canonical_u32(query.max_block_number);
    let query_min_number = F::from_canonical_u32(query.min_block_number);
    let query_range = query_max_number - query_min_number;
    let query_root = HashOut {
        elements: block_db_pi.root_data().try_into().unwrap(),
    };
    let smc_address = query.contract_address;
    let user_address = query.user_address;
    let mapping_slot = F::rand();
    let length_slot = F::rand();
    let mapping_keys = test_mapping_keys();
    let packed_field_mks = mapping_keys
        .iter()
        .map(|x| x.pack().to_fields())
        .collect::<Vec<_>>();

    log::info!("NFT IDs to set before proving: {packed_field_mks:?}");

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
    let q2_proof_buff =
        ProofWithVK::from((query2_block_proof[0].clone(), query2_block_vd[0].clone()))
            .serialize()
            .unwrap();
    let block_db_buff = serialize_proof(block_db_proof).unwrap();

    // Create the revelation input.
    let revelation_inputs = RevelationRecursiveInput::<L>::new(
        mapping_keys.into_iter().map(|x| x.to_vec()).collect(),
        query_min_number.to_canonical_u64() as usize,
        query_max_number.to_canonical_u64() as usize,
        q2_proof_buff,
        block_db_buff,
    )
    .unwrap();

    // Generate the proof.
    let proof = params.generate_proof(revelation_inputs).unwrap();

    // Save the public inputs to a file for debugging.
    save_plonky2_proof_pis(asset_dir, &deserialize_proof(&proof).unwrap());

    // Get the circuit data.
    let circuit_data = clone_circuit_data(params.circuit_data()).unwrap();

    (circuit_data, proof)
}

/// Generate the test mapping keys.
fn test_mapping_keys() -> Vec<[u8; MAPPING_KEY_LEN]> {
    (0..L)
        .map(|i| left_pad::<MAPPING_KEY_LEN>(&[i as u8]))
        .collect()
}

/// Verify the Solidity `respond` function.
fn verify_solidity_respond_fun(asset_dir: &str, query: &Query) {
    let solidity_file_path = Path::new("test_data")
        .join("query2_verifier.sol")
        .to_string_lossy()
        .to_string();

    let contract = Contract::load(
        read_file(Path::new("test_data").join("verifier.abi"))
            .unwrap()
            .as_slice(),
    )
    .expect("Failed to load the Solidity verifier contract from ABI");

    // Read the combined bytes of the full proof.
    let proof_bytes = read_file(Path::new(asset_dir).join("full_proof.bin")).unwrap();
    log_nft_ids(&proof_bytes);

    // Encode to a bytes32 array.
    let data = Token::Array(
        proof_bytes
            .chunks(32)
            .map(|b| Token::FixedBytes(b.to_vec()))
            .collect(),
    );

    let query = Token::Tuple(vec![
        Token::Address(query.contract_address),
        Token::Address(query.user_address),
        Token::Address(query.client_address),
        Token::Uint(query.min_block_number.into()),
        Token::Uint(query.max_block_number.into()),
        Token::Uint(query.block_hash),
    ]);

    // Build the ABI encoded data.
    let args = vec![data, query];
    let fun = &contract.functions["processQuery"][0];
    let calldata = fun
        .encode_input(&args)
        .expect("Failed to encode the inputs of Solidity respond function");

    let verifier =
        EVMVerifier::new(&solidity_file_path).expect("Failed to initialize the EVM verifier");

    let verified = verifier.verify(calldata);
    assert!(verified);
}

/// Log output the NFT IDs from the plonky2 public inputs.
fn log_nft_ids(data: &[u8]) {
    // The total length of the plonky2 public inputs. Each input value is
    // serialized as an uint64. It's related with both the full proof
    // serialization and the wrapped circuit code.
    const PI_TOTAL_LEN: usize = L + 24;

    // The byte offset of the NFT IDS located in the plonky2 public inputs.
    const NFT_IDS_OFFSET_IN_PI: usize = 16;

    // Same code with the Solidity `respond` function for testing.
    let mut pis = [0_u8; PI_TOTAL_LEN * 8];
    for i in 0..PI_TOTAL_LEN * 8 {
        pis[i] = data[352 + i];
    }

    let mut nft_ids = [0_u32; L];
    for i in 0..L {
        let mut chunk = [0_u8; 4];
        for j in 0..4 {
            chunk[j] = pis[(NFT_IDS_OFFSET_IN_PI + i) * 8 + j];
        }
        nft_ids[i] = convert_to_uint32(chunk);
    }

    log::info!("NFT IDs retrieved from the public inputs: {nft_ids:?}");
}

/// Convert 4 bytes to an U32. Same code with Solidity for testing.
fn convert_to_uint32(data: [u8; 4]) -> u32 {
    let mut result = 0_u32;
    for i in 0..4 {
        result |= (data[i] << (8 * i)) as u32;
    }
    return result;
}
