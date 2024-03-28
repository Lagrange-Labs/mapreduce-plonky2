//! Test the Groth16 proving process for the query2 circuit.

use anyhow::Result;
use ethers::abi::{Contract, Token};
use ethers::types::Address;
use groth16_framework::{
    compile_and_generate_assets,
    prover::groth16::combine_proofs,
    test_utils::{evm_verify, groth16_prove, groth16_verify, write_plonky2_proof_pis},
    utils::{clone_circuit_data, hex_to_u256, read_file, write_file},
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
use mapreduce_plonky2::{
    array::{Array, Vector, VectorWire},
    group_hashing::CircuitBuilderGroupHashing,
    keccak::{InputData, KeccakCircuit},
    mpt_sequential::PAD_LEN,
};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64, Sample},
    },
    hash::hash_types::{HashOut, NUM_HASH_OUT_ELTS},
    plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
};
use plonky2::{
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, circuit_data::CircuitData,
        proof::ProofWithPublicInputs,
    },
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use rand::{thread_rng, Rng};
use recursion_framework::framework_testing::TestingRecursiveCircuits;
use recursion_framework::serialization::circuit_data_serialization::{
    CustomGateSerializer, CustomGeneratorSerializer,
};
use serial_test::serial;
use std::iter::once;
use std::{array, fs::File, io::Write, marker::PhantomData, path::Path};
use std::{fs::metadata, io::Read, time::Instant};

/// gupeng
const L: usize = 5;
const BLOCK_DB_DEPTH: usize = 2;

/// Test proving and verifying for the query2 circuit.
// #[ignore] // Ignore for long running in CI.
#[serial]
#[test]
fn test_groth16_proving_for_query2() {
    env_logger::init();

    const ASSET_DIR: &str = "groth16_query2";

    // Get the query2 proving result.
    let (circuit_data, plonky2_proof) = query2_prove(ASSET_DIR);

    // Generate the Groth16 asset files.
    compile_and_generate_assets(circuit_data, ASSET_DIR)
        .expect("Failed to generate the Groth16 asset files");

    // Generate the Groth16 proof.
    let groth16_proof = groth16_prove(ASSET_DIR, &plonky2_proof);

    // Verify the Groth16 proof off-chain.
    groth16_verify(ASSET_DIR, &groth16_proof);

    // Verify the Groth16 proof on-chain.
    evm_verify(ASSET_DIR, &groth16_proof);

    // Verify with the Solidity function `respond`.
    evm_verify_respond_fun(ASSET_DIR);
}

/// Prove for the query2 circuit.
fn query2_prove(asset_dir: &str) -> (CircuitData<F, C, D>, Vec<u8>) {
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
    // block range asked is just one block less than latest block in db.
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
    write_plonky2_proof_pis(asset_dir, &deserialize_proof(&proof).unwrap());

    // Get the circuit data.
    let circuit_data = clone_circuit_data(params.circuit_data()).unwrap();

    (circuit_data, proof)
}

/// Verify with the Solidity function `respond`.
fn evm_verify_respond_fun(asset_dir: &str) {
    let solidity_file_path = Path::new(asset_dir)
        .join("verifier.sol")
        .to_string_lossy()
        .to_string();

    let contract = Contract::load(
        read_file(Path::new(asset_dir).join("verifier.abi"))
            .unwrap()
            .as_slice(),
    )
    .expect("Failed to load the Solidity verifier contract from ABI");

    let bytes = read_file(Path::new(asset_dir).join("full_proof.bin")).unwrap();
    let bytes = bytes.into_iter().map(|b| Token::Uint(b.into())).collect();
    let results = vec![Token::Array(bytes)];
    let verify_fun = &contract.functions["respond"][0];
    let calldata = verify_fun
        .encode_input(&results)
        .expect("Failed to encode the inputs of Solidity contract function respond");

    let verifier =
        EVMVerifier::new(&solidity_file_path).expect("Failed to initialize the EVM verifier");

    let verified = verifier.verify(calldata);
    assert!(verified);
}
