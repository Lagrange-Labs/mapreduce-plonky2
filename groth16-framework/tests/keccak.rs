//! Test the Groth16 proving process for the Keccak circuit.

use groth16_framework::{
    compile_and_generate_assets,
    test_utils::{save_plonky2_proof_pis, test_groth16_proving_and_verification},
    C, D, F,
};
use mapreduce_plonky2::{
    api::serialize_proof,
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakCircuit},
    mpt_sequential::PAD_LEN,
};
use plonky2::{
    field::types::Field,
    iop::{target::Target, witness::PartialWitness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
    },
};
use rand::{thread_rng, Rng};
use serial_test::serial;
use std::array;

/// Test proving for the keccak circuit.
#[ignore] // Ignore for long running time in CI.
#[serial]
#[test]
fn test_groth16_proving_for_keccak() {
    env_logger::init();

    const ASSET_DIR: &str = "groth16_keccak";

    // Build for the Keccak circuit and generate the plonky2 proof.
    let (circuit_data, proof) = plonky2_build_and_prove(ASSET_DIR);

    // Generate the asset files.
    compile_and_generate_assets(circuit_data, ASSET_DIR)
        .expect("Failed to generate the asset files");

    // Test Groth16 proving, verification and Solidity verification.
    test_groth16_proving_and_verification(ASSET_DIR, &proof);
}

/// Build for the plonky2 circuit and generate the proof.
fn plonky2_build_and_prove(asset_dir: &str) -> (CircuitData<F, C, D>, Vec<u8>) {
    let config = CircuitConfig::standard_recursion_config();
    let mut cb = CircuitBuilder::<F, D>::new(config);

    const REAL_LEN: usize = 10;
    const PADDED_LEN: usize = PAD_LEN(REAL_LEN);

    let arr = Array::new(&mut cb);
    let v = VectorWire::<Target, PADDED_LEN> {
        real_len: cb.constant(F::from_canonical_usize(REAL_LEN)),
        arr: arr.clone(),
    };
    let k = KeccakCircuit::hash_vector(&mut cb, &v);

    let mut pw = PartialWitness::new();
    let inputs = array::from_fn(|_| thread_rng().gen::<u8>());
    arr.assign(&mut pw, &inputs.map(F::from_canonical_u8));
    KeccakCircuit::<PADDED_LEN>::assign(
        &mut pw,
        &k,
        &InputData::Assigned(&Vector::from_vec(&inputs).unwrap()),
    );

    let circuit_data = cb.build::<C>();
    let proof = circuit_data.prove(pw).unwrap();
    save_plonky2_proof_pis(asset_dir, &proof);
    let proof = serialize_proof(&proof).unwrap();

    (circuit_data, proof)
}
