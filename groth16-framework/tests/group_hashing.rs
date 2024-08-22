//! Test the Groth16 proving process for the Group Hashing circuit.

use groth16_framework::{
    compile_and_generate_assets, test_utils::test_groth16_proving_and_verification, C,
};
use mp2_common::{group_hashing::CircuitBuilderGroupHashing, proof::serialize_proof, D, F};
use plonky2::{
    field::types::Field,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
    },
};
use rand::{thread_rng, Rng};
use serial_test::serial;

/// Test proving for the group-hashing circuit.
#[ignore] // Ignore for long running time in CI.
#[serial]
#[test]
fn test_groth16_proving_for_group_hashing() {
    env_logger::init();

    const ASSET_DIR: &str = "groth16_group_hashing";

    // Build for the Group Hashing circuit and generate the plonky2 proof.
    let (circuit_data, proof) = plonky2_build_and_prove();

    // Generate the asset files.
    compile_and_generate_assets(circuit_data, ASSET_DIR)
        .expect("Failed to generate the asset files");

    // Test Groth16 proving, verification and Solidity verification.
    test_groth16_proving_and_verification(ASSET_DIR, &proof);
}

/// Build for the plonky2 circuit and generate the proof.
fn plonky2_build_and_prove() -> (CircuitData<F, C, D>, Vec<u8>) {
    let config = CircuitConfig::standard_recursion_config();
    let mut cb = CircuitBuilder::<F, D>::new(config);

    let inputs = [0; 8].map(|_| cb.add_virtual_target());
    let a = cb.map_to_curve_point(&inputs[..4]);
    let b = cb.map_to_curve_point(&inputs[4..]);
    let _c = cb.add_curve_point(&[a, b]);

    // TODO: We restrict the fields of public inputs must be within the range of
    // Uint32 for sha256 of Groth16.
    // Register the public inputs twice for testing.
    // cb.register_curve_public_input(c);
    // cb.register_curve_public_input(c);

    let mut pw = PartialWitness::new();
    let mut rng = thread_rng();
    inputs
        .into_iter()
        .zip([0; 8].map(|_| F::from_canonical_u64(rng.gen())))
        .for_each(|(t, v)| pw.set_target(t, v));

    let circuit_data = cb.build::<C>();
    let proof = circuit_data.prove(pw).unwrap();
    let proof = serialize_proof(&proof).unwrap();

    (circuit_data, proof)
}
