//! This framework includes a Groth16 prover and verifier for off-chain proving
//! and verifying, and an EVM verifier for testing Solidity verification.
//!
//! The Groth16 proving process has 3 main steps:
//!
//! 1. Generate the asset files.
//!
//!    The asset files are `circuit.bin`, `r1cs.bin`, `pk.bin`, `vk.bin` and
//!    `verifier.sol`. User could call the `compile_and_generate_assets`
//!    function to generate these files as below.
//!
//!    ``
//!    use groth16_framework::clone_circuit_data;
//!    use groth16_framework::compile_and_generate_assets;
//!
//!    // Get the reference of circuit data and clone it by the
//!    // `clone_circuit_data` function.
//!    let circuit_data = parameters.final_proof_circuit_data();
//!    let circuit_data = clone_circuit_data(circuit_data);
//!
//!    // Generate the asset files into the specified asset dir. This function
//!    // creates the asset dir if not exist.
//!    compile_and_generate_assets(circuit_data, asset_dir);
//!    ``
//!
//!    After that, the asset files should be generated in the specified dir.
//!
//! 2. Initialize the Groth16 prover
//!
//!    We must download the above asset files to the dir before initializing the
//!    Groth16 prover. After initialization, this prover could be reused to
//!    generate the Groth16 proofs. It's initialized as below.
//!
//!    ``
//!    use groth16_framework::Groth16Prover;
//!
//!    // Create the Groth16 prover.
//!    let groth16_prover = Groth16Prover::new(asset_dir);
//!    ``
//!
//! 3. Prove the normal proofs of mapreduce-plonky2
//!
//!    This proving step could be called for mulitple times to generate the
//!    Groth16 proofs. It's called as below.
//!
//!    ``
//!    // Get the normal proof of mapreduce-plonky2.
//!    let normal_proof = parameters.generate_proof();
//!
//!    // Generate the proof. Return the bytes of serialized JSON Groth16 proof.
//!    let groth16_proof = groth16_prover.prove(normal_proof);
//!    ``
//!
//! The Groth16 verifying process is similar as the above proving steps. It
//! could called as below.
//!
//!    ``
//!    use groth16_framework::Groth16Verifier;
//!
//!    // Create the Groth16 verifier.
//!    let groth16_verifier = Groth16Verifier::new(asset_dir);
//!
//!    // Verify the Groth16 proofs.
//!    groth16_verifier.verify(groth16_proof1);
//!    groth16_verifier.verify(groth16_proof2);
//!    ``

use plonky2::plonk::config::PoseidonGoldilocksConfig;

mod compiler;
mod evm;
mod proof;
pub mod prover;
pub mod test_utils;
pub mod utils;
mod verifier;

// The function is used to generate the asset files of `circuit.bin`,
// `r1cs.bin`, `pk.bin`, `vk.bin` and `verifier.sol`. It's only necessary to be
// called for re-generating these asset files when the circuit code changes.
pub use compiler::compile_and_generate_assets;

// The exported Groth16 proof struct
pub use proof::Groth16Proof;

// The Groth16 prover is used to generate the proof which could be verified
// both off-chain and on-chain.
// The asset dir must include `circuit.bin`, `r1cs.bin` and `pk.bin` when
// creating the prover.
pub use prover::groth16::Groth16Prover;

pub use verifier::{
    // The EVM verifier is used for testing Solidity verification on-chain.
    evm::EVMVerifier,
    // The Groth16 verifier is used to verify the proof off-chain.
    // The asset dir must include `vk.bin` when creating the verifier.
    groth16::Groth16Verifier,
};

pub type C = PoseidonGoldilocksConfig;

// Reference more test cases in the `tests` folder.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        evm_verify_on_groth16_proof_file, test_groth16_proving_and_verification,
    };
    use mp2_common::{proof::serialize_proof, D, F};
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

    const ASSET_DIR: &str = "groth16_simple";

    /// Test the verification on a local file of generated Groth16 proof for the simple circuit.
    #[ignore] // Ignore in CI, since it could only run for local test.
    #[serial]
    #[test]
    fn test_groth16_simple_local_verification() {
        evm_verify_on_groth16_proof_file(ASSET_DIR);
    }

    /// Test proving and verifying with a simple circuit.
    // #[ignore] // Ignore for long running time in CI.
    #[serial]
    #[test]
    fn test_groth16_proving_simple() {
        env_logger::init();

        // Build for the simple circuit and generate the plonky2 proof.
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

        let [a, b] = [0; 2].map(|_| cb.add_virtual_target());
        let c = cb.add(a, b);

        cb.register_public_input(c);

        let mut pw = PartialWitness::new();
        let inputs = thread_rng()
            .gen::<[u16; 2]>()
            .map(|u| F::from_canonical_u32(u as u32));
        pw.set_target(a, inputs[0]);
        pw.set_target(b, inputs[1]);

        let circuit_data = cb.build::<C>();
        let proof = circuit_data.prove(pw).unwrap();
        let proof = serialize_proof(&proof).unwrap();

        (circuit_data, proof)
    }
}
