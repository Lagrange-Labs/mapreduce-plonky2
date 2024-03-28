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

use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

mod compiler;
mod evm;
mod proof;
mod prover;
mod utils;
mod verifier;

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

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

pub use utils::clone_circuit_data;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        prover::groth16::combine_proofs,
        utils::{hex_to_u256, read_file, write_file},
    };
    use ethers::{
        abi::{Contract, Token},
        types::U256,
    };
    use mapreduce_plonky2::{
        api::{deserialize_proof, serialize_proof},
        array::{Array, Vector, VectorWire},
        group_hashing::CircuitBuilderGroupHashing,
        keccak::{InputData, KeccakCircuit},
        mpt_sequential::PAD_LEN,
    };
    use plonky2::{
        field::types::{Field, PrimeField64},
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
    };
    use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
    use rand::{thread_rng, Rng};

    use serial_test::serial;
    use std::{array, path::Path};

    /// Test proving and verifying with a simple circuit.
    // #[ignore] // Ignore for long running in CI.
    #[serial]
    #[test]
    fn test_groth16_proving_simple() {
        env_logger::init();

        const ASSET_DIR: &str = "groth16_simple";

        let config = CircuitConfig::standard_recursion_config();
        let mut cb = CircuitBuilder::<F, D>::new(config);

        let [a, b] = [0; 2].map(|_| cb.add_virtual_target());
        let c = cb.add(a, b);

        cb.register_public_input(c);

        let mut pw = PartialWitness::new();
        let inputs = thread_rng().gen::<[u32; 2]>().map(F::from_canonical_u32);
        pw.set_target(a, inputs[0]);
        pw.set_target(b, inputs[1]);

        let circuit_data = cb.build::<C>();
        let proof = circuit_data.prove(pw).unwrap();
        write_plonky2_proof_pis(ASSET_DIR, &proof);
        let proof = serialize_proof(&proof).unwrap();

        // Generate the asset files.
        compile_and_generate_assets(circuit_data, ASSET_DIR)
            .expect("Failed to generate the asset files");

        // Generate the Groth16 proof.
        let groth16_proof = groth16_prove(ASSET_DIR, &proof);

        // Verify the proof off-chain.
        groth16_verify(ASSET_DIR, &groth16_proof);

        // Verify the proof on-chain.
        evm_verify(ASSET_DIR, &groth16_proof);
    }

    /// Test proving with the keccak circuit.
    #[ignore] // Ignore for long running in CI.
    #[serial]
    #[test]
    fn test_groth16_proving_with_keccak() {
        env_logger::init();

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
        let proof = serialize_proof(&proof).unwrap();

        const ASSET_DIR: &str = "groth16_keccak";

        // Generate the asset files.
        compile_and_generate_assets(circuit_data, ASSET_DIR)
            .expect("Failed to generate the asset files");

        // Generate the Groth16 proof.
        let groth16_proof = groth16_prove(ASSET_DIR, &proof);

        // Verify the proof off-chain.
        groth16_verify(ASSET_DIR, &groth16_proof);

        // Verify the proof on-chain.
        evm_verify(ASSET_DIR, &groth16_proof);
    }

    /// Test proving with the group-hashing circuit.
    #[ignore] // Ignore for long running in CI.
    #[serial]
    #[test]
    fn test_groth16_proving_with_group_hashing() {
        env_logger::init();

        let config = CircuitConfig::standard_recursion_config();
        let mut cb = CircuitBuilder::<F, D>::new(config);

        let inputs = [0; 8].map(|_| cb.add_virtual_target());
        let a = cb.map_to_curve_point(&inputs[..4]);
        let b = cb.map_to_curve_point(&inputs[4..]);
        let c = cb.add_curve_point(&[a, b]);

        // Register the public inputs twice for testing.
        cb.register_curve_public_input(c);
        cb.register_curve_public_input(c);

        let mut pw = PartialWitness::new();
        let mut rng = thread_rng();
        inputs
            .into_iter()
            .zip([0; 8].map(|_| F::from_canonical_u64(rng.gen())))
            .for_each(|(t, v)| pw.set_target(t, v));

        let circuit_data = cb.build::<C>();
        let proof = circuit_data.prove(pw).unwrap();
        let proof = serialize_proof(&proof).unwrap();

        const ASSET_DIR: &str = "groth16_group_hashing";

        // Generate the asset files.
        compile_and_generate_assets(circuit_data, ASSET_DIR)
            .expect("Failed to generate the asset files");

        // Generate the Groth16 proof.
        let groth16_proof = groth16_prove(ASSET_DIR, &proof);

        // Verify the proof off-chain.
        groth16_verify(ASSET_DIR, &groth16_proof);

        // Verify the proof on-chain.
        evm_verify(ASSET_DIR, &groth16_proof);
    }

    /// Test to generate the proof.
    fn groth16_prove(asset_dir: &str, plonky2_proof: &[u8]) -> Groth16Proof {
        // Initialize the Groth16 prover.
        let prover = Groth16Prover::new(asset_dir).expect("Failed to initialize the prover");

        // Construct the file paths to save the Groth16 and full proofs.
        let groth16_proof_path = Path::new(asset_dir).join("groth16_proof.json");
        let full_proof_path = Path::new(asset_dir).join("full_proof.bin");

        // Generate the Groth16 proof.
        let plonky2_proof = deserialize_proof(plonky2_proof).unwrap();
        let groth16_proof = prover
            .generate_groth16_proof(&plonky2_proof)
            .expect("Failed to generate the proof");
        write_file(
            groth16_proof_path,
            serde_json::to_string(&groth16_proof).unwrap().as_bytes(),
        )
        .unwrap();

        // Generate the full proof.
        let full_proof = combine_proofs(groth16_proof.clone(), plonky2_proof).unwrap();
        write_file(full_proof_path, &full_proof).unwrap();

        groth16_proof
    }

    /// Test to verify the proof.
    fn groth16_verify(asset_dir: &str, proof: &Groth16Proof) {
        let verifier = Groth16Verifier::new(asset_dir).expect("Failed to initialize the verifier");

        verifier.verify(proof).expect("Failed to verify the proof")
    }

    /// Test the Solidity verification.
    fn evm_verify(asset_dir: &str, proof: &Groth16Proof) {
        let solidity_file_path = Path::new(asset_dir)
            .join("verifier.sol")
            .to_string_lossy()
            .to_string();

        let contract = Contract::load(
            utils::read_file(Path::new("test_data").join("verifier.abi"))
                .unwrap()
                .as_slice(),
        )
        .expect("Failed to load the Solidity verifier contract from ABI");

        let [proofs, inputs] = [&proof.proofs, &proof.inputs].map(|ss| {
            ss.iter()
                .map(|s| Token::Uint(hex_to_u256(s).unwrap()))
                .collect()
        });
        let input = vec![Token::FixedArray(proofs), Token::FixedArray(inputs)];
        let verify_fun = &contract.functions["verifyProof"][0];
        let calldata = verify_fun
            .encode_input(&input)
            .expect("Failed to encode the inputs of Solidity contract function verifyProof");

        let verifier =
            EVMVerifier::new(&solidity_file_path).expect("Failed to initialize the EVM verifier");

        let verified = verifier.verify(calldata);
        assert!(verified);
    }

    /// Convert the plonky2 proof public inputs to bytes and write to a file.
    fn write_plonky2_proof_pis(dir: &str, proof: &ProofWithPublicInputs<F, C, D>) {
        let file_path = Path::new(dir).join("plonky2_proof_pis.bin");

        let bytes: Vec<_> = proof
            .public_inputs
            .iter()
            .flat_map(|f| f.to_canonical_u64().to_le_bytes())
            .collect();

        write_file(file_path, &bytes).unwrap();
    }

    #[test]
    fn test_solidity_verify() {
        let asset_dir = "groth16_simple";
        let solidity_file_path = Path::new(asset_dir)
            .join("verifier.sol")
            .to_string_lossy()
            .to_string();

        let contract = Contract::load(
            utils::read_file(Path::new(asset_dir).join("verifier.abi"))
                .unwrap()
                .as_slice(),
        )
        .expect("Failed to load the Solidity verifier contract from ABI");

        let bytes = utils::read_file(Path::new(asset_dir).join("full_proof.bin")).unwrap();
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
}
