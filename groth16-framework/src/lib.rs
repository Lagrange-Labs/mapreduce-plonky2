//! This framework includes a Groth16 prover and verifier for off-chain proving
//! and verifying, and an EVM verifier for testing Solidity verification.

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
pub use prover::groth16::{Groth16Prover, Groth16ProverConfig};

pub use verifier::{
    // The EVM verifier is used for testing Solidity verification on-chain.
    evm::{EVMVerifier, EVMVerifierConfig},
    // The Groth16 verifier is used to verify the proof off-chain.
    // The asset dir must include `vk.bin` when creating the verifier.
    groth16::{Groth16Verifier, Groth16VerifierConfig},
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{read_file, write_file};
    use ethers::{
        abi::{Contract, Token},
        types::U256,
    };
    use mapreduce_plonky2::{
        array::{Array, Vector, VectorWire},
        group_hashing::CircuitBuilderGroupHashing,
        keccak::{InputData, KeccakCircuit},
        mpt_sequential::PAD_LEN,
    };
    use plonky2::{
        field::types::Field,
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            circuit_data::CircuitData, proof::ProofWithPublicInputs,
        },
    };
    use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
    use rand::{thread_rng, Rng};
    use recursion_framework::serialization::circuit_data_serialization::{
        CustomGateSerializer, CustomGeneratorSerializer,
    };
    use serial_test::serial;
    use std::{array, fs::File, io::Write, marker::PhantomData, path::Path};

    /// Test proving and verifying with a simple circuit.
    #[ignore] // Ignore for long running in CI.
    #[serial]
    #[test]
    fn test_groth16_proving_simple() {
        env_logger::init();

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

        const ASSET_DIR: &str = "groth16_simple";

        // Generate the asset files.
        compile_and_generate_assets(circuit_data, &proof, ASSET_DIR)
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

        const ASSET_DIR: &str = "groth16_keccak";

        // Generate the asset files.
        compile_and_generate_assets(circuit_data, &proof, ASSET_DIR)
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

        const ASSET_DIR: &str = "groth16_group_hashing";

        // Generate the asset files.
        compile_and_generate_assets(circuit_data, &proof, ASSET_DIR)
            .expect("Failed to generate the asset files");

        // Generate the Groth16 proof.
        let groth16_proof = groth16_prove(ASSET_DIR, &proof);

        // Verify the proof off-chain.
        groth16_verify(ASSET_DIR, &groth16_proof);

        // Verify the proof on-chain.
        evm_verify(ASSET_DIR, &groth16_proof);
    }

    /// Test to generate the proof.
    fn groth16_prove(asset_dir: &str, proof: &ProofWithPublicInputs<F, C, D>) -> Groth16Proof {
        let config = Groth16ProverConfig {
            asset_dir: asset_dir.to_string(),
        };

        let prover = Groth16Prover::new(config).expect("Failed to initialize the prover");

        let proof = prover.prove(proof).expect("Failed to generate the proof");
        let json_proof = serde_json::to_string(&proof).expect("Failed to serialize the proof");
        write_file(
            Path::new(asset_dir).join("proof.json"),
            json_proof.as_bytes(),
        )
        .expect("Failed to write the proof");

        proof
    }

    /// Test to verify the proof.
    fn groth16_verify(asset_dir: &str, proof: &Groth16Proof) {
        let config = Groth16VerifierConfig {
            asset_dir: asset_dir.to_string(),
        };

        let verifier = Groth16Verifier::new(config).expect("Failed to initialize the verifier");

        verifier.verify(proof).expect("Failed to verify the proof")
    }

    /// Test the Solidity verification.
    fn evm_verify(asset_dir: &str, proof: &Groth16Proof) {
        let config = EVMVerifierConfig {
            solidity_path: Path::new(asset_dir)
                .join("verifier.sol")
                .to_string_lossy()
                .to_string(),
        };

        let contract = Contract::load(
            utils::read_file(Path::new("test_data").join("verifier.abi"))
                .unwrap()
                .as_slice(),
        )
        .expect("Failed to load the Solidity verifier contract from ABI");

        let [proofs, inputs] = [&proof.proofs, &proof.inputs]
            .map(|ss| ss.iter().map(|s| Token::Uint(str_to_u256(s))).collect());
        let input = vec![Token::FixedArray(proofs), Token::FixedArray(inputs)];
        let verify_fun = &contract.functions["verifyProof"][0];
        let calldata = verify_fun
            .encode_input(&input)
            .expect("Failed to encode the inputs of Solidity contract function verifyProof");

        let verifier = EVMVerifier::new(config).expect("Failed to initialize the EVM verifier");

        let verified = verifier.verify(calldata);
        assert!(verified);
    }

    /// Convert a string to U256.
    fn str_to_u256(s: &str) -> U256 {
        let s = s.strip_prefix("0x").unwrap();
        U256::from_str_radix(s, 16).unwrap()
    }
}
