//! This framework implements the Groth16 prover and verifier. The prover
//! generates a `wrapped` proof from the normal plonky2 proof, then employs
//! a Groth16 prover process of gnark-plonky2-verifier to generate a Groth16
//! proof which could be verified by a Solidity contract of verifier. The
//! Solidity verifier could also be generated for optional during the proving
//! process.

use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

mod evm;
mod proof;
mod prover;
mod utils;
mod verifier;

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

pub use proof::Groth16Proof;
pub use prover::groth16_prover::{Groth16Prover, Groth16ProverConfig};
pub use verifier::evm_verifier::{EVMVerifier, EVMVerifierConfig};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        prover::groth16_prover::{GROTH16_PROOF_FILE, VERIFIER_CONRTACT_FILE},
        utils::read_file,
    };
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
    use serial_test::serial;
    use std::{array, path::Path};

    /// Test proving with a simple circuit.
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

        let data = cb.build::<C>();
        let proof = data.prove(pw).unwrap();

        groth16_prove(data, proof);
        evm_verify();
    }

    /// Test proving with the keccak circuit.
    #[ignore] // Ignore for fast CI.
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

        let data = cb.build::<C>();
        let proof = data.prove(pw).unwrap();

        groth16_prove(data, proof);
    }

    /// Test proving with the group-hashing circuit.
    #[ignore] // Ignore for fast CI.
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

        let data = cb.build::<C>();
        let proof = data.prove(pw).unwrap();

        groth16_prove(data, proof);
    }

    /// Test to prove and generate Solidity verifier.
    fn groth16_prove(circuit_data: CircuitData<F, C, D>, proof: ProofWithPublicInputs<F, C, D>) {
        let config = Groth16ProverConfig {
            prover_cmd: Path::new("gnark-plonky2-verifier")
                .join("prover")
                .to_string_lossy()
                .to_string(),
            data_dir: ".".to_string(),
            circuit_data: Some(circuit_data),
        };

        let prover = Groth16Prover::new(config);

        let proof = prover
            .prove_and_generate_contract(&proof, true)
            .expect("Failed to prove and generate Solidity verifier");
    }

    /// Test EVM verification.
    fn evm_verify() {
        let proof = Groth16Proof::from_file(GROTH16_PROOF_FILE).unwrap();

        let config = EVMVerifierConfig {
            solidity_path: VERIFIER_CONRTACT_FILE.to_string(),
        };

        let contract = Contract::load(
            utils::read_file(Path::new("resources").join("verifier.abi"))
                .unwrap()
                .as_slice(),
        )
        .expect("Failed to load verifier contract from ABI");

        let [proofs, inputs] = [proof.proofs, proof.inputs]
            .map(|ss| ss.iter().map(|s| Token::Uint(str_to_u256(s))).collect());
        let input = vec![Token::FixedArray(proofs), Token::FixedArray(inputs)];
        let verify_fun = &contract.functions["verifyProof"][0];
        let calldata = verify_fun
            .encode_input(&input)
            .expect("Failed to encode the inputs of contract function verifyProof");

        let verifier = EVMVerifier::new(config).expect("Failed to create EVM verifier");

        let verified = verifier.verify(calldata);
        assert!(verified);
    }

    /// Convert a string to U256.
    fn str_to_u256(s: &str) -> U256 {
        let s = s.strip_prefix("0x").unwrap();
        U256::from_str_radix(s, 16).unwrap()
    }
}
