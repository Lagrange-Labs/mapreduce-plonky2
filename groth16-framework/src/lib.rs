//! This framework implements the Groth16 prover and verifier. The prover
//! generates a `wrapped` proof from the normal plonky2 proof, then employs
//! a Groth16 prover process of gnark-plonky2-verifier to generate a Groth16
//! proof which could be verified by a Solidity contract of verifier. The
//! Solidity verifier could also be generated for optional during the proving
//! process.

use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

mod proof;
mod prover;
mod verifier;

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

pub use prover::{Groth16Prover, Groth16ProverConfig};

#[cfg(test)]
mod tests {
    use super::*;
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
    use std::array;

    /// Test proving with a simple circuit.
    #[serial]
    #[test]
    fn test_groth16_proving_simple() {
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
    }

    /// Test proving with the keccak circuit.
    #[serial]
    #[test]
    fn test_groth16_proving_with_keccak() {
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
    #[serial]
    #[test]
    fn test_groth16_proving_with_group_hashing() {
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
            prover_cmd: "gnark-plonky2-verifier/prover".to_string(),
            data_dir: ".".to_string(),
            circuit_data: Some(circuit_data),
        };

        let prover = Groth16Prover::new(config);

        prover
            .prove_and_generate_contract(&proof, true)
            .expect("Failed to prove and generate Solidity verifier");
    }
}
