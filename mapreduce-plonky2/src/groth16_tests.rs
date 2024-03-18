use crate::{
    array::{Array, Vector, VectorWire},
    group_hashing::CircuitBuilderGroupHashing,
    keccak::{InputData, KeccakCircuit},
    mpt_sequential::PAD_LEN,
};
use plonky2::{
    field::extension::Extendable,
    field::types::{Field, Sample},
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_data::CircuitData,
    plonk::proof::ProofWithPublicInputs,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};
use plonky2_ecgfp5::{
    curve::curve::Point, gadgets::curve::CircuitBuilderEcGFp5, gadgets::curve::PartialWitnessCurve,
};
use plonky2x::backend::circuit::config::{DefaultParameters, Groth16WrapperParameters};
use plonky2x::backend::wrapper::wrap::WrappedCircuit;
use rand::{thread_rng, Rng};
use std::array;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type L = DefaultParameters;

// Only for test.
pub fn convert_u64_targets_to_u8<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    // TODO: range check
    data: &[Target],
) -> Vec<Target> {
    let four = b.constant(F::from_canonical_usize(4));
    let four_square = b.constant(F::from_canonical_usize(16));
    let four_cube = b.constant(F::from_canonical_usize(64));

    // Convert each u64 to [u8; 8].
    data.iter()
        .flat_map(|u64_element| {
            // Convert an u64 to [u2; 32], each limb is an u2, it means
            // BASE is 4 (2^2), and total 32 limbs.
            let u2_elements = b.split_le_base::<4>(*u64_element, 32);

            // Convert each [u2; 4] to an u8 as:
            // u[0] + u[1] * 4 + u[2] * 16 + u[3] * 64
            u2_elements
                .chunks(4)
                .map(|u| {
                    // acc = u[0] + u[1] * 4
                    let acc = b.mul_add(u[1], four, u[0]);
                    // acc += [u2] * 4^2
                    let acc = b.mul_add(u[2], four_square, acc);
                    // acc += [u3] * 4^3
                    b.mul_add(u[3], four_cube, acc)
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

pub fn gen_groth16_proof(data: CircuitData<F, C, D>, proof: &ProofWithPublicInputs<F, C, D>) {
    let wrapper: WrappedCircuit<_, _, 2> =
        WrappedCircuit::<L, Groth16WrapperParameters, D>::build_from_raw_data(data);
    let wrapped_proof = wrapper.prove(proof).unwrap();

    let pi = serde_json::to_string_pretty(&wrapped_proof.proof).unwrap();
    std::fs::write("proof_with_public_inputs.json", pi).unwrap();

    let common = serde_json::to_string_pretty(&wrapped_proof.common_data).unwrap();
    std::fs::write("common_circuit_data.json", common).unwrap();

    let vk = serde_json::to_string_pretty(&wrapped_proof.verifier_data).unwrap();
    std::fs::write("verifier_only_circuit_data.json", vk).unwrap();
}

fn simple() {
    let config = CircuitConfig::standard_recursion_config();
    let mut cb = CircuitBuilder::<F, D>::new(config);

    let [a, b] = [0; 2].map(|_| cb.add_virtual_target());
    let c = cb.add(a, b);

    cb.register_public_input(c);
    cb.register_public_input(c);

    let mut pw = PartialWitness::new();
    pw.set_target(a, F::ZERO);
    pw.set_target(b, F::ONE);

    let data = cb.build::<C>();
    let proof = data.prove(pw).unwrap();

    gen_groth16_proof(data, &proof);
}

fn keccak() {
    let config = CircuitConfig::standard_recursion_config();
    let mut cb = CircuitBuilder::<F, D>::new(config);

    const KLEN: usize = 10;
    const PAD_KLEN: usize = PAD_LEN(KLEN);

    let arr = Array::new(&mut cb);
    let v = VectorWire::<Target, PAD_KLEN> {
        real_len: cb.constant(F::from_canonical_usize(KLEN)),
        arr: arr.clone(),
    };
    let k = KeccakCircuit::hash_vector(&mut cb, &v);

    let mut pw = PartialWitness::new();
    let data = array::from_fn(|_| thread_rng().gen::<u8>());
    arr.assign(&mut pw, &data.map(F::from_canonical_u8));
    KeccakCircuit::<PAD_KLEN>::assign(
        &mut pw,
        &k,
        &InputData::Assigned(&Vector::from_vec(&data).unwrap()),
    );

    let data = cb.build::<C>();
    let proof = data.prove(pw).unwrap();

    gen_groth16_proof(data, &proof);
}

fn group_hashing_add() {
    let mut config = CircuitConfig::standard_recursion_config();
    let mut cb = CircuitBuilder::<F, D>::new(config);

    let a = cb.add_virtual_curve_target();
    let b = cb.add_virtual_curve_target();
    let c = cb.add_curve_point(&[a, b]);

    // Register twice for test.
    cb.register_curve_public_input(c);
    cb.register_curve_public_input(c);

    let mut pw = PartialWitness::new();
    let mut rng = thread_rng();
    pw.set_curve_target(a, Point::sample(&mut rng).to_weierstrass());
    pw.set_curve_target(b, Point::sample(&mut rng).to_weierstrass());

    let data = cb.build::<C>();
    let proof = data.prove(pw).unwrap();

    gen_groth16_proof(data, &proof);
}

fn group_hashing_map() {
    let config = CircuitConfig::standard_recursion_config();
    let mut cb = CircuitBuilder::<F, D>::new(config);

    let inputs = [0; 2].map(|_| cb.add_virtual_target());
    let output = cb.map_to_curve_point(&inputs);

    // Register twice for test.
    cb.register_curve_public_input(output);
    cb.register_curve_public_input(output);

    let mut pw = PartialWitness::new();
    let mut rng = thread_rng();
    inputs
        .into_iter()
        .zip([0; 2].map(|_| F::from_canonical_u64(rng.gen())))
        .for_each(|(it, iv)| pw.set_target(it, iv));

    let data = cb.build::<C>();
    let proof = data.prove(pw).unwrap();

    gen_groth16_proof(data, &proof);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_groth16_simple() {
        simple();
    }

    #[test]
    fn test_groth16_keccak() {
        keccak();
    }

    #[test]
    fn test_groth16_group_hashing_add() {
        group_hashing_add();
    }

    #[test]
    fn test_groth16_group_hashing_map() {
        group_hashing_map();
    }
}
