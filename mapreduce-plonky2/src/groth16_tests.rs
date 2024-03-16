use crate::{
    array::{Array, Vector, VectorWire},
    group_hashing::CircuitBuilderGroupHashing,
    keccak::{InputData, KeccakCircuit, KeccakWires, OutputByteHash, OutputHash},
    mpt_sequential::PAD_LEN,
};
use anyhow::Result;
use ethers::utils::keccak256;
use plonky2::{
    field::extension::Extendable,
    field::types::{Field, Sample},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_data::CircuitData,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
    plonk::{
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        proof::{CompressedProofWithPublicInputs, ProofWithPublicInputs},
    },
};
use plonky2_crypto::hash::{
    keccak256::{CircuitBuilderHashKeccak, WitnessHashKeccak, KECCAK256_R},
    CircuitBuilderHash,
};
use plonky2_ecgfp5::{
    curve::curve::Point,
    curve::curve::WeierstrassPoint,
    gadgets::{
        base_field::CircuitBuilderGFp5,
        curve::{CircuitBuilderEcGFp5, CurveTarget},
    },
    gadgets::{base_field::PartialWitnessQuinticExt, curve::PartialWitnessCurve},
};
use plonky2x::backend::circuit::config::{DefaultParameters, Groth16WrapperParameters};
use plonky2x::backend::circuit::CircuitBuild;
use plonky2x::backend::wrapper::wrap::WrappedCircuit;
use plonky2x::prelude::CircuitBuilder as CBuilder;
use rand::{thread_rng, Rng, RngCore};
use std::array;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type L = DefaultParameters;

fn gen_groth16_proof(data: CircuitData<F, C, D>, proof: ProofWithPublicInputs<F, C, D>) {
    let mut builder = CBuilder::<L, D>::new();
    builder.pre_build();
    let async_hints = CBuilder::<L, D>::async_hint_map(
        data.prover_only.generators.as_slice(),
        builder.async_hints,
    );

    let circuit = CircuitBuild {
        data,
        io: builder.io,
        async_hints,
    };

    let wrapper: WrappedCircuit<_, _, 2> =
        WrappedCircuit::<L, Groth16WrapperParameters, D>::build(circuit);
    let wrapped_proof = wrapper.prove(&proof).unwrap();

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

    let mut pw = PartialWitness::new();
    pw.set_target(a, F::ZERO);
    pw.set_target(b, F::ONE);
    pw.set_target(c, F::ONE);

    let data = cb.build::<C>();
    let proof = data.prove(pw).unwrap();

    gen_groth16_proof(data, proof);
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

    gen_groth16_proof(data, proof);
}

fn group_hashing_add() {
    let config = CircuitConfig::standard_recursion_config();
    let mut cb = CircuitBuilder::<F, D>::new(config);

    let inputs = [0; 2].map(|_| cb.add_virtual_curve_target());
    let output = cb.add_curve_point(&inputs);
    cb.register_curve_public_input(output);
    inputs
        .into_iter()
        .for_each(|it| cb.register_curve_public_input(it));

    let mut pw = PartialWitness::new();
    let mut rng = thread_rng();
    inputs
        .into_iter()
        .zip([0; 2].map(|_| Point::sample(&mut rng)))
        .for_each(|(it, iv)| pw.set_curve_target(it, iv.to_weierstrass()));

    let data = cb.build::<C>();
    let proof = data.prove(pw).unwrap();

    gen_groth16_proof(data, proof);
}

fn group_hashing_map() {
    let config = CircuitConfig::standard_recursion_config();
    let mut cb = CircuitBuilder::<F, D>::new(config);

    let inputs = [0; 2].map(|_| cb.add_virtual_target());
    let output = cb.map_to_curve_point(&inputs);
    cb.register_curve_public_input(output);

    let mut pw = PartialWitness::new();
    let mut rng = thread_rng();
    inputs
        .into_iter()
        .zip([0; 2].map(|_| F::from_canonical_u8(rng.gen())))
        .for_each(|(it, iv)| pw.set_target(it, iv));

    let data = cb.build::<C>();
    let proof = data.prove(pw).unwrap();

    gen_groth16_proof(data, proof);
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
