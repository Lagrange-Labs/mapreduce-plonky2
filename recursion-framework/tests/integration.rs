use std::{array, iter::once};

use plonky2::field::types::{Field, Sample};
use plonky2::{
    field::types::PrimeField64,
    hash::{hash_types::NUM_HASH_OUT_ELTS, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, GenericHashOut, Hasher, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputsTarget,
    },
};
use recursion_framework::serialization::circuit_data_serialization::SerializableRichField;
use recursion_framework::serialization::{deserialize_array, serialize_array};
use recursion_framework::{
    circuit_builder::{CircuitLogicWires, CircuitWithUniversalVerifierBuilder},
    framework::{
        prepare_recursive_circuit_for_circuit_set, RecursiveCircuitInfo, RecursiveCircuits,
        RecursiveCircuitsVerifierGagdet,
    },
    framework_testing::{new_universal_circuit_builder_for_testing, TestingRecursiveCircuits},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serial_test::serial;

/*
    This test shows how to employ the recursive framework to build circuits for a specific map-reduce style computation.
    Given a set of field elements, bounded to a set digest D, we want to compute the sum of the even elements.
    This computation is mapped to circuits as follows:
    - A `MapCircuit` that takes a constant number of elements, referred to as `INPUT_CHUNK_SIZE`, and computes the sum
      of the even ones, exposing it as a public input. Furthermore, it computes the hash of these `INPUT_CHUNK_SIZE`
      elements, exposing it as a public input too, which is necessary to recompute the digest D of the set
    - A `ReduceCircuit` that recursively verify a fixed number of proofs of either `MapCircuit` or `ReduceCircuit`,
      summing up the sum of even elements public inputs of all verified proofs, and hashing together the hash
      public inputs of all verified proofs.
    At the end, we will have a single root proof of `ReduceCircuit`, which will expose as public inputs the sum of all
    the even elements in a set and the digest of the set, which can be compared with the expected digest D to check
    that the expected set has been employed to compute the resulting sum of even elements.
    The tests also show how to recursively verify in a circuit this root proof of `ReduceCircuit` employing the
    `RecursiveCircuitsVerifierGadget` provided by this crate
*/

/// number of public inputs are the sum of even elements and the hash of the elements being
/// considered so far
const NUM_PUBLIC_INPUTS: usize = 1 + NUM_HASH_OUT_ELTS;
#[derive(Serialize, Deserialize)]
struct MapCircuitWires<const INPUT_CHUNK_SIZE: usize> {
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    input_targets: [Target; INPUT_CHUNK_SIZE],
}

impl<F: SerializableRichField<D>, const D: usize, const INPUT_CHUNK_SIZE: usize>
    CircuitLogicWires<F, D, 0> for MapCircuitWires<INPUT_CHUNK_SIZE>
{
    type CircuitBuilderParams = ();

    type Inputs = [F; INPUT_CHUNK_SIZE];

    const NUM_PUBLIC_INPUTS: usize = NUM_PUBLIC_INPUTS;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let input_targets = builder.add_virtual_target_arr::<INPUT_CHUNK_SIZE>();
        let one = builder.one();
        let sum_target = input_targets.iter().fold(builder.zero(), |sum, &input| {
            // take the first bit of `input`, which is related to the parity
            let is_odd = builder.split_le(input, F::BITS)[0];
            let parity = builder.sub(one, is_odd.target);
            // sum input to accumulator only if it is even
            builder.mul_add(parity, input, sum)
        });
        let hash_target = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input_targets.to_vec());
        builder.register_public_input(sum_target);
        builder.register_public_inputs(&hash_target.elements);
        Self { input_targets }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        pw.set_target_arr(self.input_targets.as_ref(), &inputs);

        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
struct ReduceCircuitWires<const ARITY: usize>(());

impl<F: SerializableRichField<D>, const D: usize, const ARITY: usize> CircuitLogicWires<F, D, ARITY>
    for ReduceCircuitWires<ARITY>
{
    type CircuitBuilderParams = ();

    type Inputs = ();

    const NUM_PUBLIC_INPUTS: usize = NUM_PUBLIC_INPUTS;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; ARITY],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let sum_target = verified_proofs
            .iter()
            .fold(builder.zero(), |acc, &proof_t| {
                builder.add(acc, proof_t.public_inputs[0])
            });
        let hash_input = verified_proofs
            .iter()
            .flat_map(|&proof_t| proof_t.public_inputs[1..NUM_PUBLIC_INPUTS].to_vec())
            .collect::<Vec<_>>();
        let cumulative_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(hash_input);
        builder.register_public_input(sum_target);
        builder.register_public_inputs(&cumulative_hash.elements);

        Self(())
    }

    fn assign_input(&self, _inputs: Self::Inputs, _pw: &mut PartialWitness<F>) -> Result<()> {
        Ok(())
    }
}

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

#[test]
#[serial]
fn test_map_reduce_circuits() {
    // build circuits
    const INPUT_CHUNK_SIZE: usize = 4;
    const DATASET_SIZE: usize = INPUT_CHUNK_SIZE * 8;
    const CIRCUIT_SET_SIZE: usize = 2;
    const ARITY: usize = 2;
    let config = CircuitConfig::standard_recursion_config();
    let circuit_builder = CircuitWithUniversalVerifierBuilder::<F, D, NUM_PUBLIC_INPUTS>::new::<C>(
        config.clone(),
        CIRCUIT_SET_SIZE,
    );
    let map_circuit = circuit_builder.build_circuit::<C, 0, MapCircuitWires<INPUT_CHUNK_SIZE>>(());
    let reduce_circuit = circuit_builder.build_circuit::<C, ARITY, ReduceCircuitWires<ARITY>>(());
    // Build framework for set of map reduce circuits
    let mr_circuits = vec![
        prepare_recursive_circuit_for_circuit_set(&map_circuit),
        prepare_recursive_circuit_for_circuit_set(&reduce_circuit),
    ];

    let framework = RecursiveCircuits::<F, C, D>::new(mr_circuits);
    let dataset: [F; DATASET_SIZE] = array::from_fn(|_| F::rand());

    let mut dataset_chunk_digests = dataset
        .chunks(INPUT_CHUNK_SIZE)
        .map(|chunk| PoseidonHash::hash_no_pad(chunk))
        .collect::<Vec<_>>();
    while dataset_chunk_digests.len() != 1 {
        let new_dataset_chunk_digests = dataset_chunk_digests
            .chunks(ARITY)
            .map(|chunk| {
                let inputs = chunk
                    .iter()
                    .flat_map(|hash| hash.to_vec())
                    .collect::<Vec<_>>();
                PoseidonHash::hash_no_pad(&inputs)
            })
            .collect::<Vec<_>>();
        dataset_chunk_digests = new_dataset_chunk_digests;
    }

    let dataset_digest = dataset_chunk_digests[0];
    let sum_of_even = dataset
        .into_iter()
        .filter(|input| input.to_canonical_u64() % 2 == 0)
        .reduce(|acc, el| acc + el)
        .unwrap_or(F::ZERO);

    let map_proofs = dataset
        .chunks(INPUT_CHUNK_SIZE)
        .map(|chunk| framework.generate_proof(&map_circuit, [], [], chunk.try_into().unwrap()))
        .collect::<Result<Vec<_>>>()
        .unwrap();
    let map_circuit_vd = map_circuit.get_verifier_data();
    let reduce_circuit_vd = reduce_circuit.get_verifier_data();
    let mut reduce_proofs = map_proofs
        .chunks(ARITY)
        .map(|chunk| {
            framework.generate_proof(
                &reduce_circuit,
                chunk.to_vec().try_into().unwrap(),
                [map_circuit_vd; ARITY],
                (),
            )
        })
        .collect::<Result<Vec<_>>>()
        .unwrap();
    while reduce_proofs.len() != 1 {
        let new_reduce_proofs = reduce_proofs
            .chunks(ARITY)
            .map(|chunk| {
                framework.generate_proof(
                    &reduce_circuit,
                    chunk.to_vec().try_into().unwrap(),
                    [reduce_circuit_vd; ARITY],
                    (),
                )
            })
            .collect::<Result<Vec<_>>>()
            .unwrap();
        reduce_proofs = new_reduce_proofs;
    }
    let root_proof = &reduce_proofs[0];

    // check public outputs are correct
    assert_eq!(root_proof.public_inputs[0], sum_of_even);
    assert_eq!(
        root_proof.public_inputs[1..NUM_PUBLIC_INPUTS],
        dataset_digest.to_vec()
    );

    reduce_circuit
        .circuit_data()
        .verify(root_proof.clone())
        .unwrap();

    // build a circuit to recursively verify the root proof employing the `RecursiveCircuitVerifierGadget`
    let verifier_gadget = RecursiveCircuitsVerifierGagdet::<F, C, D, NUM_PUBLIC_INPUTS>::new(
        config.clone(),
        &framework,
    );
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let proof_target =
        verifier_gadget.verify_proof_fixed_circuit_in_circuit_set(&mut builder, reduce_circuit_vd);
    builder.register_public_inputs(&proof_target.public_inputs);

    let verifier_circuit = builder.build::<C>();

    // prove the correct verification of a root proof
    let mut pw = PartialWitness::<F>::new();
    pw.set_proof_with_pis_target(&proof_target, root_proof);

    let recursive_verifier_proof = verifier_circuit.prove(pw).unwrap();

    // check public outputs are correct
    assert_eq!(recursive_verifier_proof.public_inputs[0], sum_of_even);
    assert_eq!(
        recursive_verifier_proof.public_inputs[1..NUM_PUBLIC_INPUTS],
        dataset_digest.to_vec()
    );

    verifier_circuit.verify(recursive_verifier_proof).unwrap();
}

#[test]
#[serial]
fn test_reduce_circuit_with_testing_framework() {
    // this test shows how to employ the `TestingRecursiveCircuits` framework to test a circuit with universal verifier
    // in isolation, i.e., without the need to generate proofs of other circuits to be verified by the universal verifier
    const CIRCUIT_SET_SIZE: usize = 1;
    const ARITY: usize = 2;
    let config = CircuitConfig::standard_recursion_config();
    let circuit_builder = new_universal_circuit_builder_for_testing::<F, C, D, NUM_PUBLIC_INPUTS>(
        config.clone(),
        CIRCUIT_SET_SIZE,
    );

    let reduce_circuit = circuit_builder.build_circuit::<C, ARITY, ReduceCircuitWires<ARITY>>(());

    let circuit_set = vec![prepare_recursive_circuit_for_circuit_set(&reduce_circuit)];

    let testing_framework = TestingRecursiveCircuits::new(&circuit_builder, circuit_set);

    let test_public_inputs = array::from_fn(|_| {
        let hash = PoseidonHash::hash_no_pad(F::rand_vec(8).as_slice());
        once(F::rand())
            .chain(hash.to_vec().into_iter())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    });
    let reduce_proof = testing_framework
        .generate_proof_from_public_inputs(&reduce_circuit, test_public_inputs, ())
        .unwrap();

    // check public inputs of reduce proof
    let sum_of_even = test_public_inputs
        .iter()
        .fold(F::ZERO, |acc, pub_input| acc + pub_input[0]);
    let cumulative_hash = PoseidonHash::hash_no_pad(
        test_public_inputs
            .iter()
            .flat_map(|pub_inp| pub_inp[1..NUM_PUBLIC_INPUTS].to_vec())
            .collect::<Vec<_>>()
            .as_slice(),
    );
    assert_eq!(reduce_proof.public_inputs[0], sum_of_even);
    assert_eq!(
        reduce_proof.public_inputs[1..NUM_PUBLIC_INPUTS],
        cumulative_hash.to_vec()
    );
}
