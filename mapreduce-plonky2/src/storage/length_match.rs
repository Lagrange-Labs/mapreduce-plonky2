//! This circuit is used to verify the count of entries in the mapping
//! corresponds to the length value extracted from the storage trie.

use super::{
    length_extract::{self, PublicInputs as LengthPublicInputs},
    mapping::PublicInputs as MappingPublicInputs,
};
use crate::{
    api::{default_config, deserialize_proof, serialize_proof, ProofWithVK},
    circuit::UserCircuit,
    keccak::{OutputHash, PACKED_HASH_LEN},
    types::{PackedAddressTarget, PACKED_ADDRESS_LEN},
    utils::{convert_point_to_curve_target, convert_slice_to_curve_point},
    verifier_gadget::VerifierTarget,
};
use anyhow::Result;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, VerifierCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig, Hasher},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget};
use recursion_framework::{
    framework::{
        RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
    serialization::{circuit_data_serialization::SerializableRichField, deserialize, serialize},
};
use serde::{Deserialize, Serialize};
use std::array;
/// This is a wrapper around an array of targets set as public inputs of any
/// proof generated in this module. They all share the same structure.
/// `D` Digest of the all mapping values
/// `C` MPT root of the trie
/// `M` storage slot of the mapping
/// `S` storage slot of the variable holding the length
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T: Clone> {
    pub(crate) proof_inputs: &'a [T],
}

impl<'a> PublicInputs<'a, Target> {
    pub fn register(
        cb: &mut CircuitBuilder<GoldilocksField, 2>,
        digest: &CurveTarget,
        mpt_root_hash: &OutputHash,
        mapping_slot: Target,
        length_slot: Target,
    ) {
        cb.register_curve_public_input(*digest);
        mpt_root_hash.register_as_public_input(cb);
        cb.register_public_input(mapping_slot);
        cb.register_public_input(length_slot);
    }

    /// Return the curve point target of digest defined over the public inputs.
    pub fn digest(&self) -> CurveTarget {
        convert_point_to_curve_target(self.digest_data())
    }

    pub fn root_hash(&self) -> OutputHash {
        let data = self.root_hash_data();
        array::from_fn(|i| U32Target(data[i])).into()
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    pub(crate) const D_IDX: usize = 0;
    pub(crate) const C_IDX: usize = Self::D_IDX + 11;
    pub(crate) const M_IDX: usize = Self::C_IDX + PACKED_HASH_LEN;
    pub(crate) const S_IDX: usize = Self::M_IDX + 1;
    pub(crate) const TOTAL_LEN: usize = Self::S_IDX + 1;

    pub fn from(arr: &'a [T]) -> Self {
        Self { proof_inputs: arr }
    }

    /// Transform a list of elements to a curve point.
    pub fn digest_data(&self) -> ([T; 5], [T; 5], T) {
        convert_slice_to_curve_point(&self.proof_inputs[Self::D_IDX..])
    }

    pub fn root_hash_data(&self) -> &[T] {
        &self.proof_inputs[Self::C_IDX..Self::M_IDX]
    }

    pub fn mapping_slot(&self) -> T {
        self.proof_inputs[Self::M_IDX]
    }

    pub fn length_slot(&self) -> T {
        self.proof_inputs[Self::S_IDX]
    }
}

/// Length match circuit
#[derive(Clone, Debug)]
struct LengthMatchCircuit;

impl LengthMatchCircuit {
    /// Build for circuit.
    pub fn build(
        cb: &mut CircuitBuilder<GoldilocksField, 2>,
        length_pi: &[Target],
        mapping_pi: &[Target],
    ) {
        let length_pi = LengthPublicInputs::from(length_pi);
        let mapping_pi = MappingPublicInputs::from(mapping_pi);

        let mapping_slot = mapping_pi.mapping_slot();
        let length_slot = length_pi.storage_slot();
        let digest = mapping_pi.accumulator();

        // The MPT key pointer must be equal to -1 after traversing from leaf to
        // root.
        let (_, mpt_key_pointer) = mapping_pi.mpt_key_info();
        let neg_one = cb.neg_one();
        cb.connect(mpt_key_pointer, neg_one);

        // Constrain the entry lengths are equal.
        let length_value = length_pi.length_value();
        let n = mapping_pi.n();
        cb.connect(length_value, n);

        // Constrain the MPT root hashes are same.
        let length_root_hash = length_pi.root_hash();
        let mapping_root_hash = mapping_pi.root_hash();
        length_root_hash.enforce_equal(cb, &mapping_root_hash);

        // Register the public inputs.
        PublicInputs::register(cb, &digest, &length_root_hash, mapping_slot, length_slot);
    }
}

type F = crate::api::F;
type C = crate::api::C;
const D: usize = crate::api::D;
#[derive(Serialize, Deserialize)]
pub(crate) struct Parameters {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    data: CircuitData<F, C, D>,
    length_proof_wires: VerifierTarget<D>,
    mapping_proof_wires: RecursiveCircuitsVerifierTarget<D>,
}

impl Parameters {
    /// Build circuit parameters for length matching circuit
    pub(crate) fn build(
        mapping_circuit_set: &RecursiveCircuits<F, C, D>,
        length_extract_vk: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let config = default_config();
        const NUM_PUBLIC_INPUTS: usize = MappingPublicInputs::<'_, Target>::TOTAL_LEN;
        let verifier_gadget = RecursiveCircuitsVerifierGagdet::<F, C, D, NUM_PUBLIC_INPUTS>::new(
            config.clone(),
            mapping_circuit_set,
        );
        let mut cb = CircuitBuilder::<F, D>::new(config);
        let mapping_proof_wires = verifier_gadget.verify_proof_in_circuit_set(&mut cb);
        let length_proof_wires = VerifierTarget::verify_proof(&mut cb, length_extract_vk);
        let mapping_pi = mapping_proof_wires.get_public_input_targets::<F, NUM_PUBLIC_INPUTS>();
        let length_pi = length_proof_wires.get_proof().public_inputs.as_slice();
        LengthMatchCircuit::build(&mut cb, length_pi, mapping_pi);
        let data = cb.build::<C>();
        Self {
            data,
            mapping_proof_wires,
            length_proof_wires,
        }
    }
    /// Generate a proof for length matching circuit employing the circuit parameters found in  `self`
    pub(crate) fn generate_proof(
        &self,
        mapping_circuit_set: &RecursiveCircuits<F, C, D>,
        mapping_proof: &ProofWithVK,
        length_proof: &ProofWithVK,
    ) -> Result<Vec<u8>> {
        let mut pw = PartialWitness::<F>::new();
        let (proof, vd) = mapping_proof.into();
        self.mapping_proof_wires
            .set_target(&mut pw, mapping_circuit_set, &proof, &vd)?;
        let (proof, vd) = length_proof.into();
        self.length_proof_wires.set_target(&mut pw, &proof, &vd);
        let proof = self.data.prove(pw)?;
        serialize_proof(&proof)
    }
    /// Get the `CircuitData` associated to the length matching circuit
    pub(crate) fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}

/// Data structure containing the inputs to be provided to the API in order to
/// generate a proof for the length matching circuit
pub struct CircuitInput {
    mapping_proof: Vec<u8>,
    length_extract_proof: Vec<u8>,
}

impl CircuitInput {
    /// Initialize `CircuitInput`
    pub fn new(mapping_proof: Vec<u8>, length_extract_proof: Vec<u8>) -> Self {
        Self {
            mapping_proof,
            length_extract_proof,
        }
    }
}
impl TryInto<(ProofWithVK, ProofWithPublicInputs<F, C, D>)> for CircuitInput {
    type Error = anyhow::Error;

    fn try_into(
        self,
    ) -> std::prelude::v1::Result<(ProofWithVK, ProofWithPublicInputs<F, C, D>), Self::Error> {
        Ok((
            ProofWithVK::deserialize(&self.mapping_proof)?,
            deserialize_proof(&self.length_extract_proof)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use self::length_extract::PublicParameters;

    use super::*;
    use crate::{
        api::{
            mapping::{api::NUM_IO, build_circuits_params},
            tests::TestDummyCircuit,
        },
        benches::init_logging,
        circuit::{test::run_circuit, UserCircuit},
        utils::test::random_vector,
    };
    use plonky2::{
        field::types::Field,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rand::{thread_rng, Rng};
    use recursion_framework::framework_testing::TestingRecursiveCircuits;
    use std::array;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    /// Test circuit
    #[derive(Clone, Debug)]
    struct TestCircuit {
        length_pi: Vec<F>,
        mapping_pi: Vec<F>,
    }

    impl UserCircuit<F, D> for TestCircuit {
        type Wires = (Vec<Target>, Vec<Target>);

        fn build(cb: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let length_pi = cb.add_virtual_targets(LengthPublicInputs::<Target>::TOTAL_LEN);
            let mapping_pi = cb.add_virtual_targets(MappingPublicInputs::<Target>::TOTAL_LEN);

            LengthMatchCircuit::build(cb, &length_pi, &mapping_pi);

            (length_pi, mapping_pi)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.0, &self.length_pi);
            pw.set_target_arr(&wires.1, &self.mapping_pi);
        }
    }

    /// Test the length-match circuit with simple random previous public inputs.
    #[test]
    fn test_length_match_circuit_simple() {
        init_logging();

        let mut rng = thread_rng();
        let length_value = F::from_canonical_u64(rng.gen::<u64>());
        let mpt_root_hash: [F; PACKED_HASH_LEN] =
            array::from_fn(|_| F::from_canonical_u32(rng.gen::<u32>()));

        let length_pi = generate_length_public_inputs(length_value, &mpt_root_hash);
        let mapping_pi = generate_mapping_public_inputs(length_value, &mpt_root_hash);

        let test_circuit = TestCircuit {
            length_pi,
            mapping_pi,
        };
        run_circuit::<F, D, C, _>(test_circuit);
    }

    #[test]
    fn test_length_match_circuit_parameters() {
        let testing_framework = TestingRecursiveCircuits::<F, C, D, NUM_IO>::default();
        let length_extract_dummy_circuit =
            TestDummyCircuit::<{ LengthPublicInputs::<'_, Target>::TOTAL_LEN }>::build();

        let length_match_circuit = Parameters::build(
            testing_framework.get_recursive_circuit_set(),
            &length_extract_dummy_circuit.circuit_data().verifier_data(),
        );
        // generate public inputs o proofs to be verified
        let mut rng = thread_rng();
        let length_value = F::from_canonical_u64(rng.gen::<u64>());
        let mpt_root_hash: [F; PACKED_HASH_LEN] =
            array::from_fn(|_| F::from_canonical_u32(rng.gen::<u32>()));

        let length_pi = generate_length_public_inputs(length_value, &mpt_root_hash);
        let mapping_pi = generate_mapping_public_inputs(length_value, &mpt_root_hash);

        // generate mapping proof with `mapping_pi` as public inputs
        let mapping_proof = testing_framework
            .generate_input_proofs::<1>([mapping_pi.try_into().unwrap()])
            .unwrap()
            .first()
            .unwrap()
            .clone();
        let length_proof = length_extract_dummy_circuit
            .generate_proof(length_pi.try_into().unwrap())
            .unwrap();

        let mapping_proof = (
            mapping_proof,
            testing_framework.verifier_data_for_input_proofs::<1>()[0].clone(),
        )
            .into();

        let length_proof = (
            length_proof,
            length_extract_dummy_circuit
                .circuit_data()
                .verifier_only
                .clone(),
        )
            .into();

        let proof = length_match_circuit
            .generate_proof(
                testing_framework.get_recursive_circuit_set(),
                &mapping_proof,
                &length_proof,
            )
            .unwrap();

        length_match_circuit
            .data
            .verify(bincode::deserialize(&proof).unwrap())
            .unwrap()
    }

    fn generate_length_public_inputs(length_value: F, mpt_root_hash: &[F]) -> Vec<F> {
        let mut pi: Vec<_> = random_vector::<u64>(LengthPublicInputs::<F>::TOTAL_LEN)
            .into_iter()
            .map(F::from_canonical_u64)
            .collect();

        pi[LengthPublicInputs::<F>::V_IDX] = length_value;
        pi[LengthPublicInputs::<F>::C_IDX..LengthPublicInputs::<F>::S_IDX]
            .copy_from_slice(mpt_root_hash);

        pi
    }

    fn generate_mapping_public_inputs(n: F, mpt_root_hash: &[F]) -> Vec<F> {
        let mut pi: Vec<_> = random_vector::<u64>(MappingPublicInputs::<F>::TOTAL_LEN)
            .into_iter()
            .map(F::from_canonical_u64)
            .collect();

        pi[MappingPublicInputs::<F>::T_IDX] = F::NEG_ONE;
        pi[MappingPublicInputs::<F>::N_IDX] = n;
        pi[MappingPublicInputs::<F>::C_IDX..].copy_from_slice(mpt_root_hash);

        pi
    }
}
