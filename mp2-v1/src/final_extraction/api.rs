use ethers::core::k256::elliptic_curve::rand_core::block;
use mp2_common::{C, D, F};
use plonky2::{
    iop::target::Target,
    plonk::{circuit_data::VerifierCircuitData, proof::ProofWithPublicInputs},
};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{prepare_recursive_circuit_for_circuit_set, RecursiveCircuits},
};
use serde::{Deserialize, Serialize};

use crate::api::{default_config, deserialize_proof, ProofWithVK};

use super::{
    base_circuit::BaseCircuitInput, lengthed_circuit::LengthedRecursiveWires,
    simple_circuit::SimpleCircuitRecursiveWires, BaseCircuitProofInputs, LengthedCircuit,
    PublicInputs, SimpleCircuit,
};

use anyhow::Result;

#[derive(Clone, Debug)]
pub struct FinalExtractionBuilderParams {
    pub(crate) block_vk: VerifierCircuitData<F, C, D>,
    pub(crate) contract_circuit_set: RecursiveCircuits<F, C, D>,
    pub(crate) value_circuit_set: RecursiveCircuits<F, C, D>,
    pub(crate) length_circuit_set: RecursiveCircuits<F, C, D>,
}

impl FinalExtractionBuilderParams {
    /// Instantiate a new set of building params for final extraction circuit
    pub fn new(
        block_vk: VerifierCircuitData<F, C, D>,
        contract_circuit_set: &RecursiveCircuits<F, C, D>,
        value_circuit_set: &RecursiveCircuits<F, C, D>,
        length_circuit_set: &RecursiveCircuits<F, C, D>,
    ) -> Self {
        Self {
            block_vk,
            contract_circuit_set: contract_circuit_set.clone(),
            value_circuit_set: value_circuit_set.clone(),
            length_circuit_set: length_circuit_set.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PublicParameters {
    simple: CircuitWithUniversalVerifier<F, C, D, 0, SimpleCircuitRecursiveWires>,
    lengthed: CircuitWithUniversalVerifier<F, C, D, 0, LengthedRecursiveWires>,
    circuit_set: RecursiveCircuits<F, C, D>,
}

const FINAL_EXTRACTION_CIRCUIT_SET_SIZE: usize = 2;
pub(super) const NUM_IO: usize = PublicInputs::<Target>::TOTAL_LEN;

impl PublicParameters {
    pub fn build(
        block_vk: VerifierCircuitData<F, C, D>,
        contract_circuit_set: &RecursiveCircuits<F, C, D>,
        value_circuit_set: &RecursiveCircuits<F, C, D>,
        length_circuit_set: &RecursiveCircuits<F, C, D>,
    ) -> Self {
        let builder = CircuitWithUniversalVerifierBuilder::<_, D, NUM_IO>::new::<C>(
            default_config(),
            FINAL_EXTRACTION_CIRCUIT_SET_SIZE,
        );
        let builder_params = FinalExtractionBuilderParams::new(
            block_vk,
            contract_circuit_set,
            value_circuit_set,
            length_circuit_set,
        );
        let simple = builder.build_circuit(builder_params.clone());
        let lengthed = builder.build_circuit(builder_params);

        let circuits = vec![
            prepare_recursive_circuit_for_circuit_set(&simple),
            prepare_recursive_circuit_for_circuit_set(&lengthed),
        ];

        let circuit_set = RecursiveCircuits::new(circuits);

        Self {
            simple,
            lengthed,
            circuit_set,
        }
    }

    pub(crate) fn generate_simple_proof(
        &self,
        input: SimpleCircuitInput,
        contract_circuit_set: &RecursiveCircuits<F, C, D>,
        value_circuit_set: &RecursiveCircuits<F, C, D>,
    ) -> Result<Vec<u8>> {
        let simple_inputs = SimpleCircuit::new(
            BaseCircuitProofInputs::new_from_proofs(
                input.base,
                contract_circuit_set.clone(),
                value_circuit_set.clone(),
            ),
            input.compound,
        );
        let proof = self
            .circuit_set
            .generate_proof(&self.simple, [], [], simple_inputs)?;
        ProofWithVK::serialize(&(proof, self.simple.circuit_data().verifier_only.clone()).into())
    }

    pub(crate) fn generate_lengthed_proof(
        &self,
        input: LengthedCircuitInput,
        contract_circuit_set: &RecursiveCircuits<F, C, D>,
        value_circuit_set: &RecursiveCircuits<F, C, D>,
        length_circuit_set: &RecursiveCircuits<F, C, D>,
    ) -> Result<Vec<u8>> {
        let lengthed_input = LengthedCircuit::new(
            BaseCircuitProofInputs::new_from_proofs(
                input.base,
                contract_circuit_set.clone(),
                value_circuit_set.clone(),
            ),
            input.length_proof,
            length_circuit_set.clone(),
        );
        let proof = self
            .circuit_set
            .generate_proof(&self.lengthed, [], [], lengthed_input)?;
        ProofWithVK::serialize(&(proof, self.lengthed.circuit_data().verifier_only.clone()).into())
    }
}

pub struct SimpleCircuitInput {
    base: BaseCircuitInput,
    compound: bool,
}

pub struct LengthedCircuitInput {
    base: BaseCircuitInput,
    length_proof: ProofWithVK,
}

pub enum CircuitInput {
    Simple(SimpleCircuitInput),
    Lengthed(LengthedCircuitInput),
}

impl CircuitInput {
    /// Instantiate inputs for simple variables circuit. Coumpound must be set to true
    /// if the proof is for extracting values for a variable type with dynamic length (like a mapping)
    /// but that does not require a length_proof (maybe because there is no way to get the length
    /// of the type from the onchain information, i.e. no length slot).
    pub fn new_simple_input(
        block_proof: Vec<u8>,
        contract_proof: Vec<u8>,
        value_proof: Vec<u8>,
        compound: bool,
    ) -> Result<Self> {
        let base = BaseCircuitInput::new(block_proof, contract_proof, value_proof)?;
        Ok(Self::Simple(SimpleCircuitInput { base, compound }))
    }
    /// Instantiate inputs for circuit dealing with compound types with a length slot
    pub fn new_lengthed_input(
        block_proof: Vec<u8>,
        contract_proof: Vec<u8>,
        value_proof: Vec<u8>,
        length_proof: Vec<u8>,
    ) -> Result<Self> {
        let base = BaseCircuitInput::new(block_proof, contract_proof, value_proof)?;
        let length_proof = ProofWithVK::deserialize(&length_proof)?;
        Ok(Self::Lengthed(LengthedCircuitInput { base, length_proof }))
    }
}

#[cfg(test)]
mod tests {
    use mp2_common::{C, D, F};
    use plonky2_ecgfp5::curve::curve::Point;
    use recursion_framework::framework_testing::TestingRecursiveCircuits;

    use crate::{
        api::{serialize_proof, tests::TestDummyCircuit, ProofWithVK},
        final_extraction::{
            base_circuit::{
                test::ProofsPi, BLOCK_SET_NUM_IO, CONTRACT_SET_NUM_IO, VALUE_SET_NUM_IO,
            },
            lengthed_circuit::LENGTH_SET_NUM_IO,
        },
        length_extraction,
    };

    use super::{CircuitInput, PublicParameters};

    #[test]
    fn test_final_extraction_api() {
        let block_circuit = TestDummyCircuit::<BLOCK_SET_NUM_IO>::build();
        let values_params = TestingRecursiveCircuits::<F, C, D, VALUE_SET_NUM_IO>::default();
        let contract_params = TestingRecursiveCircuits::<F, C, D, CONTRACT_SET_NUM_IO>::default();
        let length_params = TestingRecursiveCircuits::<F, C, D, LENGTH_SET_NUM_IO>::default();
        let params = PublicParameters::build(
            block_circuit.circuit_data().verifier_data(),
            contract_params.get_recursive_circuit_set(),
            values_params.get_recursive_circuit_set(),
            length_params.get_recursive_circuit_set(),
        );

        let proof_pis = ProofsPi::random();
        let length_pis = proof_pis.length_inputs();
        let len_dm = length_extraction::PublicInputs::<F>::from_slice(&length_pis).metadata_point();
        let block_proof = block_circuit
            .generate_proof(proof_pis.blocks_pi.clone().try_into().unwrap())
            .unwrap();
        let value_proof = &values_params
            .generate_input_proofs::<1>([proof_pis.values_pi.clone().try_into().unwrap()])
            .unwrap()[0];
        let contract_proof = &contract_params
            .generate_input_proofs::<1>([proof_pis.contract_pi.clone().try_into().unwrap()])
            .unwrap()[0];
        let length_proof = &length_params
            .generate_input_proofs::<1>([length_pis.try_into().unwrap()])
            .unwrap()[0];

        let contract_proof: ProofWithVK = (
            contract_proof.clone(),
            contract_params.verifier_data_for_input_proofs::<1>()[0].clone(),
        )
            .into();
        let value_proof: ProofWithVK = (
            value_proof.clone(),
            values_params.verifier_data_for_input_proofs::<1>()[0].clone(),
        )
            .into();
        // test generation of proof for simple circuit for both compound and simple types
        for compound in [false, true] {
            let circuit_input = CircuitInput::new_simple_input(
                serialize_proof(&block_proof).unwrap(),
                contract_proof.serialize().unwrap(),
                value_proof.serialize().unwrap(),
                compound,
            )
            .unwrap();

            let proof = ProofWithVK::deserialize(
                &params
                    .generate_simple_proof(
                        match circuit_input {
                            CircuitInput::Simple(input) => input,
                            _ => unreachable!(),
                        },
                        contract_params.get_recursive_circuit_set(),
                        values_params.get_recursive_circuit_set(),
                    )
                    .unwrap(),
            )
            .unwrap();
            proof_pis.check_proof_public_inputs(proof.proof(), compound, None);
        }
        // test proof generation for types with length circuit
        let length_proof: ProofWithVK = (
            length_proof.clone(),
            length_params.verifier_data_for_input_proofs::<1>()[0].clone(),
        )
            .into();
        let circuit_input = CircuitInput::new_lengthed_input(
            serialize_proof(&block_proof).unwrap(),
            contract_proof.serialize().unwrap(),
            value_proof.serialize().unwrap(),
            length_proof.serialize().unwrap(),
        )
        .unwrap();
        let proof = ProofWithVK::deserialize(
            &params
                .generate_lengthed_proof(
                    match circuit_input {
                        CircuitInput::Lengthed(input) => input,
                        _ => unreachable!(),
                    },
                    contract_params.get_recursive_circuit_set(),
                    values_params.get_recursive_circuit_set(),
                    length_params.get_recursive_circuit_set(),
                )
                .unwrap(),
        )
        .unwrap();
        proof_pis.check_proof_public_inputs(proof.proof(), true, Some(len_dm));
    }
}
