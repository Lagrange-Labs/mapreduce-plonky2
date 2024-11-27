use mp2_common::{self, default_config, proof::ProofWithVK, C, D, F};
use plonky2::{iop::target::Target, plonk::circuit_data::VerifierCircuitData};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{prepare_recursive_circuit_for_circuit_set, RecursiveCircuits},
};

use serde::{Deserialize, Serialize};

use super::{
    base_circuit::BaseCircuitInput,
    lengthed_circuit::LengthedRecursiveWires,
    merge_circuit::{MergeTable, MergeTableRecursiveWires},
    receipt_circuit::{ReceiptCircuitInput, ReceiptCircuitProofInputs, ReceiptRecursiveWires},
    simple_circuit::SimpleCircuitRecursiveWires,
    BaseCircuitProofInputs, LengthedCircuit, MergeCircuit, PublicInputs, SimpleCircuit,
};

use anyhow::Result;
pub enum CircuitInput {
    Simple(SimpleCircuitInput),
    Lengthed(LengthedCircuitInput),
    MergeTable(MergeCircuitInput),
    Receipt(ReceiptCircuitInput),
}
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
    merge: CircuitWithUniversalVerifier<F, C, D, 0, MergeTableRecursiveWires>,
    receipt: CircuitWithUniversalVerifier<F, C, D, 0, ReceiptRecursiveWires>,
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
        let lengthed = builder.build_circuit(builder_params.clone());
        let merge = builder.build_circuit(builder_params.clone());
        let receipt = builder.build_circuit(builder_params);

        let circuits = vec![
            prepare_recursive_circuit_for_circuit_set(&simple),
            prepare_recursive_circuit_for_circuit_set(&lengthed),
            prepare_recursive_circuit_for_circuit_set(&merge),
            prepare_recursive_circuit_for_circuit_set(&receipt),
        ];

        let circuit_set = RecursiveCircuits::new(circuits);

        Self {
            simple,
            lengthed,
            merge,
            receipt,
            circuit_set,
        }
    }

    pub(crate) fn generate_merge_proof(
        &self,
        input: MergeCircuitInput,
        contract_circuit_set: &RecursiveCircuits<F, C, D>,
        value_circuit_set: &RecursiveCircuits<F, C, D>,
    ) -> Result<Vec<u8>> {
        let base = BaseCircuitProofInputs::new_from_proofs(
            input.base,
            contract_circuit_set.clone(),
            value_circuit_set.clone(),
        );

        let merge = MergeTable {
            is_table_a_multiplier: input.is_table_a_multiplier,
        };
        let merge_inputs = MergeCircuit { base, merge };
        let proof = self
            .circuit_set
            .generate_proof(&self.merge, [], [], merge_inputs)?;
        ProofWithVK::serialize(&(proof, self.merge.circuit_data().verifier_only.clone()).into())
    }

    pub(crate) fn generate_simple_proof(
        &self,
        input: SimpleCircuitInput,
        contract_circuit_set: &RecursiveCircuits<F, C, D>,
        value_circuit_set: &RecursiveCircuits<F, C, D>,
    ) -> Result<Vec<u8>> {
        let simple_inputs = SimpleCircuit::new(BaseCircuitProofInputs::new_from_proofs(
            input.base,
            contract_circuit_set.clone(),
            value_circuit_set.clone(),
        ));
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

    pub(crate) fn generate_receipt_proof(
        &self,
        input: ReceiptCircuitInput,
        value_circuit_set: &RecursiveCircuits<F, C, D>,
    ) -> Result<Vec<u8>> {
        let receipt_input =
            ReceiptCircuitProofInputs::new_from_proofs(input, value_circuit_set.clone());
        let proof = self
            .circuit_set
            .generate_proof(&self.receipt, [], [], receipt_input)?;
        ProofWithVK::serialize(&(proof, self.receipt.circuit_data().verifier_only.clone()).into())
    }

    pub(crate) fn get_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        &self.circuit_set
    }
}

pub struct SimpleCircuitInput {
    base: BaseCircuitInput,
}

pub struct LengthedCircuitInput {
    base: BaseCircuitInput,
    length_proof: ProofWithVK,
}

pub struct MergeCircuitInput {
    base: BaseCircuitInput,
    is_table_a_multiplier: bool,
}

impl CircuitInput {
    /// Create a circuit input for merging  single table and a mapping table together.
    /// Both tables should belong to the same contract.
    /// This is a specialized API that uses a more general API underneath. Allowing more types of
    /// merging can be opened up on the API on a case by case basis.
    /// Table A MUST be a single table and table B MUST be a mapping table.
    pub fn new_merge_single_and_mapping(
        block_proof: Vec<u8>,
        contract_proof: Vec<u8>,
        single_table_proof: Vec<u8>,
        mapping_table_proof: Vec<u8>,
    ) -> Result<Self> {
        let base = BaseCircuitInput::new(
            block_proof,
            contract_proof,
            vec![single_table_proof, mapping_table_proof],
        )?;
        Ok(Self::MergeTable(MergeCircuitInput {
            base,
            is_table_a_multiplier: true,
        }))
    }
    /// Instantiate inputs for simple variables circuit. Coumpound must be set to true
    /// if the proof is for extracting values for a variable type with dynamic length (like a mapping)
    /// but that does not require a length_proof (maybe because there is no way to get the length
    /// of the type from the onchain information, i.e. no length slot).
    pub fn new_simple_input(
        block_proof: Vec<u8>,
        contract_proof: Vec<u8>,
        value_proof: Vec<u8>,
    ) -> Result<Self> {
        let base = BaseCircuitInput::new(block_proof, contract_proof, vec![value_proof])?;
        Ok(Self::Simple(SimpleCircuitInput { base }))
    }
    /// Instantiate inputs for circuit dealing with compound types with a length slot
    pub fn new_lengthed_input(
        block_proof: Vec<u8>,
        contract_proof: Vec<u8>,
        value_proof: Vec<u8>,
        length_proof: Vec<u8>,
    ) -> Result<Self> {
        let base = BaseCircuitInput::new(block_proof, contract_proof, vec![value_proof])?;
        let length_proof = ProofWithVK::deserialize(&length_proof)?;
        Ok(Self::Lengthed(LengthedCircuitInput { base, length_proof }))
    }

    pub fn new_receipt_input(block_proof: Vec<u8>, value_proof: Vec<u8>) -> Result<Self> {
        Ok(Self::Receipt(ReceiptCircuitInput::new(
            block_proof,
            value_proof,
        )?))
    }
}

#[cfg(test)]
mod tests {
    use mp2_common::{
        proof::{serialize_proof, ProofWithVK},
        C, D, F,
    };
    use mp2_test::circuit::TestDummyCircuit;

    use recursion_framework::framework_testing::TestingRecursiveCircuits;

    use crate::{
        final_extraction::{
            base_circuit::{test::ProofsPi, CONTRACT_SET_NUM_IO, VALUE_SET_NUM_IO},
            lengthed_circuit::LENGTH_SET_NUM_IO,
        },
        length_extraction,
    };

    use super::{CircuitInput, PublicParameters};

    pub(crate) const BLOCK_SET_NUM_IO: usize =
        crate::block_extraction::public_inputs::PublicInputs::<F>::TOTAL_LEN;

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
        let circuit_input = CircuitInput::new_simple_input(
            serialize_proof(&block_proof).unwrap(),
            contract_proof.serialize().unwrap(),
            value_proof.serialize().unwrap(),
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
        proof_pis.check_proof_public_inputs(proof.proof(), None);
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
        proof_pis.check_proof_public_inputs(proof.proof(), Some(len_dm));
    }
}
