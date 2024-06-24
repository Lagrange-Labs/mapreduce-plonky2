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
    pub fn new_simple_input(
        block_proof: Vec<u8>,
        contract_proof: Vec<u8>,
        value_proof: Vec<u8>,
        compound: bool,
    ) -> Result<Self> {
        let base = BaseCircuitInput::new(block_proof, contract_proof, value_proof)?;
        Ok(Self::Simple(SimpleCircuitInput { base, compound }))
    }

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
