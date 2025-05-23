use crate::{C, D, F};
use alloy::primitives::U256;
use anyhow::{anyhow, ensure, Result};
use itertools::Itertools;
use mp2_common::{
    self, default_config,
    proof::ProofWithVK,
    types::HashOutput,
    utils::{keccak256, Packer},
};
use plonky2::{field::types::Field, iop::target::Target, plonk::circuit_data::VerifierCircuitData};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{prepare_recursive_circuit_for_circuit_set, RecursiveCircuits},
};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::{
    api::{no_provable_metadata_digest, TableRow},
    indexing::ColumnID,
    values_extraction::compute_table_row_digest,
};
use verifiable_db::ivc::PublicInputs as IvcPublicInputs;

use super::{
    base_circuit::BaseCircuitInput,
    dummy_circuit::DummyWires,
    lengthed_circuit::LengthedRecursiveWires,
    merge_circuit::{MergeTable, MergeTableRecursiveWires},
    simple_circuit::SimpleCircuitRecursiveWires,
    BaseCircuitProofInputs, DummyCircuit, LengthedCircuit, MergeCircuit, PublicInputs,
    SimpleCircuit,
};

#[derive(Serialize, Deserialize)]
pub enum CircuitInput {
    Simple(SimpleCircuitInput),
    Lengthed(LengthedCircuitInput),
    MergeTable(MergeCircuitInput),
    NoProvable(DummyCircuit),
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
    dummy: CircuitWithUniversalVerifier<F, C, D, 0, DummyWires>,
    circuit_set: RecursiveCircuits<F, C, D>,
}

const FINAL_EXTRACTION_CIRCUIT_SET_SIZE: usize = 4;
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
        let dummy = builder.build_circuit(builder_params);

        let circuits = vec![
            prepare_recursive_circuit_for_circuit_set(&simple),
            prepare_recursive_circuit_for_circuit_set(&lengthed),
            prepare_recursive_circuit_for_circuit_set(&merge),
            prepare_recursive_circuit_for_circuit_set(&dummy),
        ];

        let circuit_set = RecursiveCircuits::new(circuits);

        Self {
            simple,
            lengthed,
            merge,
            dummy,
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

    pub(crate) fn generate_no_provable_proof(&self, input: DummyCircuit) -> Result<Vec<u8>> {
        let proof = self
            .circuit_set
            .generate_proof(&self.dummy, [], [], input)?;
        ProofWithVK::serialize(&(proof, self.dummy.circuit_data().verifier_only.clone()).into())
    }

    pub(crate) fn get_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        &self.circuit_set
    }
}

#[derive(Serialize, Deserialize)]
pub struct SimpleCircuitInput {
    base: BaseCircuitInput,
}

#[derive(Serialize, Deserialize)]
pub struct LengthedCircuitInput {
    base: BaseCircuitInput,
    length_proof: ProofWithVK,
}

#[derive(Serialize, Deserialize)]
pub struct MergeCircuitInput {
    base: BaseCircuitInput,
    is_table_a_multiplier: bool,
}

/// Represent the root of trust for the offchain data. It can be an actual hash if
/// there is a root of trust, or dummy if there is no root of trust
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum OffChainRootOfTrust {
    Hash(HashOutput),
    Dummy,
}

impl OffChainRootOfTrust {
    const DUMMY_HASH_PAYLOAD: &str = "DUMMY_ROOT_OF_TRUST";

    /// Return the actual hash employed as root of trust
    pub fn hash(&self) -> HashOutput {
        match self {
            Self::Hash(h) => *h,
            Self::Dummy => {
                HashOutput::try_from(keccak256(Self::DUMMY_HASH_PAYLOAD.as_bytes())).unwrap()
            }
        }
    }
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
    /// Instantiate inputs for the dummy circuit dealing with no provable extraction case. It allows
    /// to add a set of rows, all related to the same primary index value, to an off-chain table.
    /// It requires the following inputs:
    /// - `primary_index`: the primary index value for all the rows we are adding to the table
    /// - `root_of_trust`: the root of trust for the data placed in the table, if any;
    ///   `OffChainRootOfTrust::Dummy` is expected if there is no root of trust for the table
    /// - `prev_epoch_proof`: The final IVC proof for the off-chain table, proving updates up to the table up
    ///   to the previous epoch, if any
    /// - `table_rows` : Rows to be added to the table; they are assumed to all have the same primary index
    /// - `row_unique_columns` : The identifiers of the columns that uniquely identifies each row (i.e., primary key
    ///   columns)
    pub fn new_no_provable_input<
        PrimaryIndex: PartialEq + Eq + Default + Clone + Debug + TryInto<U256>,
    >(
        primary_index: PrimaryIndex,
        root_of_trust: OffChainRootOfTrust,
        prev_epoch_proof: Option<Vec<u8>>,
        table_rows: &[TableRow],
        row_unique_columns: &[ColumnID],
    ) -> Result<Self>
    where
        <PrimaryIndex as TryInto<U256>>::Error: Debug,
    {
        let prev_root_of_trust = prev_epoch_proof.map_or_else(
            || anyhow::Ok(HashOutput::default()), // any value would be ok as prev_root_of_trust if there is no previous epoch proof
            |prev_proof| {
                let prev_proof = ProofWithVK::deserialize(&prev_proof)?;
                let pis = IvcPublicInputs::from_slice(&prev_proof.proof().public_inputs);
                Ok(pis.block_hash_output())
            },
        )?;
        let [root_of_trust, prev_root_of_trust] =
            [root_of_trust.hash(), prev_root_of_trust].map(|h| {
                h.pack(mp2_common::utils::Endianness::Little)
                    .into_iter()
                    .map(F::from_canonical_u32)
                    .collect_vec()
                    .try_into()
                    .unwrap()
            });
        ensure!(
            !table_rows.is_empty(),
            "At least one row should be provided as input to construct a table"
        );
        let column_ids = table_rows[0].column_ids();
        let metadata_digest = no_provable_metadata_digest(column_ids);
        let row_digest = compute_table_row_digest(table_rows, row_unique_columns)?;

        Ok(Self::NoProvable(DummyCircuit::new(
            primary_index
                .try_into()
                .map_err(|e| anyhow!("while converting primary index to U256: {e:?}"))?,
            root_of_trust,
            prev_root_of_trust,
            metadata_digest,
            row_digest,
        )))
    }
}

#[cfg(test)]
mod tests {
    use crate::{C, D, F};
    use mp2_common::proof::{serialize_proof, ProofWithVK};
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
