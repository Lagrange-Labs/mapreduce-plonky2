use log::debug;
use mp2_common::{digest::TableDimension, proof::ProofWithVK, types::HashOutput, utils::ToFields};
use mp2_v1::{
    api,
    final_extraction::{CircuitInput, PublicInputs},
};

use super::TestContext;
use anyhow::Result;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractionTableProof {
    pub value_proof: Vec<u8>,
    pub dimension: TableDimension,
    pub length_proof: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeExtractionProof {
    // NOTE: Right now hardcoding for single and mapping but that can be generalized later easily.
    pub single: ExtractionTableProof,
    pub mapping: ExtractionTableProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtractionProofInput {
    Single(ExtractionTableProof),
    Merge(MergeExtractionProof),
}

impl TestContext {
    pub(crate) async fn prove_final_extraction(
        &self,
        contract_proof: Vec<u8>,
        block_proof: Vec<u8>,
        value_proofs: ExtractionProofInput,
    ) -> Result<Vec<u8>> {
        let circuit_input = match value_proofs {
            ExtractionProofInput::Single(inputs) if inputs.length_proof.is_some() => {
                CircuitInput::new_lengthed_input(
                    block_proof,
                    contract_proof,
                    inputs.value_proof,
                    inputs.length_proof.unwrap(),
                )
            }
            ExtractionProofInput::Single(inputs) => CircuitInput::new_simple_input(
                block_proof,
                contract_proof,
                inputs.value_proof,
                inputs.dimension,
            ),
            // NOTE hardcoded for single and mapping right now
            ExtractionProofInput::Merge(inputs) => CircuitInput::new_merge_single_and_mapping(
                block_proof,
                contract_proof,
                inputs.single.value_proof,
                inputs.mapping.value_proof,
            ),
        }?;
        let params = self.params();
        let proof = self
            .b
            .bench("indexing::extraction::final", || {
                api::generate_proof(params, api::CircuitInput::FinalExtraction(circuit_input))
            })
            .expect("unable to generate final extraction proof");

        let pproof = ProofWithVK::deserialize(&proof)?;
        let block = self.query_current_block().await;

        let block_hash = HashOutput::from(block.header.hash.unwrap().0);
        let prev_block_hash = HashOutput::from(block.header.parent_hash.0);

        let pis = PublicInputs::from_slice(pproof.proof().public_inputs.as_slice());
        assert_eq!(pis.block_number(), block.header.number.unwrap());
        assert_eq!(pis.block_hash_raw(), block_hash.to_fields());
        assert_eq!(pis.prev_block_hash_raw(), prev_block_hash.to_fields());
        debug!(" FINAL EXTRACTION MPT - digest: {:?}", pis.value_point());

        Ok(proof)
    }
}
