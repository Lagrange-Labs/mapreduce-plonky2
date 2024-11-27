use super::TestContext;
use alloy::primitives::U256;
use anyhow::Result;
use log::debug;
use mp2_common::{
    digest::{Digest, TableDimension},
    proof::ProofWithVK,
    types::HashOutput,
    utils::ToFields,
};
use mp2_v1::{
    api,
    final_extraction::{CircuitInput, PublicInputs},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractionTableProof {
    pub value_proof: Vec<u8>,
    pub dimension: TableDimension,
    pub length_proof: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalExtractionProof {
    pub inner: ExtractionTableProof,
    pub block_proof: Vec<u8>,
    pub contract_proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeExtractionProof {
    // NOTE: Right now hardcoding for single and mapping but that can be generalized later easily.
    pub single: ExtractionTableProof,
    pub mapping: ExtractionTableProof,
    pub block_proof: Vec<u8>,
    pub contract_proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoProvableExtractionProof {
    pub is_merge: bool,
    pub block_hash: HashOutput,
    pub prev_block_hash: HashOutput,
    pub block_number: U256,
    pub metadata_digest: Digest,
    pub row_digest: Digest,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtractionProofInput {
    Normal(NormalExtractionProof),
    Merge(MergeExtractionProof),
    NoProvable(NoProvableExtractionProof),
}

impl TestContext {
    pub(crate) async fn prove_final_extraction(
        &self,
        value_proofs: ExtractionProofInput,
    ) -> Result<Vec<u8>> {
        let block = self.query_current_block().await;

        let circuit_input = match value_proofs {
            ExtractionProofInput::Normal(inputs) => {
                if inputs.inner.length_proof.is_some() {
                    CircuitInput::new_lengthed_input(
                        inputs.block_proof,
                        inputs.contract_proof,
                        inputs.inner.value_proof,
                        inputs.inner.length_proof.unwrap(),
                    )
                } else {
                    CircuitInput::new_simple_input(
                        inputs.block_proof,
                        inputs.contract_proof,
                        inputs.inner.value_proof,
                        inputs.inner.dimension,
                    )
                }
            }
            // NOTE hardcoded for single and mapping right now
            ExtractionProofInput::Merge(inputs) => CircuitInput::new_merge_single_and_mapping(
                inputs.block_proof,
                inputs.contract_proof,
                inputs.single.value_proof,
                inputs.mapping.value_proof,
            ),
            ExtractionProofInput::NoProvable(inputs) => Ok(CircuitInput::new_no_provable_input(
                inputs.is_merge,
                inputs.block_hash,
                inputs.prev_block_hash,
                inputs.block_number,
                inputs.metadata_digest,
                inputs.row_digest,
            )),
        }?;
        let params = self.params();
        let proof = self
            .b
            .bench("indexing::extraction::final", || {
                api::generate_proof(params, api::CircuitInput::FinalExtraction(circuit_input))
            })
            .expect("unable to generate final extraction proof");

        let pproof = ProofWithVK::deserialize(&proof)?;

        let block_hash = HashOutput::from(block.header.hash.0);
        let prev_block_hash = HashOutput::from(block.header.parent_hash.0);

        let pis = PublicInputs::from_slice(pproof.proof().public_inputs.as_slice());
        assert_eq!(pis.block_number(), block.header.number);
        assert_eq!(pis.block_hash_raw(), block_hash.to_fields());
        assert_eq!(pis.prev_block_hash_raw(), prev_block_hash.to_fields());
        debug!(" FINAL EXTRACTION MPT - digest: {:?}", pis.value_point());

        Ok(proof)
    }
}
