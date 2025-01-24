use alloy::primitives::U256;
use log::debug;
use mp2_common::{digest::TableDimension, proof::ProofWithVK, types::HashOutput, utils::ToFields};
use mp2_v1::{
    api,
    final_extraction::{CircuitInput, PublicInputs},
    indexing::{block::BlockPrimaryIndex, row::CellCollection},
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
pub(crate) struct OffChainExtractionProof {
    pub(crate) hash: HashOutput,
    pub(crate) prev_hash: HashOutput,
    pub(crate) primary_index: BlockPrimaryIndex,
    pub(crate) rows: Vec<CellCollection<BlockPrimaryIndex>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtractionProofInput {
    Single(ExtractionTableProof),
    Merge(MergeExtractionProof),
    Offchain(OffChainExtractionProof),
}

impl TestContext {
    pub(crate) async fn prove_final_extraction(
        &self,
        contract_proof: Vec<u8>,
        block_proof: Vec<u8>,
        value_proofs: ExtractionProofInput,
    ) -> Result<Vec<u8>> {
        // first, extract block number, hash and previous block hash to later check public inputs
        let (primary_index, block_hash, prev_block_hash) =
            if let ExtractionProofInput::Offchain(inputs) = &value_proofs {
                (inputs.primary_index as u64, inputs.hash, inputs.prev_hash)
            } else {
                let block = self.query_current_block().await;
                let primary_index = block.header.number;
                let block_hash = HashOutput::from(block.header.hash.0);
                let prev_block_hash = HashOutput::from(block.header.parent_hash.0);

                (primary_index, block_hash, prev_block_hash)
            };
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
            ExtractionProofInput::Offchain(inputs) => CircuitInput::new_no_provable_input(
                U256::from(inputs.primary_index),
                inputs.hash,
                inputs.prev_hash,
                inputs.rows.as_slice(),
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

        let pis = PublicInputs::from_slice(pproof.proof().public_inputs.as_slice());
        assert_eq!(pis.block_number(), primary_index);
        assert_eq!(pis.block_hash_raw(), block_hash.to_fields());
        assert_eq!(pis.prev_block_hash_raw(), prev_block_hash.to_fields());
        debug!(" FINAL EXTRACTION MPT - digest: {:?}", pis.value_point());

        Ok(proof)
    }
}
