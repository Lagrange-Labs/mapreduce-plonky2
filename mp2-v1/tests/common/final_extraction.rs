use log::debug;
use mp2_common::{
    group_hashing::weierstrass_to_point, proof::ProofWithVK, types::HashOutput, utils::ToFields, F,
};
use mp2_v1::{
    api, contract_extraction,
    final_extraction::{CircuitInput, OffChainRootOfTrust, PublicInputs},
    indexing::{block::BlockPrimaryIndex, row::CellCollection, ColumnID},
    values_extraction,
};

use super::TestContext;
use anyhow::Result;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractionTableProof {
    pub value_proof: Vec<u8>,
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
    pub(crate) hash: OffChainRootOfTrust,
    pub(crate) prev_hash: HashOutput,
    pub(crate) primary_index: BlockPrimaryIndex,
    pub(crate) rows: Vec<CellCollection<BlockPrimaryIndex>>,
    pub(crate) primary_key_columns: Vec<ColumnID>,
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
                (
                    inputs.primary_index as u64,
                    inputs.hash.hash(),
                    inputs.prev_hash,
                )
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
            ExtractionProofInput::Single(inputs) => {
                {
                    let value_proof = ProofWithVK::deserialize(&inputs.value_proof).unwrap();
                    let value_pi = values_extraction::PublicInputs::<F>::new(
                        &value_proof.proof().public_inputs,
                    );
                    let contract_proof = ProofWithVK::deserialize(&contract_proof).unwrap();
                    let contract_pi = contract_extraction::PublicInputs::from_slice(
                        &contract_proof.proof().public_inputs,
                    );
                    debug!(
                        "BEFORE proving final extraction:\n\tvalues_ex_md = {:?}\n\tcontract_md = {:?}\n\texpected_final_md = {:?}",
                        value_pi.metadata_digest(),
                        contract_pi.metadata_point(),
                        (weierstrass_to_point(&value_pi.metadata_digest()) + weierstrass_to_point(&contract_pi.metadata_point())).to_weierstrass(),
                    );
                }
                CircuitInput::new_simple_input(block_proof, contract_proof, inputs.value_proof)
            }
            // NOTE hardcoded for single and mapping right now
            ExtractionProofInput::Merge(inputs) => CircuitInput::new_merge_single_and_mapping(
                block_proof,
                contract_proof,
                inputs.single.value_proof,
                inputs.mapping.value_proof,
            ),
            ExtractionProofInput::Offchain(inputs) => CircuitInput::new_no_provable_input(
                inputs.primary_index,
                inputs.hash,
                inputs.prev_hash,
                inputs.rows.as_slice(),
                &inputs.primary_key_columns,
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
        debug!(
            " FINAL EXTRACTION MPT -\n\tvalues digest: {:?}\n\tmetadata digest: {:?}",
            pis.value_point(),
            pis.metadata_point(),
        );

        Ok(proof)
    }
}
