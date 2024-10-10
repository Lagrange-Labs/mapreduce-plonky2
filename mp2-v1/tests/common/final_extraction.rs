use mp2_common::{proof::ProofWithVK, types::HashOutput, utils::ToFields};
use mp2_v1::{
    api,
    final_extraction::{CircuitInput, PublicInputs},
};

use super::TestContext;
use anyhow::Result;

impl TestContext {
    pub(crate) async fn prove_final_extraction(
        &self,
        contract_proof: Vec<u8>,
        values_proof: Vec<u8>,
        block_proof: Vec<u8>,
        compound_type: bool,
        length_proof: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let circuit_input = if let Some(length_proof) = length_proof {
            CircuitInput::new_lengthed_input(
                block_proof,
                contract_proof,
                values_proof,
                length_proof,
            )
        } else {
            CircuitInput::new_simple_input(block_proof, contract_proof, values_proof, compound_type)
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

        let block_hash = HashOutput::from(block.header.hash.0);
        let prev_block_hash = HashOutput::from(block.header.parent_hash.0);

        let pis = PublicInputs::from_slice(pproof.proof().public_inputs.as_slice());
        assert_eq!(pis.block_number(), block.header.number);
        assert_eq!(pis.block_hash_raw(), block_hash.to_fields());
        assert_eq!(pis.prev_block_hash_raw(), prev_block_hash.to_fields());

        Ok(proof)
    }
}
