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
    ) -> Result<ProofWithVK> {
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
        let proof = ProofWithVK::deserialize(&api::generate_proof(
            self.params(),
            api::CircuitInput::FinalExtraction(circuit_input),
        )?)?;

        let block = self.query_block().await;
        let block_hash = block.hash.unwrap().to_fields();
        let prev_block_hash = block.parent_hash.to_fields();

        let pis = PublicInputs::from_slice(proof.proof().public_inputs.as_slice());
        assert_eq!(pis.block_number(), block.number.unwrap());
        assert_eq!(pis.block_hash_raw(), block_hash);
        assert_eq!(pis.prev_block_hash_raw(), prev_block_hash);

        Ok(proof)
    }
}
