use mp2_common::{types::HashOutput, utils::ToFields};
use mp2_v1::{
    api::{self, ProofWithVK},
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
            &self.params(),
            api::CircuitInput::FinalExtraction(circuit_input),
        )?)?;

        let block = self.query_block().await;
        let block_hash = HashOutput(
            block
                .hash
                .unwrap()
                .as_fixed_bytes()
                .to_owned()
                .try_into()
                .unwrap(),
        );
        let prev_block_hash = HashOutput(
            block
                .parent_hash
                .as_fixed_bytes()
                .to_owned()
                .try_into()
                .unwrap(),
        );

        let pis = PublicInputs::from_slice(proof.proof().public_inputs.as_slice());
        assert_eq!(pis.block_number(), block.number.unwrap());
        assert_eq!(pis.block_hash_raw(), block_hash.to_fields());
        assert_eq!(pis.prev_block_hash_raw(), prev_block_hash.to_fields());

        Ok(proof)
    }
}