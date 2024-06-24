use anyhow::Result;
use mp2_common::{eth::BlockUtil, C, D, F};
use mp2_v1::{
    api::{self, deserialize_proof},
    block_extraction,
};

use super::TestContext;

impl TestContext {
    pub(crate) async fn prove_block_extraction(&self) -> Result<()> {
        let block = self.query_block().await;
        let buffer = block.rlp();
        let proof = api::generate_proof(
            self.params(),
            api::CircuitInput::BlockExtraction(block_extraction::CircuitInput::from_block_header(
                buffer,
            )),
        )?;
        let p2_proof = deserialize_proof::<F, C, D>(&proof)?;
        let pi = block_extraction::PublicInputs::from_slice(&p2_proof.public_inputs);
        //let block_number =
        //    left_pad_generic::<u32, NUM_LIMBS>(&block_number_buff.pack(Endianness::Big))
        //        .to_fields();
        Ok(())
    }
}
