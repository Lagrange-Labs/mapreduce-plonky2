use anyhow::Result;
use ethers::types::U64;
use mp2_common::{
    eth::{left_pad_generic, BlockUtil},
    u256,
    utils::{Endianness, Packer, ToFields},
    C, D, F,
};
use mp2_v1::{
    api::{self, deserialize_proof},
    block_extraction,
};
use plonky2::plonk::proof::ProofWithPublicInputs;

use super::TestContext;

pub(crate) fn block_number_to_u256_limbs(number: U64) -> Vec<F> {
    const NUM_LIMBS: usize = u256::NUM_LIMBS;
    let mut block_number_buff = [0u8; NUM_LIMBS];
    number.to_big_endian(&mut block_number_buff[..]);
    left_pad_generic::<u32, NUM_LIMBS>(&block_number_buff.pack(Endianness::Big)).to_fields()
}

impl TestContext {
    pub(crate) async fn prove_block_extraction(&self) -> Result<ProofWithPublicInputs<F, C, D>> {
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
        let block_number = block_number_to_u256_limbs(block.number.unwrap());
        assert_eq!(pi.block_number_raw(), &block_number);
        Ok(p2_proof)
    }
}