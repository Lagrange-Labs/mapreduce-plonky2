use alloy::primitives::U256;
use anyhow::Result;
use mp2_common::{
    eth::BlockUtil,
    proof::deserialize_proof,
    utils::{Endianness, Packer, ToFields},
    C, D, F,
};
use mp2_v1::{api, block_extraction, indexing::block::BlockPrimaryIndex};

use super::TestContext;

impl TestContext {
    pub(crate) async fn prove_block_extraction(&self, bn: BlockPrimaryIndex) -> Result<Vec<u8>> {
        let block = self
            .query_block_at(alloy::eips::BlockNumberOrTag::Number(bn as u64))
            .await;
        let buffer = block.rlp();
        let proof = self.b.bench("indexing::extraction::block", || {
            api::generate_proof(
                self.params(),
                api::CircuitInput::BlockExtraction(
                    block_extraction::CircuitInput::from_block_header(buffer.clone()),
                ),
            )
        })?;

        let pproof = deserialize_proof::<F, C, D>(&proof)?;
        let pi = block_extraction::PublicInputs::from_slice(&pproof.public_inputs);
        let block_number = U256::from(block.header.number.unwrap()).to_fields();
        let block_hash = block
            .header
            .hash
            .unwrap()
            .as_slice()
            .pack(Endianness::Little)
            .to_fields();
        let prev_block_hash = block
            .header
            .parent_hash
            .as_slice()
            .pack(Endianness::Little)
            .to_fields();

        assert_eq!(pi.block_number_raw(), &block_number);
        assert_eq!(pi.block_hash_raw(), block_hash);
        assert_eq!(pi.prev_block_hash_raw(), prev_block_hash);

        Ok(proof)
    }
}
