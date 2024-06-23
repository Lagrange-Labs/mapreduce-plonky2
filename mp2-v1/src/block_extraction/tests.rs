use std::array::from_fn as create_array;

use ethers::{
    providers::{Http, Middleware, Provider},
    types::{BlockNumber, U256},
    utils::keccak256,
};
use mp2_common::{
    eth::{left_pad, left_pad32, left_pad_generic},
    u256,
    utils::ToFields,
};

use mp2_common::{
    eth::BlockUtil,
    types::{CBuilder, GFp},
    utils::{Endianness, Packer},
    D,
};
use mp2_test::{
    circuit::{prove_circuit, setup_circuit, UserCircuit},
    eth::get_sepolia_url,
};
use plonky2::{
    field::types::Field, iop::witness::PartialWitness, plonk::config::PoseidonGoldilocksConfig,
};

use crate::block_extraction::{HEADER_BLOCK_NUMBER_OFFSET, MAX_BLOCK_NUMBER_LEN};

use super::{
    public_inputs::PublicInputs,
    {BlockCircuit, BlockWires},
};
use anyhow::Result;

pub type SepoliaBlockCircuit = BlockCircuit;

#[tokio::test]
async fn prove_and_verify_block_extraction_circuit() -> Result<()> {
    let url = get_sepolia_url();
    let provider = Provider::<Http>::try_from(url).unwrap();
    let block_number = BlockNumber::Latest;
    let block = provider.get_block(block_number).await.unwrap().unwrap();

    let rlp_headers = block.rlp();

    let prev_block_hash = block
        .parent_hash
        .0
        .to_vec()
        .pack(Endianness::Little)
        .to_fields();
    let block_hash = block.block_hash().pack(Endianness::Little).to_fields();
    let state_root = block
        .state_root
        .0
        .to_vec()
        .pack(Endianness::Little)
        .to_fields();
    let mut block_number_buff = [0u8; 8];
    block
        .number
        .unwrap()
        .to_big_endian(&mut block_number_buff[..]);
    const NUM_LIMBS: usize = u256::NUM_LIMBS;
    let block_number =
        left_pad_generic::<u32, NUM_LIMBS>(&block_number_buff.pack(Endianness::Big)).to_fields();

    let setup = setup_circuit::<_, D, PoseidonGoldilocksConfig, SepoliaBlockCircuit>();
    let circuit = SepoliaBlockCircuit::new(&rlp_headers).unwrap();
    let proof = prove_circuit(&setup, &circuit);
    let pi = PublicInputs::<GFp>::from_slice(&proof.public_inputs);

    assert_eq!(pi.prev_block_hash_raw(), &prev_block_hash);
    assert_eq!(pi.block_hash_raw(), &block_hash);
    assert_eq!(pi.state_root_raw(), &state_root);
    assert_eq!(pi.block_number_raw(), &block_number);
    Ok(())
}

impl UserCircuit<GFp, D> for BlockCircuit {
    type Wires = BlockWires;

    fn build(cb: &mut CBuilder) -> Self::Wires {
        Self::build(cb)
    }

    fn prove(&self, pw: &mut PartialWitness<GFp>, wires: &Self::Wires) {
        self.assign(pw, wires);
    }
}
