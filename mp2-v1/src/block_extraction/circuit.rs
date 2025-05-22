use super::public_inputs;
use anyhow::{ensure, Result};
use std::array::from_fn as create_array;

use crate::{CBuilder, F as GFp};
use mp2_common::{
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires, HASH_LEN},
    mpt_sequential::{utils::left_pad_leaf_value, PAD_LEN},
    public_inputs::PublicInputCommon,
    types::MAX_BLOCK_LEN,
    u256::UInt256Target,
    utils::{Endianness, ToTargets},
};
use plonky2::iop::{target::Target, witness::PartialWitness};
use serde::{Deserialize, Serialize};

use public_inputs::PublicInputs;

/// Parent hash offset in RLP encoded header.
const HEADER_PARENT_HASH_OFFSET: usize = 4;

/// State root offset in RLP encoded header.
const HEADER_STATE_ROOT_OFFSET: usize = 91;

/// Block number offset in RLP encoded header.
const HEADER_BLOCK_NUMBER_OFFSET: usize = 449;
/// We define u64 as the maximum block mnumber ever to be reached
/// +1 to include the RLP header when we read from the buffer - technical detail.
const MAX_BLOCK_NUMBER_LEN: usize = 8 + 1;

/// NOTE: Fixing the header len here since problem with const generics
/// prevents to use methods like `pack()`. It doesn't really change the
/// semantics since changing a const generic or a const is the same.
/// TODO: solve that.
const PADDED_HEADER_LEN: usize = PAD_LEN(MAX_BLOCK_LEN);

/// The wires structure for the block extraction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockWires {
    /// Block hash.
    pub(crate) bh: KeccakWires<PADDED_HEADER_LEN>,
    /// RLP encoded bytes of block header. Padded by circuit.
    pub(crate) rlp_headers: VectorWire<Target, PADDED_HEADER_LEN>,
}

/// The circuit definition for the block extraction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockCircuit {
    /// RLP encoded bytes of block header.
    pub rlp_headers: Vec<u8>,
}

impl BlockCircuit {
    /// Creates a new instance of the circuit.
    pub fn new(rlp_headers: Vec<u8>) -> Result<Self> {
        ensure!(
            rlp_headers.len() <= MAX_BLOCK_LEN,
            "block rlp headers too long: found {}, max {MAX_BLOCK_LEN}",
            rlp_headers.len()
        );
        Ok(Self { rlp_headers })
    }

    /// Build the circuit, assigning the public inputs and returning the internal wires.
    pub fn build(cb: &mut CBuilder) -> BlockWires {
        // already right padded to right size for keccak
        let rlp_headers = VectorWire::new(cb);

        // header must be bytes
        rlp_headers.assert_bytes(cb);

        // extract the previous block hash from the RLP header
        let prev_bh = Array::<Target, HASH_LEN>::from_array(create_array(|i| {
            rlp_headers.arr.arr[HEADER_PARENT_HASH_OFFSET + i]
        }));
        let packed_prev_bh = prev_bh.pack(cb, Endianness::Little).downcast_to_targets();

        // extract the state root of the block
        let state_root = Array::<Target, HASH_LEN>::from_array(create_array(|i| {
            rlp_headers.arr.arr[HEADER_STATE_ROOT_OFFSET + i]
        }));
        let state_root_packed = state_root.pack(cb, Endianness::Little);

        // compute the block hash
        let bh_wires = KeccakCircuit::hash_vector(cb, &rlp_headers);

        // extract the block number from the RLP header
        let block_number = Array::<Target, MAX_BLOCK_NUMBER_LEN>::from_array(create_array(|i| {
            rlp_headers.arr.arr[HEADER_BLOCK_NUMBER_OFFSET + i]
        }));
        // TODO: put that in array

        let bn_u256: Array<Target, 32> = left_pad_leaf_value(cb, &block_number);
        let bn_u256 = bn_u256.pack(cb, Endianness::Big);
        // safe to unwrap because packing 32 bytes gives 8 u32 limbs
        let bn_u256: UInt256Target = bn_u256.into();

        PublicInputs::new(
            &bh_wires.output_array.downcast_to_targets().arr,
            &packed_prev_bh.downcast_to_targets().arr,
            &bn_u256.to_targets(),
            &state_root_packed.downcast_to_targets().arr,
        )
        .register(cb);

        BlockWires {
            bh: bh_wires,
            rlp_headers,
        }
    }

    /// Assigns the values of this instance into the provided partial witness, using the generated
    /// circuit wires.
    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &BlockWires) {
        // this already pads the rlp header to the right size for keccak
        let rlp =
            Vector::from_vec(&self.rlp_headers).expect("the length of the bh rlp is validated");

        wires.rlp_headers.assign(pw, &rlp);

        KeccakCircuit::assign(pw, &wires.bh, &InputData::Assigned(&rlp));
    }
}

#[cfg(test)]
mod test {

    use alloy::{
        eips::BlockNumberOrTag,
        providers::{Provider, ProviderBuilder},
    };
    use mp2_common::{eth::left_pad_generic, u256, utils::ToFields, C, F};

    use mp2_common::{
        eth::BlockUtil,
        types::CBuilder,
        utils::{Endianness, Packer},
        D,
    };
    use mp2_test::{
        circuit::{prove_circuit, setup_circuit, UserCircuit},
        eth::get_sepolia_url,
    };

    use plonky2::iop::witness::PartialWitness;

    use super::{public_inputs::PublicInputs, BlockCircuit, BlockWires};
    use anyhow::Result;

    pub type SepoliaBlockCircuit = BlockCircuit;

    #[tokio::test]
    async fn prove_and_verify_block_extraction_circuit() -> Result<()> {
        let url = get_sepolia_url();
        let provider = ProviderBuilder::new().connect_http(url.parse().unwrap());
        let block_number = BlockNumberOrTag::Latest;
        let block = provider
            .get_block_by_number(block_number)
            .full()
            .await
            .unwrap()
            .unwrap();

        let rlp_headers = block.rlp();

        let prev_block_hash = block
            .header
            .parent_hash
            .0
            .pack(Endianness::Little)
            .to_fields();
        let block_hash = block.block_hash().pack(Endianness::Little).to_fields();
        let state_root = block
            .header
            .state_root
            .0
            .pack(Endianness::Little)
            .to_fields();
        let block_number_buff = block.header.number.to_be_bytes();
        const NUM_LIMBS: usize = u256::NUM_LIMBS;
        let block_number =
            left_pad_generic::<u32, NUM_LIMBS>(&block_number_buff.pack(Endianness::Big))
                .to_fields();

        let setup = setup_circuit::<_, D, C, SepoliaBlockCircuit>();
        let circuit = SepoliaBlockCircuit::new(rlp_headers).unwrap();
        let proof = prove_circuit(&setup, &circuit);
        let pi = PublicInputs::<F>::from_slice(&proof.public_inputs);

        assert_eq!(pi.prev_block_hash_raw(), &prev_block_hash);
        assert_eq!(pi.block_hash_raw(), &block_hash);
        assert_eq!(
            pi.block_hash_raw(),
            block.header.hash.0.pack(Endianness::Little).to_fields()
        );
        assert_eq!(pi.state_root_raw(), &state_root);
        assert_eq!(pi.block_number_raw(), &block_number);
        Ok(())
    }

    impl UserCircuit<F, D> for BlockCircuit {
        type Wires = BlockWires;

        fn build(cb: &mut CBuilder) -> Self::Wires {
            Self::build(cb)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.assign(pw, wires);
        }
    }
}
