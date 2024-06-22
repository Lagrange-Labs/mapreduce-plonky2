mod public_inputs;

#[cfg(test)]
mod tests;

use std::array;

use mp2_common::{
    array::{Array, Vector, VectorWire, L32},
    keccak::{InputData, KeccakCircuit, KeccakWires, OutputHash, HASH_LEN, PACKED_HASH_LEN},
    public_inputs::PublicInputCommon,
    rlp::extract_be_value,
    types::{CBuilder, GFp},
    utils::{less_than, Endianness, PackerTarget},
    D,
};
use plonky2::{
    field::types::Field,
    iop::{target::Target, witness::PartialWitness},
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use serde::{Deserialize, Serialize};

use public_inputs::PublicInputs;

/// Parent hash offset in RLP encoded header.
const HEADER_PARENT_HASH_OFFSET: usize = 4;

/// State root offset in RLP encoded header.
const HEADER_STATE_ROOT_OFFSET: usize = 91;

/// Block number offset in RLP encoded header.
const HEADER_BLOCK_NUMBER_OFFSET: usize = 450;
const HEADER_BLOCK_NUMBER_LEN: usize = HEADER_BLOCK_NUMBER_OFFSET - 1;

/// RLP header offset for the block number length.
const HEADER_BLOCK_NUMBER_LENGTH_OFFSET: usize = 128;

/// The wires structure for the block extraction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockWires<const BLOCK_HEADER_MAX_LEN: usize> {
    /// Block hash.
    pub(crate) bh: KeccakWires<BLOCK_HEADER_MAX_LEN>,

    /// RLP encoded bytes of block header.
    pub(crate) rlp_headers: VectorWire<Target, BLOCK_HEADER_MAX_LEN>,
}

/// The circuit definition for the block extraction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockCircuit<const BLOCK_HEADER_MAX_LEN: usize> {
    /// RLP encoded bytes of block header.
    pub rlp_headers: Vec<u8>,
}

impl<const BLOCK_HEADER_MAX_LEN: usize> BlockCircuit<BLOCK_HEADER_MAX_LEN> {
    /// Creates a new instance of the circuit.
    pub fn new(rlp_headers: &[u8]) -> anyhow::Result<Self> {
        KeccakCircuit::<BLOCK_HEADER_MAX_LEN>::new_unpadded(rlp_headers).map(|c| Self {
            rlp_headers: c.data,
        })
    }

    /// Build the circuit, assigning the public inputs and returning the internal wires.
    pub fn build(cb: &mut CBuilder) -> BlockWires<BLOCK_HEADER_MAX_LEN>
    where
        [(); L32(HASH_LEN)]:,
    {
        let zero = cb.zero();
        let one = cb.one();

        let rlp_headers = VectorWire::new(cb);

        // header must be bytes
        rlp_headers.assert_bytes(cb);

        // extract the previous block hash from the RLP header
        let prev_bh =
            &rlp_headers.arr.arr[HEADER_PARENT_HASH_OFFSET..HEADER_PARENT_HASH_OFFSET + HASH_LEN];
        let prev_bh: Vec<U32Target> = Array::<_, HASH_LEN>::try_from(prev_bh)
            .unwrap()
            .arr
            .pack(cb, Endianness::Little);
        let prev_bh_targets: Vec<_> = prev_bh.iter().copied().map(|t| t.0).collect();

        // extract the state root of the block
        let sh =
            &rlp_headers.arr.arr[HEADER_STATE_ROOT_OFFSET..HEADER_STATE_ROOT_OFFSET + HASH_LEN];
        let sh: Vec<U32Target> = Array::<_, HASH_LEN>::try_from(sh)
            .unwrap()
            .arr
            .pack(cb, Endianness::Little);
        let sh: Vec<_> = sh.iter().copied().map(|t| t.0).collect();

        // compute the block hash
        let bh_wires = KeccakCircuit::hash_vector(cb, &rlp_headers);
        let bh = array::from_fn::<_, PACKED_HASH_LEN, _>(|i| bh_wires.output_array.arr[i].0);

        // extract the block number from the RLP header
        let bn = extract_be_value::<_, D, 4>(cb, &rlp_headers.arr.arr, HEADER_BLOCK_NUMBER_LEN);

        PublicInputs::new(&bh, &prev_bh_targets, &bn, &sh).register(cb);

        BlockWires {
            bh: bh_wires,
            rlp_headers,
        }
    }

    /// Assigns the values of this instance into the provided partial witness, using the generated
    /// circuit wires.
    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &BlockWires<BLOCK_HEADER_MAX_LEN>) {
        let rlp =
            Vector::from_vec(&self.rlp_headers).expect("the length of the bh rlp is validated");

        wires.rlp_headers.assign(pw, &rlp);

        KeccakCircuit::<BLOCK_HEADER_MAX_LEN>::assign(pw, &wires.bh, &InputData::Assigned(&rlp));
    }
}
