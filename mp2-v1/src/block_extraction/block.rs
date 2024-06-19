use std::array;

use mp2_common::{
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires, OutputHash, HASH_LEN, PACKED_HASH_LEN},
    public_inputs::PublicInputCommon,
    types::{CBuilder, GFp},
    utils::{convert_u8_targets_to_u32, less_than},
};
use plonky2::{
    field::types::Field,
    iop::{target::Target, witness::PartialWitness},
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use serde::{Deserialize, Serialize};

use super::public_inputs::PublicInputs;

/// Parent hash offset in RLP encoded header.
const HEADER_PARENT_HASH_OFFSET: usize = 4;

/// State root offset in RLP encoded header.
const HEADER_STATE_ROOT_OFFSET: usize = 91;

/// Block number offset in RLP encoded header.
const HEADER_BLOCK_NUMBER_OFFSET: usize = 450;
const HEADER_BLOCK_NUMBER_LEN: usize = HEADER_BLOCK_NUMBER_OFFSET - 1;

/// RLP header offset for the block number length.
const HEADER_BLOCK_NUMBER_LENGTH_OFFSET: usize = 128;

/// Maximum supported length of the RLP length to the block number.
const HEADER_BLOCK_NUMBER_LENGTH_MAX: usize = 4;

/// The wires structure for the block extraction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockWires<const BLOCK_HEADER_MAX_LEN: usize> {
    /// Block hash.
    pub(crate) bh: KeccakWires<BLOCK_HEADER_MAX_LEN>,

    /// Previous block hash.
    pub(crate) prev_bh: OutputHash,

    /// Block number.
    /// TODO: should be u256 once #222 is merged
    pub(crate) bn: U32Target,

    /// RLP encoded bytes of block header.
    pub(crate) rlp_headers: VectorWire<Target, BLOCK_HEADER_MAX_LEN>,
}

/// The circuit definition for the block extraction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockCircuit<const BLOCK_HEADER_MAX_LEN: usize, const BLOCK_NUMBER_PAD: usize> {
    /// RLP encoded bytes of block header.
    pub rlp_headers: Vec<u8>,
}

impl<const BLOCK_HEADER_MAX_LEN: usize, const BLOCK_NUMBER_PAD: usize>
    BlockCircuit<BLOCK_HEADER_MAX_LEN, BLOCK_NUMBER_PAD>
{
    /// Creates a new instance of the circuit.
    pub fn new(rlp_headers: &[u8]) -> anyhow::Result<Self> {
        assert!(
            BLOCK_NUMBER_PAD <= HEADER_BLOCK_NUMBER_LENGTH_MAX,
            "the RLP block number len is not supported"
        );

        KeccakCircuit::<BLOCK_HEADER_MAX_LEN>::new_unpadded(rlp_headers).map(|c| Self {
            rlp_headers: c.data,
        })
    }

    /// Build the circuit, assigning the public inputs and returning the internal wires.
    pub fn build(cb: &mut CBuilder) -> BlockWires<BLOCK_HEADER_MAX_LEN> {
        let zero = cb.zero();

        let rlp_headers = VectorWire::new(cb);

        // header must be bytes
        rlp_headers.assert_bytes(cb);

        // extract the previous block hash from the RLP header
        let prev_bh =
            &rlp_headers.arr.arr[HEADER_PARENT_HASH_OFFSET..HEADER_PARENT_HASH_OFFSET + HASH_LEN];
        let prev_bh = OutputHash::pack_u32_from_slice(cb, prev_bh);
        let prev_bh_targets: Vec<_> = prev_bh.arr.iter().copied().map(|t| t.0).collect();

        // extract the state root of the block
        let sh =
            &rlp_headers.arr.arr[HEADER_STATE_ROOT_OFFSET..HEADER_STATE_ROOT_OFFSET + HASH_LEN];
        let sh = OutputHash::pack_u32_from_slice(cb, sh).to_u32_targets();

        // compute the block hash
        let bh_wires = KeccakCircuit::hash_vector(cb, &rlp_headers);
        let bh = array::from_fn::<_, PACKED_HASH_LEN, _>(|i| bh_wires.output_array.arr[i].0);

        // the encoding of the block number can have a variable lengt depending on the used chain.
        // We first read the rlp header to know the length and then extract the length.
        let bn_length_offset = GFp::from_canonical_usize(HEADER_BLOCK_NUMBER_LENGTH_OFFSET);
        let bn_length_offset = cb.constant(bn_length_offset);
        let bn_len = cb.sub(
            rlp_headers.arr.arr[HEADER_BLOCK_NUMBER_LEN],
            bn_length_offset,
        );

        // extracts the RLP length for the block number, assumed to be max 4xu32 limbs
        let bn_rlp_len = array::from_fn::<_, 4, _>(|i| {
            (i < BLOCK_NUMBER_PAD)
                .then_some(
                    rlp_headers.arr.arr[HEADER_BLOCK_NUMBER_OFFSET + BLOCK_NUMBER_PAD - 1 - i],
                )
                .unwrap_or(zero)
        });
        let bn_rlp_len = Array::from(bn_rlp_len);
        let bn_rlp_len = bn_rlp_len.convert_u8_to_u32(cb)[0];

        // endianness-aware computation of the block number from the rlp header
        let shift_bits = GFp::from_canonical_u8(255);
        let bn = (BLOCK_NUMBER_PAD..4).fold(bn_rlp_len.0, |n, i| {
            let index = cb.constant(GFp::from_canonical_usize(i));
            let is_block_number_byte = less_than(cb, index, bn_len, 2);
            let current_byte = rlp_headers.arr.arr[HEADER_BLOCK_NUMBER_OFFSET + i];
            let shifted_number = cb.mul_const_add(shift_bits, n, current_byte);

            cb.mul_add(is_block_number_byte.target, shifted_number, n)
        });
        let bn = U32Target(bn);

        PublicInputs::new(&bh, &prev_bh_targets, &bn.0, &sh.arr).register(cb);

        BlockWires {
            bh: bh_wires,
            prev_bh,
            bn,
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
