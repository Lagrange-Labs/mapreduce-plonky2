use std::array;

use mp2_common::{
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires, OutputHash, HASH_LEN, PACKED_HASH_LEN},
    public_inputs::PublicInputCommon,
    types::{CBuilder, GFp},
    utils::less_than,
};
use plonky2::{
    field::types::Field,
    iop::{target::Target, witness::PartialWitness},
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use serde::{Deserialize, Serialize};

use super::public_inputs::PublicInputs;

/// Length of the block RLP header.
///
/// TODO: define & export this constant.
pub const BLOCK_HEADER_RLP_LEN: usize = 620;

/// Parent hash offset in RLP encoded header.
const HEADER_RLP_PARENT_HASH_OFFSET: usize = 4;

/// State root offset in RLP encoded header.
const HEADER_RLP_STATE_ROOT_OFFSET: usize = 91;

/// Block number offset in RLP encoded header.
const HEADER_RLP_BLOCK_NUMBER_OFFSET: usize = 450;
const HEADER_RLP_BLOCK_NUMBER_LEN: usize = HEADER_RLP_BLOCK_NUMBER_OFFSET - 1;

/// RLP header offset for the block number length.
const HEADER_RLP_BLOCK_NUMBER_RLP_LENGTH_OFFSET: usize = 128;

/// Maximum supported length of the RLP length to the block number.
const HEADER_RLP_BLOCK_NUMBER_RLP_LENGTH_MAX: usize = 4;

/// The wires structure for the block extraction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockWires {
    /// Block hash.
    pub(crate) bh: KeccakWires<BLOCK_HEADER_RLP_LEN>,

    /// Previous block hash.
    pub(crate) prev_bh: OutputHash,

    /// Block number.
    pub(crate) bn: U32Target,

    /// RLP encoded bytes of block header.
    pub(crate) bh_rlp: VectorWire<Target, BLOCK_HEADER_RLP_LEN>,
}

/// The circuit definition for the block extraction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockCircuit<const BN_RLP_PAD: usize> {
    /// RLP encoded bytes of block header.
    bh_rlp: Vec<u8>,
}

impl<const BN_RLP_PAD: usize> BlockCircuit<BN_RLP_PAD> {
    /// Creates a new instance of the circuit.
    pub fn new(bh_rlp: Vec<u8>) -> Self {
        assert!(
            BN_RLP_PAD <= HEADER_RLP_BLOCK_NUMBER_RLP_LENGTH_MAX,
            "the RLP block number len is not supported"
        );
        assert_eq!(
            bh_rlp.len(),
            BLOCK_HEADER_RLP_LEN,
            "the provided RLP encoded block header has an invalid length"
        );

        Self { bh_rlp }
    }

    /// Build the circuit, assigning the public inputs and returning the internal wires.
    pub fn build(cb: &mut CBuilder) -> BlockWires {
        let zero = cb.zero();

        let bh_rlp = VectorWire::new(cb);

        // header must be bytes
        bh_rlp.assert_bytes(cb);

        // extract the previous block hash from the RLP header
        let prev_bh_targets = &bh_rlp.arr.arr
            [HEADER_RLP_PARENT_HASH_OFFSET..HEADER_RLP_PARENT_HASH_OFFSET + HASH_LEN];
        let prev_bh = OutputHash {
            arr: array::from_fn(|i| U32Target(prev_bh_targets[i])),
        };

        // extract the state root of the block
        let sh =
            &bh_rlp.arr.arr[HEADER_RLP_STATE_ROOT_OFFSET..HEADER_RLP_STATE_ROOT_OFFSET + HASH_LEN];

        // compute the block hash
        let bh_wires = KeccakCircuit::hash_vector(cb, &bh_rlp);
        let bh = array::from_fn::<_, PACKED_HASH_LEN, _>(|i| bh_wires.output_array.arr[i].0);

        // the RLP length for the block number might vary depending on the used chain
        let bn_length_offset = GFp::from_canonical_usize(HEADER_RLP_BLOCK_NUMBER_RLP_LENGTH_OFFSET);
        let bn_length_offset = cb.constant(bn_length_offset);
        let bn_len = cb.sub(
            bh_rlp.arr.arr[HEADER_RLP_BLOCK_NUMBER_LEN],
            bn_length_offset,
        );

        // extracts the RLP length for the block number, assumed to be max 4xu32 limbs
        let bn_rlp_len = array::from_fn::<_, 4, _>(|i| {
            (i < BN_RLP_PAD)
                .then_some(bh_rlp.arr.arr[HEADER_RLP_BLOCK_NUMBER_OFFSET + BN_RLP_PAD - 1 - i])
                .unwrap_or(zero)
        });
        let bn_rlp_len = Array::from(bn_rlp_len);
        let bn_rlp_len = bn_rlp_len.convert_u8_to_u32(cb)[0];

        // endianness-aware computation of the block number from the rlp header
        let shift_bits = GFp::from_canonical_u8(255);
        let bn = (BN_RLP_PAD..4).fold(bn_rlp_len.0, |n, i| {
            let index = cb.constant(GFp::from_canonical_usize(i));
            let is_block_number_byte = less_than(cb, index, bn_len, 2);
            let current_byte = bh_rlp.arr.arr[HEADER_RLP_BLOCK_NUMBER_OFFSET + i];
            let shifted_number = cb.mul_const_add(shift_bits, n, current_byte);

            cb.mul_add(is_block_number_byte.target, shifted_number, n)
        });
        let bn = U32Target(bn);

        PublicInputs::new(&bh, &prev_bh_targets, &bn.0, sh).register(cb);

        BlockWires {
            bh: bh_wires,
            prev_bh,
            bn,
            bh_rlp,
        }
    }

    /// Assigns the values of this instance into the provided partial witness, using the generated
    /// circuit wires.
    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &BlockWires) {
        let rlp = Vector::from_vec(&self.bh_rlp).expect("the length of the bh rlp is validated");

        wires.bh_rlp.assign(pw, &rlp);

        KeccakCircuit::<BLOCK_HEADER_RLP_LEN>::assign(pw, &wires.bh, &InputData::Assigned(&rlp));
    }
}
