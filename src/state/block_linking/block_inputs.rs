//! This is the block-inputs gadget. It builds the circuit to prove that the
//! hash of state MPT root should be included in the block header.

use crate::{
    array::{Array, Vector, VectorWire},
    keccak::{ByteKeccakWires, InputData, KeccakCircuit, OutputByteHash, OutputHash, HASH_LEN},
    mpt_sequential::PAD_LEN,
    rlp::{decode_compact_encoding, decode_fixed_list, RlpHeader},
    utils::{
        convert_u8_slice_to_u32_fields, find_index_subvector, less_than, PackedU64Target, U64Target,
    },
};
use anyhow::Result;
use ethers::types::H256;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use std::array;

/// Parent hash offset in RLP encoded header
const HEADER_RLP_PARENT_HASH_OFFSET: usize = 4;
/// State root offset in RLP encoded header
const HEADER_RLP_STATE_ROOT_OFFSET: usize = 91;
/// Number offset in RLP encoded header
const HEADER_RLP_NUMBER_OFFSET: usize = 450;

/// The block input wires
pub struct BlockInputsWires<const MAX_LEN: usize>
where
    [(); PAD_LEN(MAX_LEN)]:,
{
    /// Block number
    pub(crate) number: PackedU64Target,
    /// Block parent hash
    pub(crate) parent_hash: OutputHash,
    /// The keccak wires computed from RLP encoded header
    pub(crate) hash: ByteKeccakWires<{ PAD_LEN(MAX_LEN) }>,
    /// The hash bytes of state root
    state_root_bytes: OutputByteHash,
    /// RLP encoded bytes of block header
    pub(crate) header_rlp: VectorWire<Target, MAX_LEN>,
}

/// The block input gadget
#[derive(Clone, Debug)]
pub struct BlockInputs {
    /// The hash bytes of state root
    state_root_bytes: H256,
    /// RLP encoded bytes of block header
    header_rlp: Vec<u8>,
}

impl BlockInputs {
    pub fn new(state_root_bytes: H256, header_rlp: Vec<u8>) -> Self {
        Self {
            state_root_bytes,
            header_rlp,
        }
    }

    /// Build for circuit.
    pub fn build<F, const D: usize, const MAX_LEN: usize>(
        cb: &mut CircuitBuilder<F, D>,
    ) -> BlockInputsWires<MAX_LEN>
    where
        F: RichField + Extendable<D>,
        [(); PAD_LEN(MAX_LEN)]:,
    {
        let state_root_bytes = Array::new(cb);
        let header_rlp = VectorWire::new(cb);

        // Calculate the keccak hash of RLP encoded header.
        let zero = cb.zero();
        let mut arr = [zero; PAD_LEN(MAX_LEN)];
        arr[..MAX_LEN].copy_from_slice(&header_rlp.arr.arr);
        let bytes_to_keccak = &VectorWire::<Target, { PAD_LEN(MAX_LEN) }> {
            real_len: header_rlp.real_len,
            arr: Array { arr },
        };
        let hash = KeccakCircuit::hash_to_bytes(cb, bytes_to_keccak);

        // Get the number from RLP encoded header.
        let number_offset = cb.constant(F::from_canonical_usize(HEADER_RLP_NUMBER_OFFSET));
        let number: U64Target = header_rlp.arr.extract_array(cb, number_offset);
        let number: PackedU64Target = number.convert_u8_to_u32(cb);

        // Get the parent hash from RLP encoded header.
        let parent_hash_offset =
            cb.constant(F::from_canonical_usize(HEADER_RLP_PARENT_HASH_OFFSET));
        let parent_hash: OutputByteHash = header_rlp.arr.extract_array(cb, parent_hash_offset);
        let parent_hash: OutputHash = parent_hash.convert_u8_to_u32(cb);

        /*
                let zero = cb.zero();
                let rlp_headers = decode_fixed_list::<_, _, 9>(cb, &header_rlp.arr.arr, zero);
                let hash_len = cb.constant(F::from_canonical_usize(HASH_LEN));
                cb.connect(rlp_headers.len[0], hash_len);
                cb.connect(rlp_headers.len[8], hash_len);
                        // cb.connect(should_false.target, ffalse.target);
                        cb.connect(kkk.real_len, hash_len);
        */

        BlockInputsWires {
            number,
            parent_hash,
            hash,
            state_root_bytes,
            header_rlp,
        }
    }

    /// Assign the wires.
    pub fn assign<F, const MAX_LEN: usize>(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &BlockInputsWires<MAX_LEN>,
    ) -> Result<()>
    where
        F: RichField,
        [(); PAD_LEN(MAX_LEN)]:,
    {
        // Assign the hash bytes of state root.
        wires
            .state_root_bytes
            .assign(pw, &self.state_root_bytes.0.map(F::from_canonical_u8));

        // Assign the RLP encoded block header.
        wires
            .header_rlp
            .assign(pw, &Vector::from_vec(&self.header_rlp)?);

        // Assign the keccak value of RLP encoded header.
        KeccakCircuit::<{ PAD_LEN(MAX_LEN) }>::assign_byte_keccak(
            pw,
            &wires.hash,
            &InputData::Assigned(
                &Vector::from_vec(&self.header_rlp)
                    .expect("Cannot create vector input for keccak RLP encoded header"),
            ),
        );

        Ok(())
    }

    /// Verify the block header includes the hash of state MPT root. We use an
    /// offset given as wire to indicate where the hash resides in the encoded
    /// block header. The circuit doesn't need to decode the RLP headers as we
    /// rely on the security of the hash function.
    pub fn verify_state_root_hash_inclusion<F, const D: usize, const MAX_LEN: usize>(
        cb: &mut CircuitBuilder<F, D>,
        wires: &BlockInputsWires<MAX_LEN>,
        state_root_hash: &OutputHash,
    ) where
        F: RichField + Extendable<D>,
        [(); PAD_LEN(MAX_LEN)]:,
    {
        let tt = cb._true();

        // Verify the offset of state MPT root hash is within range.
        let state_root_offset = cb.constant(F::from_canonical_usize(HEADER_RLP_STATE_ROOT_OFFSET));
        let within_range = less_than(cb, state_root_offset, wires.header_rlp.real_len, 10);
        cb.connect(within_range.target, tt.target);

        // Convert the hash bytes of state root to an u32 array, and verify it's
        // equal to the packed hash value.
        let is_equal = wires
            .state_root_bytes
            .convert_u8_to_u32(cb)
            .equals(cb, state_root_hash);
        cb.connect(is_equal.target, tt.target);

        // Verify the block header includes the state MPT root hash.
        let expected_state_root: OutputByteHash =
            wires.header_rlp.arr.extract_array(cb, state_root_offset);
        expected_state_root
            .convert_u8_to_u32(cb)
            .enforce_equal(cb, &state_root_hash);
    }
}
