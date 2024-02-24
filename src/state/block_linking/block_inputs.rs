//! This is the block-inputs gadget. It builds the circuit to prove that the
//! hash of state MPT root should be included in the block header.

use crate::{
    array::{Array, Vector, VectorWire},
    eth::RLPBlock,
    keccak::{OutputByteHash, OutputHash},
    utils::{convert_u8_slice_to_u32_fields, find_index_subvector, less_than},
};
use anyhow::Result;
use ethers::types::{Block, H256};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

/// The block input values
#[derive(Clone, Debug)]
pub struct BlockInputs {
    /// Block number
    number: u64,
    /// Block hash
    hash: H256,
    /// Block parent hash
    parent_hash: H256,
    /// The offset of state MPT root hash located in RLP encoded block header
    state_root_offset: usize,
    /// RLP encoded bytes of block header
    header_rlp: Vec<u8>,
}

impl BlockInputs {
    pub fn new(block: Block<H256>, state_root_hash: H256) -> Self {
        let header_rlp = rlp::encode(&RLPBlock(&block)).to_vec();

        // Find the state root hash from block header.
        let state_root_offset = find_index_subvector(&header_rlp, &state_root_hash.0)
            .expect("Failed to find the root hash of state MPT in the RLP encoded block header");

        Self {
            number: block.number.unwrap().as_u64(),
            hash: block.hash.unwrap(),
            parent_hash: block.parent_hash,
            state_root_offset,
            header_rlp,
        }
    }
}

/// The block input wires
pub struct BlockInputsWires<const MAX_LEN: usize> {
    /// Block number
    pub number: Target,
    /// Block hash
    pub hash: OutputHash,
    /// Block parent hash
    pub parent_hash: OutputHash,
    /// The offset of state MPT root hash located in RLP encoded block header
    pub state_root_offset: Target,
    /// RLP encoded bytes of block header
    pub header_rlp: VectorWire<Target, MAX_LEN>,
}

impl<const MAX_LEN: usize> BlockInputsWires<MAX_LEN> {
    pub fn new<F, const D: usize>(cb: &mut CircuitBuilder<F, D>) -> Self
    where
        F: RichField + Extendable<D>,
    {
        Self {
            number: cb.add_virtual_target(),
            hash: Array::new(cb),
            parent_hash: Array::new(cb),
            state_root_offset: cb.add_virtual_target(),
            header_rlp: VectorWire::new(cb),
        }
    }

    /// Assign the wires.
    pub fn assign<F>(&self, pw: &mut PartialWitness<F>, value: &BlockInputs) -> Result<()>
    where
        F: RichField,
    {
        // Assign the block number.
        pw.set_target(self.number, F::from_canonical_u64(value.number));

        // Assign the block hash and parent hash.
        [
            (&self.hash, value.hash),
            (&self.parent_hash, value.parent_hash),
        ]
        .iter()
        .for_each(|(target, value)| {
            target.assign(
                pw,
                &convert_u8_slice_to_u32_fields(&value.0).try_into().unwrap(),
            )
        });

        // Assign the offset of state MPT root hash located in RLP encoded block
        // header.
        pw.set_target(
            self.state_root_offset,
            F::from_canonical_usize(value.state_root_offset),
        );

        // Assign the RLP encoded block header.
        self.header_rlp
            .assign(pw, &Vector::from_vec(&value.header_rlp)?);

        Ok(())
    }

    /// Verify the block header includes the hash of state MPT root.
    /// We use a offset given as wire to indicate where the hash resides in the encoded block header.
    /// The circuit doesn't need to decode the RLP headers as we rely on the security of the hash function.
    pub fn verify_state_root_hash_inclusion<F, const D: usize>(
        &self,
        cb: &mut CircuitBuilder<F, D>,
        state_root_hash: &OutputHash,
    ) where
        F: RichField + Extendable<D>,
    {
        let tt = cb._true();

        // Verify the offset of state MPT root hash is within range.
        let within_range = less_than(cb, self.state_root_offset, self.header_rlp.real_len, 10);
        cb.connect(within_range.target, tt.target);

        // Verify the block header includes the state MPT root hash.
        let state_root_hash = OutputByteHash::from_u32_array(cb, state_root_hash);
        let is_included =
            self.header_rlp
                .arr
                .contains_array(cb, &state_root_hash, self.state_root_offset);
        cb.connect(is_included.target, tt.target);
    }
}
