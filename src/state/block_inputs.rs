//! This is the block-inputs gadget. It builds the circuit to prove that the
//! hash of state MPT should be included in block header.

use crate::{
    array::{Array, Vector, VectorWire},
    eth::RLPBlock,
    keccak::{OutputHash, PACKED_HASH_LEN},
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
use std::array;

/// The block input values
#[derive(Clone, Debug)]
pub struct BlockInputs {
    /// Block number
    number: u64,
    /// Block hash
    hash: H256,
    /// Block parent hash
    parent_hash: H256,
    /// The offset of MPT root hash located in RLP encoded bytes
    root_hash_offset: usize,
    /// RLP encoded bytes of block header
    rlp_bytes: Vec<u8>,
}

impl BlockInputs {
    pub fn new(block: Block<H256>, root_hash: &[u8]) -> Self {
        let rlp_bytes = rlp::encode(&RLPBlock(&block)).to_vec();
        let root_hash_offset = find_index_subvector(&rlp_bytes, root_hash).unwrap();

        Self {
            number: block.number.unwrap().as_u64(),
            hash: block.hash.unwrap(),
            parent_hash: block.parent_hash,
            root_hash_offset,
            rlp_bytes,
        }
    }
}

/// The block input wires
pub struct BlockInputsWires<const MAX_LEN: usize> {
    /// Block number
    pub number: Target,
    /// Block hash
    pub hash: Array<Target, PACKED_HASH_LEN>,
    /// Block parent hash
    pub parent_hash: Array<Target, PACKED_HASH_LEN>,
    /// The offset of MPT root hash located in RLP encoded bytes
    pub root_hash_offset: Target,
    /// RLP encoded bytes of block header
    pub rlp_bytes: VectorWire<MAX_LEN>,
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
            root_hash_offset: cb.add_virtual_target(),
            rlp_bytes: VectorWire::new(cb),
        }
    }

    /// Assign the wires.
    pub fn assign<F>(&self, pw: &mut PartialWitness<F>, value: &BlockInputs) -> Result<()>
    where
        F: RichField,
    {
        // Assign block number.
        pw.set_target(self.number, F::from_canonical_u64(value.number));

        // Assign block hash and parent hash.
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

        // Assign the MPT root offset.
        pw.set_target(
            self.root_hash_offset,
            F::from_canonical_usize(value.root_hash_offset),
        );

        // Assign the block RLP bytes.
        self.rlp_bytes
            .assign(pw, &Vector::from_vec(value.rlp_bytes.clone())?);

        Ok(())
    }

    /// Verify the block header includes the hash of MPT root.
    pub fn verify_root_hash_inclusion<F, const D: usize>(
        &self,
        cb: &mut CircuitBuilder<F, D>,
        root_hash: &OutputHash,
    ) where
        F: RichField + Extendable<D>,
    {
        // Verify the offset of MPT root hash is within range.
        let tt = cb._true();
        let within_range = less_than(cb, self.root_hash_offset, self.rlp_bytes.real_len, 10);
        cb.connect(tt.target, within_range.target);

        // Verify the block header includes the hash of MPT root.
        let root_hash = Array::<_, PACKED_HASH_LEN>::from(array::from_fn(|i| root_hash[i].0));
        let is_root_included =
            self.rlp_bytes
                .arr
                .contains_array(cb, &root_hash, self.root_hash_offset);
        cb.connect(is_root_included.target, tt.target);
    }
}
