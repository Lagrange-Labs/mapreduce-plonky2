//! Intermediate node circuit of Merkle tree

use crate::{keccak::OutputHash, keccak::PACKED_HASH_LEN};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use std::array;

/// This is a wrapper around an array of targets set as public inputs of any
/// proof generated in this module. They all share the same structure.
/// - C: Merkle root of this node
/// - H: Blockchain header hash
/// - N: Block number
/// - PREV_H: Blockchain header hash of the parent block
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T: Clone> {
    pub(crate) proof_inputs: &'a [T],
}

impl<'a> PublicInputs<'a, Target> {
    pub fn register<F, const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
        root: &HashOutTarget,
        block_header: &OutputHash,
        block_number: U32Target,
        prev_block_header: &OutputHash,
    ) where
        F: RichField + Extendable<D>,
    {
        cb.register_public_inputs(&root.elements);
        block_header.register_as_input(cb);
        cb.register_public_input(block_number.0);
        prev_block_header.register_as_input(cb);
    }

    /// Return the root hash.
    pub fn root(&self) -> HashOutTarget {
        let data = self.root_data();
        array::from_fn(|i| data[i]).into()
    }

    /// Return the block header hash.
    pub fn block_header(&self) -> OutputHash {
        let data = self.block_header_data();
        array::from_fn(|i| U32Target(data[i])).into()
    }

    /// Return the block number.
    pub fn block_number(&self) -> U32Target {
        U32Target(self.block_number_data())
    }

    /// Return the previous block header hash.
    pub fn prev_block_header(&self) -> OutputHash {
        let data = self.prev_block_header_data();
        array::from_fn(|i| U32Target(data[i])).into()
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    pub(crate) const C_IDX: usize = 0;
    pub(crate) const H_IDX: usize = Self::C_IDX + NUM_HASH_OUT_ELTS;
    pub(crate) const N_IDX: usize = Self::H_IDX + PACKED_HASH_LEN;
    pub(crate) const PREV_H_IDX: usize = Self::N_IDX + 1;
    pub(crate) const TOTAL_LEN: usize = Self::PREV_H_IDX + PACKED_HASH_LEN;

    pub fn from(arr: &'a [T]) -> Self {
        Self { proof_inputs: arr }
    }

    pub fn root_data(&self) -> &[T] {
        &self.proof_inputs[Self::C_IDX..Self::H_IDX]
    }

    pub fn block_header_data(&self) -> &[T] {
        &self.proof_inputs[Self::H_IDX..Self::N_IDX]
    }

    pub fn block_number_data(&self) -> T {
        self.proof_inputs[Self::N_IDX]
    }

    pub fn prev_block_header_data(&self) -> &[T] {
        &self.proof_inputs[Self::PREV_H_IDX..]
    }
}

// TODO: add intermediate node circuit
