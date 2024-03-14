//! Intermediate node circuit of Merkle tree

use core::array;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;

use crate::{
    keccak::{OutputHash, PACKED_HASH_LEN},
    state::BlockLinkingInputs,
};

/// The public inputs for the leaf circuit.
///
/// # Attributes
///
/// The inner attributes are, in order:
///
/// - C: Merkle root of this node represented by `H("LEAF" || node)`
/// - H: Blockchain header hash
/// - N: Block index
/// - PREV_H: Blockchain header hash of the parent block
///
/// The elements of `node` are, in order:
///
/// - A: Smart contract address
/// - C: Merkle root of the storage database
/// - S: Storage slot of the variable holding the length
/// - M: Storage slot of the mapping
#[derive(Clone, Debug)]
pub struct StateInputs<'a, T: Clone> {
    pub(crate) proof_inputs: &'a [T],
}

impl<'a> StateInputs<'a, Target> {
    /// Registers the public inputs into the circuit builder.
    pub fn register<F, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        root: &HashOutTarget,
        block_linking: &BlockLinkingInputs<'a, Target>,
    ) where
        F: RichField + Extendable<D>,
    {
        b.register_public_inputs(&root.elements);
        b.register_public_inputs(block_linking.block_hash());
        b.register_public_input(*block_linking.block_number());
        b.register_public_inputs(block_linking.prev_block_hash());
    }

    /// Registers the public inputs of the instance into the circuit builder.
    pub fn register_block_linking_data<F, const D: usize>(&self, b: &mut CircuitBuilder<F, D>)
    where
        F: RichField + Extendable<D>,
    {
        self.block_header().register_as_public_input(b);
        b.register_public_input(self.block_number().0);
        self.prev_block_header().register_as_public_input(b);
    }

    /// Returns the root hash.
    pub fn root(&self) -> HashOutTarget {
        let data = self.root_data();
        array::from_fn(|i| data[i]).into()
    }

    /// Returns the block header hash.
    pub fn block_header(&self) -> OutputHash {
        let data = self.block_header_data();
        array::from_fn(|i| U32Target(data[i])).into()
    }

    /// Returns the block number.
    pub fn block_number(&self) -> U32Target {
        U32Target(self.block_number_data())
    }

    /// Returns the previous block header hash.
    pub fn prev_block_header(&self) -> OutputHash {
        let data = self.prev_block_header_data();
        array::from_fn(|i| U32Target(data[i])).into()
    }
}

impl<'a, T: Copy> StateInputs<'a, T> {
    pub(crate) const C_LEN: usize = NUM_HASH_OUT_ELTS;
    pub(crate) const H_LEN: usize = PACKED_HASH_LEN;
    // Number can be encoded into a full target on 64 bits so no need to keep
    // an array of bytes/targets as we do when reading the block header from chain
    pub(crate) const N_LEN: usize = 1;
    pub(crate) const PREV_H_LEN: usize = PACKED_HASH_LEN;
    pub(crate) const TOTAL_LEN: usize = Self::C_LEN + Self::H_LEN + Self::N_LEN + Self::PREV_H_LEN;

    pub(crate) const C_IDX: usize = 0;
    pub(crate) const H_IDX: usize = Self::C_IDX + Self::C_LEN;
    pub(crate) const N_IDX: usize = Self::H_IDX + Self::H_LEN;
    pub(crate) const PREV_H_IDX: usize = Self::N_IDX + Self::N_LEN;

    /// Creates a representation of the public inputs from the provided slice.
    ///
    /// # Panics
    ///
    /// This function will panic if the length of the provided slice is smaller than
    /// [Self::TOTAL_LEN].
    pub fn from_slice(arr: &'a [T]) -> Self {
        assert!(
            Self::TOTAL_LEN <= arr.len(),
            "The public inputs slice length must be equal or greater than the expected length."
        );

        Self { proof_inputs: arr }
    }

    /// Returns the elements of the node root data.
    pub fn root_data(&self) -> &[T] {
        &self.proof_inputs[Self::C_IDX..Self::C_IDX + Self::C_LEN]
    }

    /// Returns the elements of the block header data.
    pub fn block_header_data(&self) -> &[T] {
        &self.proof_inputs[Self::H_IDX..Self::H_IDX + Self::H_LEN]
    }

    /// Returns the element representation of the storage slot of the variable holding the length.
    pub fn block_number_data(&self) -> T {
        self.proof_inputs[Self::N_IDX]
    }

    /// Returns the header hash of the previous block.
    pub fn prev_block_header_data(&self) -> &[T] {
        &self.proof_inputs[Self::PREV_H_IDX..Self::PREV_H_IDX + Self::PREV_H_LEN]
    }
}
