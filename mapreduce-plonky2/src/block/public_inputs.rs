use crate::{keccak::OutputHash, keccak::PACKED_HASH_LEN};
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    hash::hash_types::{HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use std::array;

/// This is a wrapper around an array of targets set as public inputs of any
/// proof generated in this module. They all share the same structure.
/// - U0: Initial empty root
/// - Ui: New root
/// - Z1: First block number inserted
/// - Zi: New block number inserted
/// - H: Header hash of the new block inserted
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T: Clone> {
    pub(crate) proof_inputs: &'a [T],
}

impl<'a> PublicInputs<'a, Target> {
    pub fn register<F, const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
        init_root: &HashOutTarget,
        root: &HashOutTarget,
        first_block_number: U32Target,
        block_number: U32Target,
        block_header: &OutputHash,
    ) where
        F: RichField + Extendable<D>,
    {
        cb.register_public_inputs(&init_root.elements);
        cb.register_public_inputs(&root.elements);
        cb.register_public_input(first_block_number.0);
        cb.register_public_input(block_number.0);
        block_header.register_as_public_input(cb);
    }

    /// Return the init root hash.
    pub fn init_root(&self) -> HashOutTarget {
        let data = self.init_root_data();
        array::from_fn(|i| data[i]).into()
    }

    /// Return the new root hash.
    pub fn root(&self) -> HashOutTarget {
        let data = self.root_data();
        array::from_fn(|i| data[i]).into()
    }

    /// Return the first block number.
    pub fn first_block_number(&self) -> U32Target {
        U32Target(self.first_block_number_data())
    }

    /// Return the current block number.
    pub fn block_number(&self) -> U32Target {
        U32Target(self.block_number_data())
    }

    /// Return the block header hash extracted from the blockchain
    pub fn original_block_header(&self) -> OutputHash {
        let data = self.block_header_data();
        array::from_fn(|i| U32Target(data[i])).into()
    }
}

impl<'a, T: Copy + Default> PublicInputs<'a, T> {
    pub(crate) const U0_IDX: usize = 0;
    pub(crate) const UI_IDX: usize = Self::U0_IDX + NUM_HASH_OUT_ELTS;
    pub(crate) const Z1_IDX: usize = Self::UI_IDX + NUM_HASH_OUT_ELTS;
    pub(crate) const ZI_IDX: usize = Self::Z1_IDX + 1;
    pub(crate) const H_IDX: usize = Self::ZI_IDX + 1;
    pub(crate) const TOTAL_LEN: usize = Self::H_IDX + PACKED_HASH_LEN;

    pub fn from(arr: &'a [T]) -> Self {
        Self { proof_inputs: arr }
    }

    pub fn init_root_data(&self) -> &[T] {
        &self.proof_inputs[Self::U0_IDX..Self::UI_IDX]
    }

    pub fn root_data(&self) -> &[T] {
        &self.proof_inputs[Self::UI_IDX..Self::Z1_IDX]
    }

    pub fn first_block_number_data(&self) -> T {
        self.proof_inputs[Self::Z1_IDX]
    }

    pub fn block_number_data(&self) -> T {
        self.proof_inputs[Self::ZI_IDX]
    }

    pub fn block_header_data(&self) -> &[T] {
        &self.proof_inputs[Self::H_IDX..]
    }
}

impl PublicInputs<'_, GoldilocksField> {
    // Only used for testing.
    pub fn from_parts(
        init_root: &[GoldilocksField; NUM_HASH_OUT_ELTS],
        last_root: &[GoldilocksField; NUM_HASH_OUT_ELTS],
        init_block_number: GoldilocksField,
        last_block_number: GoldilocksField,
        last_block_hash: &[GoldilocksField; PACKED_HASH_LEN],
    ) -> [GoldilocksField; Self::TOTAL_LEN] {
        let mut arr = [GoldilocksField::default(); Self::TOTAL_LEN];
        arr[Self::U0_IDX..Self::UI_IDX].copy_from_slice(init_root);
        arr[Self::UI_IDX..Self::Z1_IDX].copy_from_slice(last_root);
        arr[Self::Z1_IDX] = init_block_number;
        arr[Self::ZI_IDX] = last_block_number;
        arr[Self::H_IDX..].copy_from_slice(last_block_hash);
        arr
    }
}
