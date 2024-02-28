//! This circuit is used to verify the length value extracted from storage trie.

use crate::{
    keccak::{OutputHash, PACKED_HASH_LEN},
    utils::{PackedAddressTarget, PACKED_ADDRESS_LEN},
};
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use std::array;

/// This is a wrapper around an array of targets set as public inputs of any
/// proof generated in this module. They all share the same structure.
/// `C` MPT root hash
/// `A` Contract address
/// `S` storage slot of the variable holding the length
/// `V` Integer value stored at key `S` (can be given by prover)
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T: Clone> {
    pub(crate) proof_inputs: &'a [T],
}

impl<'a> PublicInputs<'a, Target> {
    pub fn register<F, const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
        mpt_root_hash: &OutputHash,
        contract_address: PackedAddressTarget,
        storage_slot: Target,
        length_value: Target,
    ) where
        F: RichField + Extendable<D>,
    {
        mpt_root_hash.register_as_input(cb);
        contract_address.register_as_input(cb);
        cb.register_public_input(storage_slot);
        cb.register_public_input(length_value);
    }

    pub fn root_hash(&self) -> OutputHash {
        let data = self.root_hash_data();
        OutputHash::from_array(array::from_fn(|i| U32Target(data[i])))
    }

    pub fn contract_address(&self) -> PackedAddressTarget {
        let data = self.contract_address_data();
        PackedAddressTarget::from_array(array::from_fn(|i| U32Target(data[i])))
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    pub(crate) const C_IDX: usize = 0;
    pub(crate) const A_IDX: usize = Self::C_IDX + PACKED_HASH_LEN;
    pub(crate) const S_IDX: usize = Self::A_IDX + PACKED_ADDRESS_LEN;
    pub(crate) const V_IDX: usize = Self::S_IDX + 1;
    pub(crate) const TOTAL_LEN: usize = Self::V_IDX + 1;

    pub fn from(arr: &'a [T]) -> Self {
        Self { proof_inputs: arr }
    }

    pub fn root_hash_data(&self) -> &[T] {
        &self.proof_inputs[Self::C_IDX..Self::A_IDX]
    }

    pub fn contract_address_data(&self) -> &[T] {
        &self.proof_inputs[Self::A_IDX..Self::S_IDX]
    }

    pub fn storage_slot(&self) -> T {
        self.proof_inputs[Self::S_IDX]
    }

    pub fn length_value(&self) -> T {
        self.proof_inputs[Self::V_IDX]
    }
}
