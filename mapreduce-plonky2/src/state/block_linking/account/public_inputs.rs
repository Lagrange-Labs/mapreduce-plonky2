use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::hash_types::{HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget};
use std::array::from_fn as create_array;

use crate::{
    array::Array,
    keccak::{OutputHash, PACKED_HASH_LEN},
    mpt_sequential::MPTKeyWire,
    rlp::MAX_KEY_NIBBLE_LEN,
    types::{PackedAddressTarget, CURVE_TARGET_LEN, PACKED_ADDRESS_LEN},
    utils::{convert_point_to_curve_target, convert_slice_to_curve_point},
};

// This is a wrapper around an array of targets set as public inputs
// of any proof generated in this module. They all share the same
// structure.
// `K` Full key for a leaf inside this subtree
// `T` Index of the part “processed” on the full key
// `A` Smart contract address
// `S` storage slot of the mapping
// `n` slot of the variable holding the length
// `C` MPT root (of the current node)
// `D` Accumulator digest of the values
// `R` Merkle-root of LPN storage DB
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T: Clone> {
    pub(crate) proof_inputs: &'a [T],
}

impl<'a> PublicInputs<'a, Target> {
    pub fn register(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        key: &MPTKeyWire,
        addr: &PackedAddressTarget,
        mapping_slot: Target,
        length_slot: Target,
        c: &OutputHash,
        d: &CurveTarget,
        lpn_root: &HashOutTarget,
    ) {
        key.register_as_input(b);
        addr.register_as_public_input(b);
        b.register_public_input(mapping_slot);
        b.register_public_input(length_slot);
        c.register_as_public_input(b);
        b.register_curve_public_input(*d);
        b.register_public_inputs(&lpn_root.elements)
    }
    /// Returns the MPT key defined over the public inputs
    pub fn mpt_key(&self) -> MPTKeyWire {
        let (key, ptr) = self.mpt_key_info();
        MPTKeyWire {
            key: Array {
                arr: create_array(|i| key[i]),
            },
            pointer: ptr,
        }
    }
    /// Returns the contract address defined over the public inputs.
    pub fn contract_address(&self) -> PackedAddressTarget {
        let addr = self.contract_address_info();
        PackedAddressTarget::from_array(create_array(|i| U32Target(addr[i])))
    }

    pub fn mapping_slot(&self) -> Target {
        *self.mapping_slot_info()
    }

    pub fn length_slot(&self) -> Target {
        *self.length_slot_info()
    }

    /// Returns the accumulator digest defined over the public inputs
    pub fn digest(&self) -> CurveTarget {
        convert_point_to_curve_target(self.digest_info())
    }

    /// Returns the merkle hash C of the subtree this proof has processed.
    pub fn root_hash(&self) -> OutputHash {
        let hash = self.root_hash_info();
        Array::<U32Target, PACKED_HASH_LEN>::from_array(create_array(|i| U32Target(hash[i])))
    }
    /// Returns the root of the LPN storage DB
    pub fn lpn_root(&self) -> HashOutTarget {
        let root = self.lpn_root_info();
        HashOutTarget::from(std::array::from_fn(|i| root[i]))
    }
}

impl<'a> PublicInputs<'a, GoldilocksField> {
    // Returns in packed representation
    pub fn root_hash(&self) -> Vec<u32> {
        let hash = self.root_hash_info();
        hash.iter().map(|t| t.0 as u32).collect()
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    pub(crate) const KEY_IDX: usize = 0; // 64 nibbles
    pub(crate) const T_IDX: usize = Self::KEY_IDX + MAX_KEY_NIBBLE_LEN; // 1 index
    pub(crate) const A_IDX: usize = Self::T_IDX + 1; // packed address
    pub(crate) const S_IDX: usize = Self::A_IDX + PACKED_ADDRESS_LEN; // 1 element
    pub(crate) const N_IDX: usize = Self::S_IDX + 1; // 1 element
    pub(crate) const C_IDX: usize = Self::N_IDX + 1; // packed hash = 8 U32-F elements
    pub(crate) const D_IDX: usize = Self::C_IDX + PACKED_HASH_LEN; // curve target elements
    pub(crate) const R_IDX: usize = Self::D_IDX + CURVE_TARGET_LEN; // HashOutTarget
    pub(crate) const TOTAL_LEN: usize = Self::R_IDX + NUM_HASH_OUT_ELTS;
    pub fn from(arr: &'a [T]) -> Self {
        Self { proof_inputs: arr }
    }

    pub(crate) fn mpt_key_info(&self) -> (&[T], T) {
        let key_range = Self::KEY_IDX..Self::KEY_IDX + MAX_KEY_NIBBLE_LEN;
        let key = &self.proof_inputs[key_range];
        let ptr_range = Self::T_IDX..Self::T_IDX + 1;
        let ptr = self.proof_inputs[ptr_range][0];
        (key, ptr)
    }

    pub(crate) fn contract_address_info(&self) -> &[T] {
        let addr_range = Self::A_IDX..Self::A_IDX + PACKED_ADDRESS_LEN;
        &self.proof_inputs[addr_range]
    }

    // small utility function to transform a list of target to a curvetarget.
    pub(crate) fn digest_info(&self) -> ([T; 5], [T; 5], T) {
        convert_slice_to_curve_point(&self.proof_inputs[Self::D_IDX..])
    }

    pub(crate) fn mapping_slot_info(&self) -> &T {
        &self.proof_inputs[Self::S_IDX]
    }

    pub(crate) fn length_slot_info(&self) -> &T {
        &self.proof_inputs[Self::N_IDX]
    }

    pub(crate) fn root_hash_info(&self) -> &[T] {
        // poseidon merkle root hash is 4 F elements
        let hash_range = Self::C_IDX..Self::C_IDX + PACKED_HASH_LEN;
        &self.proof_inputs[hash_range]
    }

    pub(crate) fn lpn_root_info(&self) -> &[T] {
        let root_range = Self::R_IDX..Self::R_IDX + NUM_HASH_OUT_ELTS;
        &self.proof_inputs[root_range]
    }
}
