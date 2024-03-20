use std::{array, marker, ops};

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::gadgets::curve::CurveTarget;

use crate::{
    types::{AddressTarget, PackedAddressTarget, CURVE_TARGET_LEN},
    utils::{convert_point_to_curve_target, convert_slice_to_curve_point},
};

#[cfg(test)]
mod tests;

/// Used to tag the provenance aspect of the PublicInputs
#[derive(Clone, Copy)]
pub(crate) struct Provenance;

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum CommonInput {
    BlockNumber,
    Range,
    Root,
    MinBlockNumber,
    MaxBlockNumber,
    SmartContractAddress,
    UserAddress,
    MappingSlot,
    LengthSlot,
}

impl CommonInput {
    const SIZES: [usize; 9] = [
        1,
        1,
        NUM_HASH_OUT_ELTS,
        1,
        1,
        PackedAddressTarget::LEN,
        PackedAddressTarget::LEN,
        1,
        1,
    ];

    fn total_len() -> usize {
        Self::SIZES.iter().sum()
    }

    const fn len(&self) -> usize {
        match self {
            Self::BlockNumber => Self::SIZES[0],
            Self::Range => Self::SIZES[1],
            Self::Root => Self::SIZES[2],
            Self::MinBlockNumber => Self::SIZES[3],
            Self::MaxBlockNumber => Self::SIZES[4],
            Self::SmartContractAddress => Self::SIZES[5],
            Self::UserAddress => Self::SIZES[6],
            Self::MappingSlot => Self::SIZES[7],
            Self::LengthSlot => Self::SIZES[8],
        }
    }

    const fn offset(&self) -> usize {
        match self {
            Self::BlockNumber => 0,
            Self::Range => Self::BlockNumber.offset() + Self::SIZES[*self as usize - 1],
            Self::Root => Self::Range.offset() + Self::SIZES[*self as usize - 1],
            Self::MinBlockNumber => Self::Root.offset() + Self::SIZES[*self as usize - 1],
            Self::MaxBlockNumber => Self::MinBlockNumber.offset() + Self::SIZES[*self as usize - 1],
            Self::SmartContractAddress => {
                Self::MaxBlockNumber.offset() + Self::SIZES[*self as usize - 1]
            }
            Self::UserAddress => {
                Self::SmartContractAddress.offset() + Self::SIZES[*self as usize - 1]
            }
            Self::MappingSlot => Self::UserAddress.offset() + Self::SIZES[*self as usize - 1],
            Self::LengthSlot => Self::MappingSlot.offset() + Self::SIZES[*self as usize - 1],
        }
    }

    const fn range(&self) -> ops::Range<usize> {
        let offset = self.offset();

        offset..offset + Self::SIZES[*self as usize]
    }
}

/// These public inputs are used by the aggregation & revelation proofs.
/// As they only differ by their last element, we place them at the submodule level.
/// On top of the habitual T, this type is parametrized by:
///   - Variant :: describes whether this is the Aggregation or Revelation phase PI
///   - L :: the LIMIT argument of the query
#[derive(Clone)]
pub struct PublicInputs<'input, T: Clone, Variant, const L: usize> {
    pub inputs: &'input [T],
    variant: marker::PhantomData<Variant>,
}
impl<'input, T: Clone, Variant, const L: usize> PublicInputs<'input, T, Variant, L> {
    pub const TOTAL_COMMON_LEN: usize = CommonInput::SIZES[0]
        + CommonInput::SIZES[1]
        + CommonInput::SIZES[2]
        + CommonInput::SIZES[3]
        + CommonInput::SIZES[4]
        + CommonInput::SIZES[5]
        + CommonInput::SIZES[6]
        + CommonInput::SIZES[7]
        + CommonInput::SIZES[8];

    /// Creates a representation of the public inputs from the provided slice.
    ///
    /// # Panics
    ///
    /// This function will panic if the length of the provided slice is smaller than
    /// [Self::TOTAL_COMMON_LEN].
    pub fn from_slice(arr: &'input [T]) -> Self {
        assert!(
            Self::TOTAL_COMMON_LEN <= arr.len(),
            "The public inputs slice length must be equal or greater than the expected length."
        );

        Self {
            inputs: arr,
            variant: marker::PhantomData,
        }
    }
}
impl<'a, T: Clone + Copy, Variant, const L: usize> PublicInputs<'a, T, Variant, L> {
    pub(crate) fn block_number_raw(&self) -> &T {
        &self.inputs[CommonInput::BlockNumber.offset()]
    }

    pub(crate) fn range_raw(&self) -> &T {
        &self.inputs[CommonInput::Range.offset()]
    }

    pub(crate) fn root_raw(&self) -> &[T] {
        &self.inputs[CommonInput::Root.range()]
    }

    pub(crate) fn min_block_number_raw(&self) -> &T {
        &self.inputs[CommonInput::MinBlockNumber.offset()]
    }

    pub(crate) fn max_block_number_raw(&self) -> &T {
        &self.inputs[CommonInput::MaxBlockNumber.offset()]
    }

    pub(crate) fn smart_contract_address_raw(&self) -> &[T] {
        &self.inputs[CommonInput::SmartContractAddress.range()]
    }

    pub(crate) fn user_address_raw(&self) -> &[T] {
        &self.inputs[CommonInput::UserAddress.range()]
    }

    pub(crate) fn mapping_slot_raw(&self) -> &T {
        &self.inputs[CommonInput::MappingSlot.offset()]
    }

    pub(crate) fn length_slot_raw(&self) -> &T {
        &self.inputs[CommonInput::LengthSlot.offset()]
    }
}
impl<'a, T: Clone + Copy, const L: usize> PublicInputs<'a, T, Provenance, L> {
    pub(crate) fn total_len() -> usize {
        CommonInput::total_len() + CURVE_TARGET_LEN
    }

    fn digest_raw(
        &self,
    ) -> (
        [T; crate::group_hashing::N],
        [T; crate::group_hashing::N],
        T,
    ) {
        convert_slice_to_curve_point(&self.inputs[Self::TOTAL_COMMON_LEN..Self::total_len()])
    }
}
impl<'a, Variant, const L: usize> PublicInputs<'a, Target, Variant, L> {
    pub(crate) fn block_number(&self) -> Target {
        *self.block_number_raw()
    }

    pub(crate) fn range(&self) -> Target {
        *self.range_raw()
    }

    pub(crate) fn root(&self) -> HashOutTarget {
        HashOutTarget {
            elements: self.root_raw().try_into().unwrap(),
        }
    }

    pub(crate) fn min_block_number(&self) -> Target {
        *self.min_block_number_raw()
    }

    pub(crate) fn max_block_number(&self) -> Target {
        *self.max_block_number_raw()
    }

    pub(crate) fn smart_contract_address(&self) -> PackedAddressTarget {
        PackedAddressTarget::from_array(array::from_fn(|i| {
            U32Target(self.smart_contract_address_raw()[i])
        }))
    }

    pub(crate) fn user_address(&self) -> PackedAddressTarget {
        PackedAddressTarget::from_array(array::from_fn(|i| U32Target(self.user_address_raw()[i])))
    }

    pub(crate) fn mapping_slot(&self) -> Target {
        *self.mapping_slot_raw()
    }

    pub(crate) fn length_slot(&self) -> Target {
        *self.length_slot_raw()
    }
}
impl<'a, const L: usize> PublicInputs<'a, Target, Provenance, L> {
    pub fn register<F, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        block_number: Target,
        range: Target,
        root: &HashOutTarget,
        min_block_number: Target,
        max_block_number: Target,
        smc_address: &PackedAddressTarget,
        user_address: &PackedAddressTarget,
        mapping_slot: Target,
        length_slot: Target,
        digest: &CurveTarget,
    ) where
        F: RichField + Extendable<D>,
    {
        b.register_public_input(block_number);
        b.register_public_input(range);
        b.register_public_inputs(&root.elements);
        b.register_public_input(min_block_number);
        b.register_public_input(max_block_number);
        smc_address.register_as_public_input(b);
        user_address.register_as_public_input(b);
        b.register_public_input(mapping_slot);
        b.register_public_input(length_slot);
        b.register_public_inputs(&digest.0 .0[0].0);
        b.register_public_inputs(&digest.0 .0[1].0);
        b.register_public_input(digest.0 .1.target);
    }
    pub(crate) fn digest(&self) -> CurveTarget {
        convert_point_to_curve_target(self.digest_raw())
    }
}
