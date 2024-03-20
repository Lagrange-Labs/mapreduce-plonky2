use std::ops;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::CurveTarget;

use crate::{
    types::{AddressTarget, CURVE_TARGET_LEN},
    utils::{convert_point_to_curve_target, convert_slice_to_curve_point},
};

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
        AddressTarget::LEN,
        AddressTarget::LEN,
        1,
        1,
    ];

    fn total_len() -> usize {
        Self::SIZES.iter().sum()
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
    variant: std::marker::PhantomData<Variant>,
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
    fn total_len() -> usize {
        CommonInput::total_len() + CURVE_TARGET_LEN
    }

    fn digest_raw(
        &self,
    ) -> (
        [T; crate::group_hashing::N],
        [T; crate::group_hashing::N],
        T,
    ) {
        convert_slice_to_curve_point(
            &self.inputs[CommonInput::total_len()..CommonInput::total_len() + 1],
        )
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

    pub(crate) fn smart_contract_address(&self) -> AddressTarget {
        AddressTarget::from_array(self.smart_contract_address_raw().try_into().unwrap())
    }

    pub(crate) fn user_address(&self) -> AddressTarget {
        AddressTarget::from_array(self.user_address_raw().try_into().unwrap())
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
        smc_address: &AddressTarget,
        user_address: &AddressTarget,
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
        b.register_public_inputs(&smc_address.arr);
        b.register_public_inputs(&user_address.arr);
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
