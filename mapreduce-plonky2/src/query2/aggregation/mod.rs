use itertools::Itertools;
use plonky2::{
    field::{
        extension::{quintic::QuinticExtension, FieldExtension},
        goldilocks_field::GoldilocksField,
        types::Field,
    },
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::{
    curve::curve::WeierstrassPoint,
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget},
};

use crate::{
    types::{PackedAddressTarget as PackedSCAddressTarget, CURVE_TARGET_LEN, PACKED_VALUE_LEN},
    utils::{convert_point_to_curve_target, convert_slice_to_curve_point},
};

use super::PackedAddressTarget;

pub mod full_node;
pub mod partial_node;

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Inputs {
    /// B - block number of the latest block aggregated
    BlockNumber,
    /// R - aggregated range
    Range,
    /// C - Merkle hash of the subtree, or poseidon hash of the leaf
    Root,
    /// A - SMC address in compact packed u32
    SmartContractAddress,
    /// X - onwer's address - treated as generic 32byte value, packed in u32
    UserAddress,
    /// M - mapping slot
    MappingSlot,
    /// S - storage slot length
    StorageSlotLength,
    /// D - aggregated digest
    Digest,
}
const NUM_ELEMENTS: usize = 8;
impl Inputs {
    const SIZES: [usize; NUM_ELEMENTS] = [
        1,
        1,
        NUM_HASH_OUT_ELTS,
        PackedSCAddressTarget::LEN,
        PACKED_VALUE_LEN,
        1,
        1,
        CURVE_TARGET_LEN,
    ];

    const fn total_len() -> usize {
        Self::SIZES[0]
            + Self::SIZES[1]
            + Self::SIZES[2]
            + Self::SIZES[3]
            + Self::SIZES[4]
            + Self::SIZES[5]
            + Self::SIZES[6]
            + Self::SIZES[7]
    }

    pub const fn len(&self) -> usize {
        let me = *self as u8;
        Self::SIZES[me as usize]
    }

    fn range(&self) -> std::ops::Range<usize> {
        let mut offset = 0;
        let me = *self as u8;
        for i in 0..me {
            offset += Self::SIZES[i as usize];
        }

        offset..offset + Self::SIZES[me as usize]
    }
}

/// On top of the habitual T
#[derive(Clone, Debug)]
pub struct AggregationPublicInputs<'input, T: Clone> {
    pub inputs: &'input [T],
}

impl<'a, T: Clone + Copy> From<&'a [T]> for AggregationPublicInputs<'a, T> {
    fn from(inputs: &'a [T]) -> Self {
        assert_eq!(inputs.len(), Self::total_len());
        Self { inputs }
    }
}

impl<'a, T: Clone + Copy> AggregationPublicInputs<'a, T> {
    fn block_number_raw(&self) -> &[T] {
        &self.inputs[Inputs::BlockNumber.range()]
    }
    fn range_raw(&self) -> &[T] {
        &self.inputs[Inputs::Range.range()]
    }
    fn root_raw(&self) -> &[T] {
        &self.inputs[Inputs::Root.range()]
    }
    fn smart_contract_address_raw(&self) -> &[T] {
        &self.inputs[Inputs::SmartContractAddress.range()]
    }
    fn user_address_raw(&self) -> &[T] {
        &self.inputs[Inputs::UserAddress.range()]
    }
    fn mapping_slot_raw(&self) -> &[T] {
        &self.inputs[Inputs::MappingSlot.range()]
    }

    pub(crate) fn storage_slot_length_raw(&self) -> &[T] {
        &self.inputs[Inputs::StorageSlotLength.range()]
    }

    fn digest_raw(
        &self,
    ) -> (
        [T; crate::group_hashing::N],
        [T; crate::group_hashing::N],
        T,
    ) {
        convert_slice_to_curve_point(&self.inputs[Inputs::Digest.range()])
    }

    pub(crate) const fn total_len() -> usize {
        Inputs::total_len()
    }
}

impl<'a> AggregationPublicInputs<'a, Target> {
    pub(crate) fn block_number(&self) -> Target {
        self.block_number_raw()[0]
    }

    pub(crate) fn range(&self) -> Target {
        self.range_raw()[0]
    }

    pub(crate) fn root(&self) -> HashOutTarget {
        HashOutTarget {
            elements: self.root_raw().try_into().unwrap(),
        }
    }

    pub(crate) fn smart_contract_address(&self) -> PackedSCAddressTarget {
        PackedSCAddressTarget::try_from(
            self.smart_contract_address_raw()
                .iter()
                .map(|&t| U32Target(t))
                .collect_vec(),
        )
        .unwrap()
    }

    pub(crate) fn user_address(&self) -> PackedAddressTarget {
        PackedAddressTarget::try_from(
            self.user_address_raw()
                .iter()
                .map(|&t| U32Target(t))
                .collect_vec(),
        )
        .unwrap()
    }

    pub(crate) fn mapping_slot(&self) -> Target {
        self.mapping_slot_raw()[0]
    }

    pub(crate) fn digest(&self) -> CurveTarget {
        convert_point_to_curve_target(self.digest_raw())
    }

    pub(crate) fn mapping_slot_length(&self) -> Target {
        self.storage_slot_length_raw()[0]
    }

    pub fn register(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        block_number: Target,
        range: Target,
        root: &HashOutTarget,
        smc_address: &PackedSCAddressTarget,
        user_address: &PackedAddressTarget,
        mapping_slot: Target,
        mapping_slot_length: Target,
        digest: CurveTarget,
    ) {
        b.register_public_input(block_number);
        b.register_public_input(range);
        b.register_public_inputs(&root.elements);
        smc_address.register_as_public_input(b);
        user_address.register_as_public_input(b);
        b.register_public_input(mapping_slot);
        b.register_public_input(mapping_slot_length);
        b.register_curve_public_input(digest);
    }
}

impl<'a> AggregationPublicInputs<'a, GoldilocksField> {
    pub fn block_number(&self) -> GoldilocksField {
        self.block_number_raw()[0]
    }

    pub fn range(&self) -> GoldilocksField {
        self.range_raw()[0]
    }

    pub fn root(&self) -> HashOut<GoldilocksField> {
        HashOut::from_vec(self.root_raw().to_owned())
    }

    pub fn smart_contract_address(&self) -> &[GoldilocksField] {
        self.smart_contract_address_raw()
    }

    pub fn user_address(&self) -> &[GoldilocksField] {
        self.user_address_raw()
    }

    pub fn mapping_slot(&self) -> GoldilocksField {
        self.mapping_slot_raw()[0]
    }

    pub fn digest(&self) -> WeierstrassPoint {
        let (x, y, is_inf) = self.digest_raw();
        WeierstrassPoint {
            x: QuinticExtension::<GoldilocksField>::from_basefield_array(std::array::from_fn::<
                GoldilocksField,
                5,
                _,
            >(|i| x[i])),
            y: QuinticExtension::<GoldilocksField>::from_basefield_array(std::array::from_fn::<
                GoldilocksField,
                5,
                _,
            >(|i| y[i])),
            is_inf: is_inf.is_nonzero(),
        }
    }

    pub(crate) fn mapping_slot_length(&self) -> GoldilocksField {
        self.storage_slot_length_raw()[0]
    }
}
