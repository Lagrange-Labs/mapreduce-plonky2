use itertools::Itertools;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;

use crate::{
    keccak::OutputHash,
    query2::AddressTarget,
    types::{PackedAddressTarget as PackedSCAddressTarget, CURVE_TARGET_LEN},
};

use super::PackedAddressTarget;

pub mod circuit;

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum Inputs<const L: usize> {
    BlockNumber,
    Range,
    Root,
    MinBlockNumber,
    MaxBlockNumber,
    SmartContractAddress,
    UserAddress,
    MappingSlot,
    MappingSlotLength,
    NftIds,
    BlockHeader,
}
impl<const L: usize> Inputs<L> {
    const SIZES: [usize; 11] = [
        // Block number
        1,
        // Range
        1,
        // Root
        NUM_HASH_OUT_ELTS,
        // Min block number
        1,
        // Max block number
        1,
        // SMC Address
        PackedSCAddressTarget::LEN,
        // Owner's address
        PackedAddressTarget::LEN,
        // Mapping Slot
        1,
        // Mapping slot length
        1,
        // L × NFT ID
        L * 8,
        // Block Header
        OutputHash::LEN,
    ];

    fn total_len() -> usize {
        Self::SIZES.iter().sum()
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

#[derive(Clone)]
pub struct RevelationPublicInputs<'input, T: Clone, const L: usize> {
    pub inputs: &'input [T],
}

impl<'a, T: Clone + Copy, const L: usize> From<&'a [T]> for RevelationPublicInputs<'a, T, L> {
    fn from(inputs: &'a [T]) -> Self {
        assert_eq!(inputs.len(), Self::total_len());
        Self { inputs }
    }
}

impl<'a, T: Clone + Copy, const L: usize> RevelationPublicInputs<'a, T, L> {
    fn block_number_raw(&self) -> &[T] {
        &self.inputs[Inputs::<L>::BlockNumber.range()]
    }
    fn range_raw(&self) -> &[T] {
        &self.inputs[Inputs::<L>::Range.range()]
    }
    fn root_raw(&self) -> &[T] {
        &self.inputs[Inputs::<L>::Root.range()]
    }
    fn min_block_number_raw(&self) -> &[T] {
        &self.inputs[Inputs::<L>::MinBlockNumber.range()]
    }
    fn max_block_number_raw(&self) -> &[T] {
        &self.inputs[Inputs::<L>::MaxBlockNumber.range()]
    }
    fn smart_contract_address_raw(&self) -> &[T] {
        &self.inputs[Inputs::<L>::SmartContractAddress.range()]
    }
    fn user_address_raw(&self) -> &[T] {
        &self.inputs[Inputs::<L>::UserAddress.range()]
    }
    fn mapping_slot_raw(&self) -> &[T] {
        &self.inputs[Inputs::<L>::MappingSlot.range()]
    }
    fn mapping_slot_length_raw(&self) -> &[T] {
        &self.inputs[Inputs::<L>::MappingSlot.range()]
    }
    fn nft_ids_raw(&self) -> &[T] {
        &self.inputs[Inputs::<L>::NftIds.range()]
    }
    fn block_header_raw(&self) -> &[T] {
        &self.inputs[Inputs::<L>::BlockHeader.range()]
    }
    fn total_len() -> usize {
        Inputs::<L>::total_len()
    }
}

impl<'a, const L: usize> RevelationPublicInputs<'a, Target, L> {
    pub fn register(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        block_number: Target,
        range: Target,
        root: &HashOutTarget,
        min_block_number: Target,
        max_block_number: Target,
        smc_address: &PackedSCAddressTarget,
        user_address: &PackedAddressTarget,
        mapping_slot: Target,
        mapping_slot_length: Target,
        nft_ids: &[[Target; 8]],
        block_header: OutputHash,
    ) {
        b.register_public_input(block_number);
        b.register_public_input(range);
        b.register_public_inputs(&root.elements);
        b.register_public_input(min_block_number);
        b.register_public_input(max_block_number);
        smc_address.register_as_public_input(b);
        user_address.register_as_public_input(b);
        b.register_public_input(mapping_slot);
        b.register_public_input(mapping_slot_length);
        for nft_id in nft_ids {
            b.register_public_inputs(nft_id);
        }
        b.register_public_inputs(&block_header.to_targets().arr);
    }

    fn block_number(&self) -> Target {
        self.block_number_raw()[0]
    }

    fn range(&self) -> Target {
        self.range_raw()[0]
    }

    fn root(&self) -> HashOutTarget {
        HashOutTarget {
            elements: self.root_raw().try_into().unwrap(),
        }
    }

    fn min_block_number(&self) -> Target {
        self.min_block_number_raw()[0]
    }

    fn max_block_number(&self) -> Target {
        self.max_block_number_raw()[0]
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

    fn mapping_slot(&self) -> Target {
        self.mapping_slot_raw()[0]
    }

    fn mapping_slot_length(&self) -> Target {
        self.mapping_slot_length_raw()[0]
    }

    fn nft_ids(&self) -> &[Target] {
        self.nft_ids_raw()
    }

    fn block_header(&self) -> OutputHash {
        OutputHash::from_array(
            self.block_header_raw()
                .iter()
                .map(|x| U32Target(*x))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }
}

impl<'a, const L: usize> RevelationPublicInputs<'a, GoldilocksField, L> {
    fn block_number(&self) -> GoldilocksField {
        self.block_number_raw()[0]
    }

    fn range(&self) -> GoldilocksField {
        self.range_raw()[0]
    }

    fn root(&self) -> HashOut<GoldilocksField> {
        HashOut::from_vec(self.root_raw().to_owned())
    }

    fn min_block_number(&self) -> GoldilocksField {
        self.min_block_number_raw()[0]
    }

    fn max_block_number(&self) -> GoldilocksField {
        self.max_block_number_raw()[0]
    }

    fn smart_contract_address(&self) -> &[GoldilocksField] {
        self.smart_contract_address_raw()
    }

    fn user_address(&self) -> &[GoldilocksField] {
        self.user_address_raw()
    }

    fn mapping_slot(&self) -> GoldilocksField {
        self.mapping_slot_raw()[0]
    }

    fn mapping_slot_length(&self) -> GoldilocksField {
        self.mapping_slot_length_raw()[0]
    }

    fn nft_ids(&self) -> &[GoldilocksField] {
        self.nft_ids_raw()
    }

    fn block_header(&self) -> &[GoldilocksField] {
        self.block_header_raw()
    }
}
