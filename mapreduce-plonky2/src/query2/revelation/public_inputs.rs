use std::array::from_fn as create_array;

use plonky2::{
    field::goldilocks_field::GoldilocksField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;

use crate::{keccak::OutputHash, types::PackedAddressTarget};

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum Inputs<const L: usize> {
    BlockNumber,
    Range,
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
    const SIZES: [usize; 10] = [
        // Block number
        1,
        // Range
        1,
        // Min block number
        1,
        // Max block number
        1,
        // Smart contract address
        PackedAddressTarget::LEN,
        // User address
        PackedAddressTarget::LEN,
        // Mapping Slot
        1,
        // Mapping slot length
        1,
        // L × NFT ID as u32
        L,
        // Block Header
        OutputHash::LEN,
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
            + Self::SIZES[8]
            + Self::SIZES[9]
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
        &self.inputs[Inputs::<L>::MappingSlotLength.range()]
    }
    fn nft_ids_raw(&self) -> &[T] {
        &self.inputs[Inputs::<L>::NftIds.range()]
    }
    fn block_header_raw(&self) -> &[T] {
        &self.inputs[Inputs::<L>::BlockHeader.range()]
    }
    pub const fn total_len() -> usize {
        Inputs::<L>::total_len()
    }
}

impl<'a, const L: usize> RevelationPublicInputs<'a, Target, L> {
    pub fn register(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        query_block_number: Target,
        query_range: Target,
        query_min_block: Target,
        query_max_block: Target,
        query_contract_address: &PackedAddressTarget,
        query_user_address: &PackedAddressTarget,
        query_mapping_slot: Target,
        mapping_slot_length: Target,
        query_nft_ids: &[U32Target; L],
        // the block hash of the latest block inserted at time of building the circuit
        // i.e. the one who corresponds to the block db proof being verified here.
        lpn_latest_block: OutputHash,
    ) {
        b.register_public_input(query_block_number);
        b.register_public_input(query_range);
        b.register_public_input(query_min_block);
        b.register_public_input(query_max_block);
        query_contract_address.register_as_public_input(b);
        query_user_address.register_as_public_input(b);
        b.register_public_input(query_mapping_slot);
        b.register_public_input(mapping_slot_length);
        for nft_id in query_nft_ids {
            b.register_public_input(nft_id.0);
        }
        b.register_public_inputs(&lpn_latest_block.to_targets().arr);
    }

    fn block_number(&self) -> Target {
        self.block_number_raw()[0]
    }

    pub(crate) fn range(&self) -> Target {
        self.range_raw()[0]
    }

    fn min_block_number(&self) -> Target {
        self.min_block_number_raw()[0]
    }

    fn max_block_number(&self) -> Target {
        self.max_block_number_raw()[0]
    }

    pub(crate) fn smart_contract_address(&self) -> PackedAddressTarget {
        let arr = self.smart_contract_address_raw();
        PackedAddressTarget {
            arr: create_array(|i| U32Target(arr[i])),
        }
    }

    pub(crate) fn user_address(&self) -> PackedAddressTarget {
        let arr = self.user_address_raw();
        PackedAddressTarget {
            arr: create_array(|i| U32Target(arr[i])),
        }
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

    pub(crate) fn range(&self) -> GoldilocksField {
        self.range_raw()[0]
    }

    pub(crate) fn min_block_number(&self) -> GoldilocksField {
        self.min_block_number_raw()[0]
    }

    pub(crate) fn max_block_number(&self) -> GoldilocksField {
        self.max_block_number_raw()[0]
    }

    pub(crate) fn smart_contract_address(&self) -> &[GoldilocksField] {
        self.smart_contract_address_raw()
    }

    pub(crate) fn user_address(&self) -> &[GoldilocksField] {
        self.user_address_raw()
    }

    pub(crate) fn mapping_slot(&self) -> GoldilocksField {
        self.mapping_slot_raw()[0]
    }

    pub(crate) fn mapping_slot_length(&self) -> GoldilocksField {
        self.mapping_slot_length_raw()[0]
    }

    pub(crate) fn nft_ids(&self) -> &[GoldilocksField] {
        self.nft_ids_raw()
    }

    pub(crate) fn block_header(&self) -> &[GoldilocksField] {
        self.block_header_raw()
    }
}
