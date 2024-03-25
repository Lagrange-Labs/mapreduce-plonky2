use std::fmt::{self, Debug, Display};

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
use recursion_framework::circuit_builder::CircuitWithUniversalVerifier;
use serde::{Deserialize, Serialize};

use crate::{
    api::{ProofWithVK, C, D, F},
    types::{PackedAddressTarget, PackedValueTarget, CURVE_TARGET_LEN, PACKED_VALUE_LEN},
    utils::{convert_point_to_curve_target, convert_slice_to_curve_point},
};

use self::{full_node::FullNodeWires, partial_node::PartialNodeWires};

pub mod full_node;
pub mod partial_node;

pub enum CircuitInput {
    /// left and right children proof
    FullNode((ProofWithVK, ProofWithVK)),
    PartialNode(ProofWithVK),
}

impl CircuitInput {
    fn new_full_node(left_proof: Vec<u8>, right_proof: Vec<u8>) -> Self {
        Self::FullNode((
            ProofWithVK::deserialize(&left_proof).unwrap(),
            ProofWithVK::deserialize(&right_proof).unwrap(),
        ))
    }

    fn new_partial_node(child_proof: Vec<u8>) -> Self {
        Self::PartialNode(ProofWithVK::deserialize(&child_proof).unwrap())
    }
}

#[derive(Serialize, Deserialize)]
pub struct Parameters {
    //full_node_circuit: CircuitWithUniversalVerifier<F, C, D, 2, FullNodeWires>,
    //partial_node_circuit: CircuitWithUniversalVerifier<F, C, D, 1, PartialNodeWires>,
}

impl Parameters {
    pub fn build() -> Self {
        todo!()
    }

    pub fn generate_proof(&self, input: CircuitInput) -> Vec<u8> {
        todo!()
    }
}

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
        PackedAddressTarget::LEN,
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
#[derive(Clone)]
pub struct BlockPublicInputs<'input, T: Clone> {
    pub inputs: &'input [T],
}

impl<'a, T: Clone + Copy + Debug> Debug for BlockPublicInputs<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BlockNumber: {:?}\n", self.block_number_raw())?;
        write!(f, "Range: {:?}\n", self.range_raw())?;
        write!(f, "Root: {:?}\n", self.root_raw())?;
        write!(f, "SC Address: {:?}\n", self.smart_contract_address_raw())?;
        write!(f, "Owner Address: {:?}\n", self.user_address_raw())?;
        write!(f, "Mapping slot: {:?}\n", self.mapping_slot_raw())?;
        write!(
            f,
            "Storage slot length: {:?}\n",
            self.storage_slot_length_raw()
        )?;
        write!(f, "Digest: {:?}\n", self.digest_raw())
    }
}

impl<'a, T: Clone + Copy> From<&'a [T]> for BlockPublicInputs<'a, T> {
    fn from(inputs: &'a [T]) -> Self {
        assert_eq!(inputs.len(), Self::total_len());
        Self { inputs }
    }
}

impl<'a, T: Clone + Copy> BlockPublicInputs<'a, T> {
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

impl<'a> BlockPublicInputs<'a, Target> {
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

    pub(crate) fn smart_contract_address(&self) -> PackedAddressTarget {
        PackedAddressTarget::try_from(
            self.smart_contract_address_raw()
                .iter()
                .map(|&t| U32Target(t))
                .collect_vec(),
        )
        .unwrap()
    }

    pub(crate) fn user_address(&self) -> PackedValueTarget {
        PackedValueTarget::try_from(
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
        smc_address: &PackedAddressTarget,
        user_address: &PackedValueTarget,
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

#[cfg(test)]
use crate::types::PACKED_ADDRESS_LEN;

impl<'a> BlockPublicInputs<'a, GoldilocksField> {
    #[cfg(test)]
    pub fn from_parts(
        block_number: GoldilocksField,
        range: GoldilocksField,
        root: HashOut<GoldilocksField>,
        smart_contract_address: &[GoldilocksField; PACKED_ADDRESS_LEN],
        user_address: &[GoldilocksField; PACKED_VALUE_LEN],
        mapping_slot: GoldilocksField,
        storage_slot_length: GoldilocksField,
        digest: WeierstrassPoint,
    ) -> [GoldilocksField; Self::total_len()] {
        let mut inputs = vec![];
        inputs.push(block_number);
        inputs.push(range);
        inputs.extend_from_slice(&root.elements);
        inputs.extend_from_slice(smart_contract_address.as_slice());
        inputs.extend_from_slice(user_address.as_slice());
        inputs.push(mapping_slot);
        inputs.push(storage_slot_length);
        inputs.extend_from_slice(&digest.x.0);
        inputs.extend_from_slice(&digest.y.0);
        inputs.push(GoldilocksField::from_bool(digest.is_inf));
        inputs.try_into().unwrap()
    }
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
