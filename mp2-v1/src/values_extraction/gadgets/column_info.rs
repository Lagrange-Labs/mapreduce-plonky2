//! Column information for values extraction

use itertools::{zip_eq, Itertools};
use mp2_common::{
    eth::{left_pad, left_pad32},
    group_hashing::{map_to_curve_point, CircuitBuilderGroupHashing},
    poseidon::H,
    types::{CBuilder, MAPPING_LEAF_VALUE_LEN},
    utils::{Endianness, Packer},
    CHasher, F,
};
use plonky2::{
    field::types::{Field, Sample},
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{target::Target, witness::WitnessWrite},
    plonk::config::Hasher,
};
use plonky2_ecgfp5::{curve::curve::Point, gadgets::curve::CurveTarget};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::{array, iter::once};

/// Trait defining common functionality between [`InputColumnInfo`] and [`ExtractedColumnInfo`]
pub trait ColumnInfo {
    /// Getter for the column identifier as a field element
    fn identifier_field(&self) -> F;

    /// Getter for the identifier as a [`u64`]
    fn identifier(&self) -> u64;
}

/// Column info
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct InputColumnInfo {
    /// This is the information used to identify the data relative to the contract,
    /// for storage extraction its the slot, for receipts its the event signature for example
    pub extraction_identifier: [F; 8],
    /// Column identifier
    pub identifier: F,
    /// Prefix used in computing mpt metadata
    pub metadata_prefix: [u8; 32],
    /// The length (in bits) of the field to extract in the EVM word
    pub length: F,
}

impl InputColumnInfo {
    /// Construct a new instance of [`ColumnInfo`]
    pub fn new(
        extraction_identifier: &[u8],
        identifier: u64,
        metadata_prefix: &[u8],
        length: usize,
    ) -> Self {
        let mut extraction_vec = extraction_identifier.pack(Endianness::Little);
        extraction_vec.resize(8, 0u32);
        extraction_vec.reverse();
        let extraction_identifier = extraction_vec
            .into_iter()
            .map(F::from_canonical_u32)
            .collect::<Vec<F>>()
            .try_into()
            .expect("This should never fail");
        let identifier = F::from_canonical_u64(identifier);
        let length = F::from_canonical_usize(length);

        Self {
            extraction_identifier,
            identifier,
            metadata_prefix: left_pad::<32>(metadata_prefix),
            length,
        }
    }

    /// Compute the MPT metadata.
    pub fn mpt_metadata(&self) -> HashOut<F> {
        // key_column_md = H( "\0KEY" || slot)
        let inputs = [
            self.metadata_prefix().as_slice(),
            self.extraction_id().as_slice(),
        ]
        .concat();
        H::hash_no_pad(&inputs)
    }

    /// Compute the column information digest.
    pub fn digest(&self) -> Point {
        let metadata = self.mpt_metadata();

        // digest = D(mpt_metadata || info.identifier)
        let inputs = [metadata.elements.as_slice(), &[self.identifier()]].concat();

        map_to_curve_point(&inputs)
    }

    pub fn extraction_id(&self) -> [F; 8] {
        self.extraction_identifier
    }

    pub fn identifier(&self) -> F {
        self.identifier
    }

    pub fn metadata_prefix(&self) -> Vec<F> {
        self.metadata_prefix
            .as_slice()
            .pack(Endianness::Big)
            .into_iter()
            .map(F::from_canonical_u32)
            .collect()
    }

    pub fn length(&self) -> F {
        self.length
    }

    pub fn value_digest(&self, value: &[u8]) -> Point {
        let bytes = left_pad32(value);

        let inputs = once(self.identifier())
            .chain(
                bytes
                    .pack(Endianness::Big)
                    .into_iter()
                    .map(F::from_canonical_u32),
            )
            .collect_vec();
        map_to_curve_point(&inputs)
    }
}

/// Column info
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize, Copy)]
pub struct ExtractedColumnInfo {
    /// This is the information used to identify the data relative to the contract,
    /// for storage extraction its the slot, for receipts its the event signature for example
    pub extraction_identifier: [F; 8],
    /// Column identifier
    pub identifier: F,
    /// The offset in bytes where to extract this column from some predetermined start point,
    /// for storage this would be the byte offset from the start of the given EVM word, for Receipts
    /// this would be either the offset from the start of the receipt or from the start of the
    /// relevant log       
    pub byte_offset: F,
    /// The length (in bits) of the field to extract in the EVM word
    pub length: F,
    /// For storage this is the EVM word, for receipts this is either 1 or 0 and indicates whether to
    /// use the relevant log offset or not.
    pub location_offset: F,
}

impl PartialOrd for ExtractedColumnInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExtractedColumnInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.location_offset
            .0
            .cmp(&other.location_offset.0)
            .then(self.byte_offset.0.cmp(&other.byte_offset.0))
    }
}

impl ExtractedColumnInfo {
    /// Construct a new instance of [`ColumnInfo`]
    pub fn new(
        extraction_identifier: &[u8],
        identifier: u64,
        byte_offset: usize,
        length: usize,
        location_offset: u32,
    ) -> Self {
        let mut extraction_vec = extraction_identifier.pack(Endianness::Little);
        extraction_vec.resize(8, 0u32);
        extraction_vec.reverse();
        let extraction_identifier = extraction_vec
            .into_iter()
            .map(F::from_canonical_u32)
            .collect::<Vec<F>>()
            .try_into()
            .expect("This should never fail");
        let identifier = F::from_canonical_u64(identifier);
        let [byte_offset, length] = [byte_offset, length].map(F::from_canonical_usize);
        let location_offset = F::from_canonical_u32(location_offset);

        Self {
            extraction_identifier,
            identifier,
            byte_offset,
            length,
            location_offset,
        }
    }

    /// Create a sample column info. It could be used in integration tests.
    pub fn sample_storage(extraction_identifier: &[F; 8], location_offset: F) -> Self {
        let rng = &mut thread_rng();

        let length: usize = rng.gen_range(1..=MAPPING_LEAF_VALUE_LEN);
        let max_byte_offset = MAPPING_LEAF_VALUE_LEN - length;
        let byte_offset = F::from_canonical_usize(rng.gen_range(0..=max_byte_offset));
        let length = F::from_canonical_usize(length);
        let identifier = F::rand();

        Self {
            extraction_identifier: *extraction_identifier,
            identifier,
            byte_offset,
            length,
            location_offset,
        }
    }

    /// Sample a ne [`ExtractedColumnInfo`] at random, if `flag` is `true` then it will be for storage extraction,
    /// if false it will be for receipt extraction.
    pub fn sample(flag: bool, extraction_identifier: &[F; 8], location_offset: F) -> Self {
        if flag {
            ExtractedColumnInfo::sample_storage(extraction_identifier, location_offset)
        } else {
            unimplemented!()
        }
    }

    /// Compute the MPT metadata.
    pub fn mpt_metadata(&self) -> HashOut<F> {
        // metadata = H(info.extraction_id || info.location_offset || info.byte_offset || info.length)
        let inputs = [
            self.extraction_id().as_slice(),
            &[self.location_offset(), self.byte_offset(), self.length()],
        ]
        .concat();

        H::hash_no_pad(&inputs)
    }

    /// Compute the column information digest.
    pub fn digest(&self) -> Point {
        let metadata = self.mpt_metadata();

        // digest = D(mpt_metadata || info.identifier)
        let inputs = [metadata.elements.as_slice(), &[self.identifier()]].concat();

        map_to_curve_point(&inputs)
    }

    pub fn extraction_id(&self) -> [F; 8] {
        self.extraction_identifier
    }

    pub fn identifier(&self) -> F {
        self.identifier
    }

    pub fn byte_offset(&self) -> F {
        self.byte_offset
    }

    pub fn length(&self) -> F {
        self.length
    }

    pub fn location_offset(&self) -> F {
        self.location_offset
    }

    pub fn extract_value(&self, value: &[u8]) -> [u8; 32] {
        left_pad32(
            &value[self.byte_offset().0 as usize
                ..self.byte_offset().0 as usize + self.length.0 as usize],
        )
    }

    pub fn value_digest(&self, value: &[u8]) -> Point {
        if self.identifier().0 == 0 {
            Point::NEUTRAL
        } else {
            let bytes = left_pad32(
                &value[self.byte_offset().0 as usize
                    ..self.byte_offset().0 as usize + self.length.0 as usize],
            );

            let inputs = once(self.identifier())
                .chain(
                    bytes
                        .pack(Endianness::Big)
                        .into_iter()
                        .map(F::from_canonical_u32),
                )
                .collect_vec();
            map_to_curve_point(&inputs)
        }
    }

    pub fn receipt_value_digest(&self, value: &[u8], offset: usize) -> Point {
        if self.identifier().0 == 0 {
            Point::NEUTRAL
        } else {
            let start = offset + self.byte_offset().0 as usize;
            let bytes = left_pad32(&value[start..start + self.length.0 as usize]);

            let inputs = once(self.identifier())
                .chain(
                    bytes
                        .pack(Endianness::Big)
                        .into_iter()
                        .map(F::from_canonical_u32),
                )
                .collect_vec();
            map_to_curve_point(&inputs)
        }
    }
}

impl ColumnInfo for InputColumnInfo {
    fn identifier_field(&self) -> F {
        self.identifier
    }

    fn identifier(&self) -> u64 {
        self.identifier.0
    }
}

impl ColumnInfo for ExtractedColumnInfo {
    fn identifier_field(&self) -> F {
        self.identifier
    }

    fn identifier(&self) -> u64 {
        self.identifier.0
    }
}
/// Column info
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize, Copy)]
pub struct ExtractedColumnInfoTarget {
    /// This is the information used to identify the data relative to the contract,
    /// for storage extraction its the slot, for receipts its the event signature for example
    pub(crate) extraction_identifier: [Target; 8],
    /// Column identifier
    pub(crate) identifier: Target,
    /// The offset in bytes where to extract this column from some predetermined start point,
    /// for storage this would be the byte offset from the start of the given EVM word, for Receipts
    /// this would be either the offset from the start of the receipt or from the start of the
    /// relevant log       
    pub(crate) byte_offset: Target,
    /// The length (in bits) of the field to extract in the EVM word
    pub(crate) length: Target,
    /// For storage this is the EVM word, for receipts this is either 1 or 0 and indicates whether to
    /// use the relevant log offset or not.
    pub(crate) location_offset: Target,
}

impl ExtractedColumnInfoTarget {
    /// Compute the MPT metadata.
    pub fn mpt_metadata(&self, b: &mut CBuilder) -> HashOutTarget {
        // metadata = H(info.extraction_id || info.location_offset || info.byte_offset || info.length)
        let inputs = [
            self.extraction_id().as_slice(),
            &[self.location_offset(), self.byte_offset(), self.length()],
        ]
        .concat();

        b.hash_n_to_hash_no_pad::<CHasher>(inputs)
    }

    /// Compute the column information digest.
    pub fn digest(&self, b: &mut CBuilder) -> CurveTarget {
        let metadata = self.mpt_metadata(b);

        // digest = D(mpt_metadata || info.identifier)
        let inputs = [metadata.elements.as_slice(), &[self.identifier()]].concat();

        b.map_to_curve_point(&inputs)
    }

    pub fn extraction_id(&self) -> [Target; 8] {
        self.extraction_identifier
    }

    pub fn identifier(&self) -> Target {
        self.identifier
    }

    pub fn byte_offset(&self) -> Target {
        self.byte_offset
    }

    pub fn length(&self) -> Target {
        self.length
    }

    pub fn location_offset(&self) -> Target {
        self.location_offset
    }
}

/// Column info
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct InputColumnInfoTarget {
    /// This is the information used to identify the data relative to the contract,
    /// for storage extraction its the slot, for receipts its the event signature for example
    pub extraction_identifier: [Target; 8],
    /// Column identifier
    pub identifier: Target,
    /// Prefix used in computing mpt metadata
    pub metadata_prefix: [Target; 8],
    /// The length of the field to extract in the EVM word
    pub length: Target,
}

impl InputColumnInfoTarget {
    /// Compute the MPT metadata.
    pub fn mpt_metadata(&self, b: &mut CBuilder) -> HashOutTarget {
        // key_column_md = H( "\0KEY" || slot)
        let inputs = [self.metadata_prefix(), self.extraction_id().as_slice()].concat();

        b.hash_n_to_hash_no_pad::<CHasher>(inputs)
    }

    /// Compute the column information digest.
    pub fn digest(&self, b: &mut CBuilder) -> CurveTarget {
        let metadata = self.mpt_metadata(b);

        // digest = D(mpt_metadata || info.identifier)
        let inputs = [metadata.elements.as_slice(), &[self.identifier()]].concat();

        b.map_to_curve_point(&inputs)
    }

    pub fn extraction_id(&self) -> [Target; 8] {
        self.extraction_identifier
    }

    pub fn identifier(&self) -> Target {
        self.identifier
    }

    pub fn metadata_prefix(&self) -> &[Target] {
        self.metadata_prefix.as_slice()
    }

    pub fn length(&self) -> Target {
        self.length
    }
}

pub trait CircuitBuilderColumnInfo {
    /// Add a virtual extracted column info target.
    fn add_virtual_extracted_column_info(&mut self) -> ExtractedColumnInfoTarget;

    /// Add a virtual input column info target.
    fn add_virtual_input_column_info(&mut self) -> InputColumnInfoTarget;
}

impl CircuitBuilderColumnInfo for CBuilder {
    fn add_virtual_extracted_column_info(&mut self) -> ExtractedColumnInfoTarget {
        let extraction_identifier: [Target; 8] = array::from_fn(|_| self.add_virtual_target());
        let [identifier, byte_offset, length, location_offset] =
            array::from_fn(|_| self.add_virtual_target());

        ExtractedColumnInfoTarget {
            extraction_identifier,
            identifier,
            byte_offset,
            length,
            location_offset,
        }
    }

    fn add_virtual_input_column_info(&mut self) -> InputColumnInfoTarget {
        let extraction_identifier: [Target; 8] = array::from_fn(|_| self.add_virtual_target());
        let metadata_prefix: [Target; 8] = array::from_fn(|_| self.add_virtual_target());
        let [identifier, length] = array::from_fn(|_| self.add_virtual_target());

        InputColumnInfoTarget {
            extraction_identifier,
            identifier,
            metadata_prefix,
            length,
        }
    }
}

pub trait WitnessWriteColumnInfo {
    fn set_extracted_column_info_target(
        &mut self,
        target: &ExtractedColumnInfoTarget,
        value: &ExtractedColumnInfo,
    );

    fn set_extracted_column_info_target_arr(
        &mut self,
        targets: &[ExtractedColumnInfoTarget],
        values: &[ExtractedColumnInfo],
    ) {
        zip_eq(targets, values)
            .for_each(|(target, value)| self.set_extracted_column_info_target(target, value));
    }

    fn set_input_column_info_target(
        &mut self,
        target: &InputColumnInfoTarget,
        value: &InputColumnInfo,
    );

    fn set_input_column_info_target_arr(
        &mut self,
        targets: &[InputColumnInfoTarget],
        values: &[InputColumnInfo],
    ) {
        zip_eq(targets, values)
            .for_each(|(target, value)| self.set_input_column_info_target(target, value));
    }
}

impl<T: WitnessWrite<F>> WitnessWriteColumnInfo for T {
    fn set_extracted_column_info_target(
        &mut self,
        target: &ExtractedColumnInfoTarget,
        value: &ExtractedColumnInfo,
    ) {
        target
            .extraction_identifier
            .iter()
            .zip(value.extraction_identifier.iter())
            .for_each(|(t, v)| self.set_target(*t, *v));
        [
            (target.identifier, value.identifier),
            (target.byte_offset, value.byte_offset),
            (target.length, value.length),
            (target.location_offset, value.location_offset),
        ]
        .into_iter()
        .for_each(|(t, v)| self.set_target(t, v));
    }

    fn set_input_column_info_target(
        &mut self,
        target: &InputColumnInfoTarget,
        value: &InputColumnInfo,
    ) {
        target
            .extraction_identifier
            .iter()
            .zip(value.extraction_identifier.iter())
            .for_each(|(t, v)| self.set_target(*t, *v));
        target
            .metadata_prefix
            .iter()
            .zip(value.metadata_prefix().iter())
            .for_each(|(t, v)| self.set_target(*t, *v));

        self.set_target(target.length, value.length());
        self.set_target(target.identifier, value.identifier());
    }
}