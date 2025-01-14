//! The metadata gadget is used to ensure the correct extraction from the set of all identifiers.

use crate::values_extraction::{DATA_PREFIX, GAS_USED_PREFIX, TOPIC_PREFIX, TX_INDEX_PREFIX};

use super::column_info::{
    CircuitBuilderColumnInfo, ExtractedColumnInfo, ExtractedColumnInfoTarget, InputColumnInfo,
    InputColumnInfoTarget, WitnessWriteColumnInfo,
};
use alloy::{
    primitives::{Log, B256},
    rlp::Decodable,
};
use itertools::Itertools;
use mp2_common::{
    array::{Array, Targetable, L32},
    eth::EventLogInfo,
    group_hashing::CircuitBuilderGroupHashing,
    poseidon::H,
    serialization::{deserialize_long_array, serialize_long_array},
    types::{CBuilder, HashOutput},
    u256::{CircuitBuilderU256, UInt256Target},
    utils::{Endianness, Packer},
    F,
};
use plonky2::{
    field::types::{Field, PrimeField64},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::config::Hasher,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::{
    curve::curve::Point,
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget},
};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::{array, iter::once};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableMetadata<const MAX_COLUMNS: usize, const INPUT_COLUMNS: usize>
where
    [(); MAX_COLUMNS - INPUT_COLUMNS]:,
{
    /// Columns that aren't extracted from the node, like the mapping keys
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) input_columns: [InputColumnInfo; INPUT_COLUMNS],
    /// The extracted column info
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) extracted_columns: [ExtractedColumnInfo; MAX_COLUMNS - INPUT_COLUMNS],
    /// Actual column number
    pub(crate) num_actual_columns: usize,
}

impl<const MAX_COLUMNS: usize, const INPUT_COLUMNS: usize> TableMetadata<MAX_COLUMNS, INPUT_COLUMNS>
where
    [(); MAX_COLUMNS - INPUT_COLUMNS]:,
{
    /// Create a new instance of [`TableColumns`] from a slice of [`ColumnInfo`] we assume that the columns are sorted into a predetermined order.
    pub fn new(
        input_columns: &[InputColumnInfo; INPUT_COLUMNS],
        extracted_columns: &[ExtractedColumnInfo],
    ) -> TableMetadata<MAX_COLUMNS, INPUT_COLUMNS> {
        let num_actual_columns = extracted_columns.len() + INPUT_COLUMNS;
        // Check that we don't have too many columns
        assert!(num_actual_columns <= MAX_COLUMNS);

        // We order the columns so that the location_offset increases, then if two columns have the same location offset
        // they are ordered by increasing byte offset. Then if byte offset is the same they are ordered such that if `self.is_extracted` is
        // false they appear first.
        let mut table_info = [ExtractedColumnInfo::default(); { MAX_COLUMNS - INPUT_COLUMNS }];
        table_info
            .iter_mut()
            .zip(extracted_columns)
            .for_each(|(ti, &column)| *ti = column);

        TableMetadata::<MAX_COLUMNS, INPUT_COLUMNS> {
            input_columns: input_columns.clone(),
            extracted_columns: table_info,
            num_actual_columns,
        }
    }

    /// Create a sample MPT metadata. It could be used in integration tests.
    pub fn sample(
        flag: bool,
        input_prefixes: &[&[u8]; INPUT_COLUMNS],
        extraction_identifier: &[u8],
        location_offset: F,
    ) -> Self {
        let rng = &mut thread_rng();

        let input_columns = input_prefixes
            .map(|prefix| InputColumnInfo::new(extraction_identifier, rng.gen(), prefix, 32));

        let num_actual_columns = rng.gen_range(1..=MAX_COLUMNS - INPUT_COLUMNS);

        let mut extraction_vec = extraction_identifier.pack(Endianness::Little);
        extraction_vec.resize(8, 0u32);
        extraction_vec.reverse();
        let extraction_id: [F; 8] = extraction_vec
            .into_iter()
            .map(F::from_canonical_u32)
            .collect::<Vec<F>>()
            .try_into()
            .expect("This should never fail");

        let extracted_columns = (0..num_actual_columns)
            .map(|_| ExtractedColumnInfo::sample(flag, &extraction_id, location_offset))
            .collect::<Vec<ExtractedColumnInfo>>();

        TableMetadata::<MAX_COLUMNS, INPUT_COLUMNS>::new(&input_columns, &extracted_columns)
    }

    /// Get the input columns
    pub fn input_columns(&self) -> &[InputColumnInfo] {
        self.input_columns.as_slice()
    }

    /// Get the columns we actually extract from
    pub fn extracted_columns(&self) -> &[ExtractedColumnInfo] {
        &self.extracted_columns[..self.num_actual_columns - INPUT_COLUMNS]
    }

    /// Compute the metadata digest.
    pub fn digest(&self) -> Point {
        let input_iter = self
            .input_columns()
            .iter()
            .map(|column| column.digest())
            .collect::<Vec<Point>>();

        let extracted_iter = self
            .extracted_columns()
            .iter()
            .map(|column| column.digest())
            .collect::<Vec<Point>>();

        input_iter
            .into_iter()
            .chain(extracted_iter)
            .fold(Point::NEUTRAL, |acc, b| acc + b)
    }

    /// Computes the value digest for a provided value array and the unique row_id
    pub fn input_value_digest(
        &self,
        input_vals: &[&[u8; 32]; INPUT_COLUMNS],
    ) -> (Point, HashOutput) {
        let point = self
            .input_columns()
            .iter()
            .zip(input_vals.iter())
            .fold(Point::NEUTRAL, |acc, (column, value)| {
                acc + column.value_digest(value.as_slice())
            });

        let row_id_input = input_vals
            .map(|key| {
                key.pack(Endianness::Big)
                    .into_iter()
                    .map(F::from_canonical_u32)
            })
            .into_iter()
            .flatten()
            .collect::<Vec<F>>();

        (point, H::hash_no_pad(&row_id_input).into())
    }

    pub fn extracted_value_digest(
        &self,
        value: &[u8],
        extraction_id: &[u8],
        location_offset: F,
    ) -> Point {
        let mut extraction_vec = extraction_id.pack(Endianness::Little);
        extraction_vec.resize(8, 0u32);
        extraction_vec.reverse();
        let extraction_id: [F; 8] = extraction_vec
            .into_iter()
            .map(F::from_canonical_u32)
            .collect::<Vec<F>>()
            .try_into()
            .expect("This should never fail");

        self.extracted_columns()
            .iter()
            .fold(Point::NEUTRAL, |acc, column| {
                let correct_id = extraction_id == column.extraction_id();
                let correct_offset = location_offset == column.location_offset();
                let correct_location = correct_id && correct_offset;

                if correct_location {
                    acc + column.value_digest(value)
                } else {
                    acc
                }
            })
    }

    pub fn extracted_receipt_value_digest<const NO_TOPICS: usize, const MAX_DATA: usize>(
        &self,
        value: &[u8],
        event: &EventLogInfo<NO_TOPICS, MAX_DATA>,
    ) -> Point {
        // Convert to Rlp form so we can use provided methods.
        let node_rlp = rlp::Rlp::new(value);

        // The actual receipt data is item 1 in the list
        let (receipt_rlp, receipt_off) = node_rlp.at_with_offset(1).unwrap();
        // The rlp encoded Receipt is not a list but a string that is formed of the `tx_type` followed by the remaining receipt
        // data rlp encoded as a list. We retrieve the payload info so that we can work out relevant offsets later.
        let receipt_str_payload = receipt_rlp.payload_info().unwrap();

        // We make a new `Rlp` struct that should be the encoding of the inner list representing the `ReceiptEnvelope`
        let receipt_list = rlp::Rlp::new(&receipt_rlp.data().unwrap()[1..]);

        // The logs themselves start are the item at index 3 in this list
        let (logs_rlp, logs_off) = receipt_list.at_with_offset(3).unwrap();

        // We calculate the offset the that the logs are at from the start of the node
        let logs_offset = receipt_off + receipt_str_payload.header_len + 1 + logs_off;

        // Now we produce an iterator over the logs with each logs offset.
        #[allow(clippy::unnecessary_find_map)]
        let relevant_log_offset = std::iter::successors(Some(0usize), |i| Some(i + 1))
            .map_while(|i| logs_rlp.at_with_offset(i).ok())
            .find_map(|(log_rlp, log_off)| {
                let mut bytes = log_rlp.as_raw();
                let log = Log::decode(&mut bytes).expect("Couldn't decode log");

                if log.address == event.address
                    && log
                        .data
                        .topics()
                        .contains(&B256::from(event.event_signature))
                {
                    Some(logs_offset + log_off)
                } else {
                    Some(0usize)
                }
            })
            .expect("No relevant log in the provided value");

        self.extracted_columns()
            .iter()
            .fold(Point::NEUTRAL, |acc, column| {
                acc + column.receipt_value_digest(value, relevant_log_offset)
            })
    }

    pub fn num_actual_columns(&self) -> usize {
        self.num_actual_columns
    }
}

pub struct TableMetadataGadget<const MAX_COLUMNS: usize, const INPUT_COLUMNS: usize>;

impl<const MAX_COLUMNS: usize, const INPUT_COLUMNS: usize>
    TableMetadataGadget<MAX_COLUMNS, INPUT_COLUMNS>
where
    [(); MAX_COLUMNS - INPUT_COLUMNS]:,
{
    pub(crate) fn build(b: &mut CBuilder) -> TableMetadataTarget<MAX_COLUMNS, INPUT_COLUMNS> {
        TableMetadataTarget {
            input_columns: array::from_fn(|_| b.add_virtual_input_column_info()),
            extracted_columns: array::from_fn(|_| b.add_virtual_extracted_column_info()),
            num_actual_columns: b.add_virtual_target(),
        }
    }

    pub(crate) fn assign(
        pw: &mut PartialWitness<F>,
        columns_metadata: &TableMetadata<MAX_COLUMNS, INPUT_COLUMNS>,
        metadata_target: &TableMetadataTarget<MAX_COLUMNS, INPUT_COLUMNS>,
    ) {
        pw.set_input_column_info_target_arr(
            metadata_target.input_columns.as_slice(),
            columns_metadata.input_columns.as_slice(),
        );

        pw.set_extracted_column_info_target_arr(
            metadata_target.extracted_columns.as_slice(),
            columns_metadata.extracted_columns.as_slice(),
        );
        pw.set_target(
            metadata_target.num_actual_columns,
            F::from_canonical_usize(columns_metadata.num_actual_columns),
        );
    }
}

impl<const NO_TOPICS: usize, const MAX_DATA: usize, const MAX_COLUMNS: usize>
    From<EventLogInfo<NO_TOPICS, MAX_DATA>> for TableMetadata<MAX_COLUMNS, 2>
where
    [(); MAX_COLUMNS - 2 - NO_TOPICS - MAX_DATA]:,
{
    fn from(event: EventLogInfo<NO_TOPICS, MAX_DATA>) -> Self {
        let extraction_id = event.event_signature;

        let tx_index_input = [
            event.address.as_slice(),
            event.event_signature.as_slice(),
            TX_INDEX_PREFIX,
        ]
        .concat()
        .into_iter()
        .map(F::from_canonical_u8)
        .collect::<Vec<F>>();
        let tx_index_column_id = H::hash_no_pad(&tx_index_input).elements[0].to_canonical_u64();

        let gas_used_input = [
            event.address.as_slice(),
            event.event_signature.as_slice(),
            GAS_USED_PREFIX,
        ]
        .concat()
        .into_iter()
        .map(F::from_canonical_u8)
        .collect::<Vec<F>>();
        let gas_used_column_id = H::hash_no_pad(&gas_used_input).elements[0].to_canonical_u64();

        let tx_index_input_column = InputColumnInfo::new(
            extraction_id.as_slice(),
            tx_index_column_id,
            TX_INDEX_PREFIX,
            32,
        );
        let gas_used_index_column = InputColumnInfo::new(
            extraction_id.as_slice(),
            gas_used_column_id,
            GAS_USED_PREFIX,
            32,
        );

        let topic_columns = event
            .topics
            .iter()
            .enumerate()
            .map(|(j, &offset)| {
                let input = [
                    event.address.as_slice(),
                    event.event_signature.as_slice(),
                    TOPIC_PREFIX,
                    &[j as u8 + 1],
                ]
                .concat()
                .into_iter()
                .map(F::from_canonical_u8)
                .collect::<Vec<F>>();

                let topic_id = H::hash_no_pad(&input).elements[0].to_canonical_u64();
                ExtractedColumnInfo::new(extraction_id.as_slice(), topic_id, offset, 32, 0)
            })
            .collect::<Vec<ExtractedColumnInfo>>();

        let data_columns = event
            .data
            .iter()
            .enumerate()
            .map(|(j, &offset)| {
                let input = [
                    event.address.as_slice(),
                    event.event_signature.as_slice(),
                    DATA_PREFIX,
                    &[j as u8 + 1],
                ]
                .concat()
                .into_iter()
                .map(F::from_canonical_u8)
                .collect::<Vec<F>>();

                let data_id = H::hash_no_pad(&input).elements[0].to_canonical_u64();
                ExtractedColumnInfo::new(extraction_id.as_slice(), data_id, offset, 32, 0)
            })
            .collect::<Vec<ExtractedColumnInfo>>();

        let extracted_columns = [topic_columns, data_columns].concat();

        TableMetadata::<MAX_COLUMNS, 2>::new(
            &[tx_index_input_column, gas_used_index_column],
            &extracted_columns,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct TableMetadataTarget<const MAX_COLUMNS: usize, const INPUT_COLUMNS: usize>
where
    [(); MAX_COLUMNS - INPUT_COLUMNS]:,
{
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    /// Information about all input columns of the table
    pub(crate) input_columns: [InputColumnInfoTarget; INPUT_COLUMNS],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    /// Information about all extracted columns of the table
    pub(crate) extracted_columns: [ExtractedColumnInfoTarget; MAX_COLUMNS - INPUT_COLUMNS],
    /// The number of actual columns
    pub(crate) num_actual_columns: Target,
}

type ReceiptExtractedOutput = (
    Array<Target, 20>,
    Array<Target, 32>,
    CurveTarget,
    CurveTarget,
);

impl<const MAX_COLUMNS: usize, const INPUT_COLUMNS: usize>
    TableMetadataTarget<MAX_COLUMNS, INPUT_COLUMNS>
where
    [(); MAX_COLUMNS - INPUT_COLUMNS]:,
{
    #[cfg(test)]
    pub fn metadata_digest(&self, b: &mut CBuilder) -> CurveTarget {
        let input_points = self
            .input_columns
            .iter()
            .map(|column| column.digest(b))
            .collect::<Vec<CurveTarget>>();
        let zero = b.zero();
        let curve_zero = b.curve_zero();
        let extracted_points = self
            .extracted_columns
            .iter()
            .map(|column| {
                let selector = b.is_equal(zero, column.identifier());
                let poss_digest = column.digest(b);
                b.select_curve_point(selector, curve_zero, poss_digest)
            })
            .collect::<Vec<CurveTarget>>();

        let points = [input_points, extracted_points].concat();

        b.add_curve_point(&points)
    }

    /// Computes the value digest and metadata digest for the input columns from the supplied inputs.
    /// Outputs are ordered as `(MetadataDigest, ValueDigest)`.
    pub(crate) fn inputs_digests(
        &self,
        b: &mut CBuilder,
        input_values: &[Array<U32Target, 8>; INPUT_COLUMNS],
    ) -> (CurveTarget, CurveTarget) {
        let (metadata_points, value_points): (Vec<CurveTarget>, Vec<CurveTarget>) = self
            .input_columns
            .iter()
            .zip(input_values.iter())
            .map(|(column, input_val)| {
                let inputs = once(column.identifier)
                    .chain(input_val.arr.iter().map(|t| t.to_target()))
                    .collect_vec();
                (column.digest(b), b.map_to_curve_point(&inputs))
            })
            .unzip();

        (
            b.add_curve_point(&metadata_points),
            b.add_curve_point(&value_points),
        )
    }

    /// Computes the value digest and metadata digest for the extracted columns from the supplied value
    /// Outputs are ordered as `(MetadataDigest, ValueDigest)`.
    pub(crate) fn extracted_digests<const VALUE_LEN: usize>(
        &self,
        b: &mut CBuilder,
        value: &Array<Target, VALUE_LEN>,
        location_no_offset: &UInt256Target,
        location: &UInt256Target,
        extraction_id: &[Target; 8],
    ) -> (CurveTarget, CurveTarget) {
        let zero = b.zero();
        let one = b.one();

        let curve_zero = b.curve_zero();

        let ex_id_arr = Array::<Target, 8>::from(*extraction_id);

        let (metadata_points, value_points): (Vec<CurveTarget>, Vec<CurveTarget>) = self
            .extracted_columns
            .into_iter()
            .map(|column| {
                // Calculate the column digest
                let column_digest = column.digest(b);
                // The column is real if the identifier is non-zero so we use it as a selector
                let selector = b.is_equal(zero, column.identifier());

                // Now we work out if the column is to be extracted, if it is we will take the value we recover from `value[column.byte_offset..column.byte_offset + column.length]`
                // left padded.
                let loc_offset_u256 =
                    UInt256Target::new_from_target_unsafe(b, column.location_offset());
                let (sum, _) = b.add_u256(&loc_offset_u256, location_no_offset);
                let correct_offset = b.is_equal_u256(&sum, location);

                // We check that we have the correct base extraction id
                let column_ex_id_arr = Array::<Target, 8>::from(column.extraction_id());
                let correct_extraction_id = column_ex_id_arr.equals(b, &ex_id_arr);

                // We only extract if we are in the correct location AND `column.is_extracted` is true
                let correct_location = b.and(correct_offset, correct_extraction_id);
                let not_selector = b.not(selector);
                // We also make sure we should actually extract for this column, otherwise we have issues
                // when indexing into the array.
                let correct = b.and(not_selector, correct_location);

                // last_byte_found lets us know whether we continue extracting or not.
                // Hence if we want to extract values `extract` will be true so `last_byte_found` should be false
                let mut last_byte_found = b.not(correct);

                // Even if the constant `VALUE_LEN` is larger than 32 this is the maximum size in bytes
                // of data that we extract per column
                let mut result_bytes = [zero; 32];

                // We iterate over the result bytes in reverse order, the first element that we want to access
                // from `value` is `value[MAPPING_LEAF_VALUE_LEN - column.byte_offset - column.length]` and then
                // we keep extracting until we reach `value[column.byte_offset]`.

                let last_byte_offset = b.add(column.byte_offset, column.length);

                let start = b.sub(last_byte_offset, one);

                result_bytes
                    .iter_mut()
                    .rev()
                    .enumerate()
                    .for_each(|(i, out_byte)| {
                        // offset = info.byte_offset + i
                        let index = b.constant(F::from_canonical_usize(i));
                        let offset = b.sub(start, index);
                        // Set to 0 if found the last byte.
                        let offset = b.select(last_byte_found, zero, offset);

                        // Since VALUE_LEN is a constant that is determined at compile time this conditional won't
                        // cause any issues with the circuit.
                        let byte = if VALUE_LEN < 64 {
                            b.random_access(offset, value.arr.to_vec())
                        } else {
                            value.random_access_large_array(b, offset)
                        };

                        // Now if `last_byte_found` is true we add zero, otherwise add `byte`
                        let to_add = b.select(last_byte_found, zero, byte);

                        *out_byte = b.add(*out_byte, to_add);
                        // is_last_byte = offset == last_byte_offset
                        let is_last_byte = b.is_equal(offset, column.byte_offset);
                        // last_byte_found |= is_last_byte
                        last_byte_found = b.or(last_byte_found, is_last_byte);
                    });

                let result_arr = Array::<Target, 32>::from_array(result_bytes);

                let result_packed: Array<U32Target, { L32(32) }> =
                    Array::<Target, 32>::pack(&result_arr, b, Endianness::Big);

                let inputs = once(column.identifier)
                    .chain(result_packed.arr.iter().map(|t| t.to_target()))
                    .collect_vec();
                let value_digest = b.map_to_curve_point(&inputs);
                let negated = b.not(correct_location);
                let value_selector = b.or(negated, selector);
                (
                    b.curve_select(selector, curve_zero, column_digest),
                    b.curve_select(value_selector, curve_zero, value_digest),
                )
            })
            .unzip();

        (
            b.add_curve_point(&metadata_points),
            b.add_curve_point(&value_points),
        )
    }

    /// Computes the value digest and metadata digest for the extracted columns from the supplied value
    /// Outputs are ordered as `(MetadataDigest, ValueDigest)`.
    pub(crate) fn extracted_receipt_digests<const VALUE_LEN: usize>(
        &self,
        b: &mut CBuilder,
        value: &Array<Target, VALUE_LEN>,
        log_offset: Target,
        address_offset: Target,
        signature_offset: Target,
    ) -> ReceiptExtractedOutput {
        let zero = b.zero();
        let one = b.one();
        let curve_zero = b.curve_zero();

        let address_start = b.add(log_offset, address_offset);
        let address = value.extract_array_large::<_, _, 20>(b, address_start);

        let signature_start = b.add(log_offset, signature_offset);
        let signature = value.extract_array_large::<_, _, 32>(b, signature_start);

        let (metadata_points, value_points): (Vec<CurveTarget>, Vec<CurveTarget>) = self
            .extracted_columns
            .into_iter()
            .map(|column| {
                // Calculate the column digest
                let column_digest = column.digest(b);
                // The column is real if the identifier is non-zero so we use it as a selector
                let selector = b.is_equal(zero, column.identifier());

                let location = b.add(log_offset, column.byte_offset());

                // last_byte_found lets us know whether we continue extracting or not.
                // If `selector` is false then we have data to extract
                let mut last_byte_found = selector;

                // Even if the constant `VALUE_LEN` is larger than 32 this is the maximum size in bytes
                // of data that we extract per column
                let mut result_bytes = [zero; 32];

                // We iterate over the result bytes in reverse order, the first element that we want to access
                // from `value` is `value[location + column.length - 1]` and then
                // we keep extracting until we reach `value[location]`.

                let last_byte_offset = b.add(location, column.length);

                let start = b.sub(last_byte_offset, one);

                result_bytes
                    .iter_mut()
                    .rev()
                    .enumerate()
                    .for_each(|(i, out_byte)| {
                        // offset = info.byte_offset + i
                        let index = b.constant(F::from_canonical_usize(i));
                        let offset = b.sub(start, index);
                        // Set to 0 if found the last byte.
                        let offset = b.select(last_byte_found, zero, offset);

                        // Since VALUE_LEN is a constant that is determined at compile time this conditional won't
                        // cause any issues with the circuit.
                        let byte = if VALUE_LEN < 64 {
                            b.random_access(offset, value.arr.to_vec())
                        } else {
                            value.random_access_large_array(b, offset)
                        };

                        // Now if `last_byte_found` is true we add zero, otherwise add `byte`
                        let to_add = b.select(last_byte_found, zero, byte);

                        *out_byte = b.add(*out_byte, to_add);
                        // is_last_byte = offset == last_byte_offset
                        let is_last_byte = b.is_equal(offset, column.byte_offset);
                        // last_byte_found |= is_last_byte
                        last_byte_found = b.or(last_byte_found, is_last_byte);
                    });

                let result_arr = Array::<Target, 32>::from_array(result_bytes);

                let result_packed: Array<U32Target, { L32(32) }> =
                    Array::<Target, 32>::pack(&result_arr, b, Endianness::Big);

                let inputs = once(column.identifier)
                    .chain(result_packed.arr.iter().map(|t| t.to_target()))
                    .collect_vec();
                let value_digest = b.map_to_curve_point(&inputs);
                (
                    b.curve_select(selector, curve_zero, column_digest),
                    b.curve_select(selector, curve_zero, value_digest),
                )
            })
            .unzip();

        (
            address,
            signature,
            b.add_curve_point(&metadata_points),
            b.add_curve_point(&value_points),
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tests::TEST_MAX_COLUMNS;
    use mp2_common::{C, D};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2_ecgfp5::gadgets::curve::PartialWitnessCurve;

    #[derive(Clone, Debug)]
    struct TestMedataCircuit {
        columns_metadata: TableMetadata<TEST_MAX_COLUMNS, 0>,
        slot: u8,
        expected_num_actual_columns: usize,
        expected_metadata_digest: Point,
    }

    impl UserCircuit<F, D> for TestMedataCircuit {
        // Metadata target + slot + expected number of actual columns + expected metadata digest
        type Wires = (
            TableMetadataTarget<TEST_MAX_COLUMNS, 0>,
            Target,
            Target,
            CurveTarget,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let metadata_target = TableMetadataGadget::build(b);
            let slot = b.add_virtual_target();
            let expected_num_actual_columns = b.add_virtual_target();
            let expected_metadata_digest = b.add_virtual_curve_target();

            let metadata_digest = metadata_target.metadata_digest(b);

            b.connect_curve_points(metadata_digest, expected_metadata_digest);

            b.connect(
                metadata_target.num_actual_columns,
                expected_num_actual_columns,
            );

            (
                metadata_target,
                slot,
                expected_num_actual_columns,
                expected_metadata_digest,
            )
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            TableMetadataGadget::assign(pw, &self.columns_metadata, &wires.0);

            pw.set_target(wires.1, F::from_canonical_u8(self.slot));
            pw.set_target(
                wires.2,
                F::from_canonical_usize(self.expected_num_actual_columns),
            );
            pw.set_curve_target(wires.3, self.expected_metadata_digest.to_weierstrass());
        }
    }

    #[test]
    fn test_values_extraction_metadata_gadget() {
        let rng = &mut thread_rng();

        let slot = rng.gen();
        let evm_word = rng.gen();

        let metadata = TableMetadata::<TEST_MAX_COLUMNS, 0>::sample(
            true,
            &[],
            &[slot],
            F::from_canonical_u32(evm_word),
        );

        let expected_num_actual_columns = metadata.num_actual_columns();
        let expected_metadata_digest = metadata.digest();

        let test_circuit = TestMedataCircuit {
            columns_metadata: metadata,
            slot,
            expected_num_actual_columns,
            expected_metadata_digest,
        };

        let _ = run_circuit::<F, D, C, _>(test_circuit);
    }
}
