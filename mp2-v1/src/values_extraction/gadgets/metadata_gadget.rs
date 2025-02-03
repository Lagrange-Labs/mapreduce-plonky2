//! The metadata gadget is used to ensure the correct extraction from the set of all identifiers.

use crate::values_extraction::{DATA_PREFIX, GAS_USED_PREFIX, TOPIC_PREFIX, TX_INDEX_PREFIX};

use super::column_info::{
    CircuitBuilderColumnInfo, ExtractedColumnInfo, ExtractedColumnInfoTarget, InputColumnInfo,
    InputColumnInfoTarget, WitnessWriteColumnInfo,
};

use itertools::Itertools;
use mp2_common::{
    array::{Array, Targetable},
    eth::{left_pad32, EventLogInfo, StorageSlot},
    group_hashing::CircuitBuilderGroupHashing,
    poseidon::{empty_poseidon_hash, hash_to_int_value, H},
    serialization::{
        deserialize_array, deserialize_long_array, serialize_array, serialize_long_array,
    },
    types::{CBuilder, HashOutput},
    utils::{Endianness, Packer, ToFields},
    F,
};
use plonky2::{
    field::types::{Field, PrimeField64},
    hash::hash_types::HashOut,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::config::Hasher,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::{
    curve::{curve::Point, scalar_field::Scalar},
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget},
};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::{array, borrow::Borrow, iter::once};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// This struct stores the [`InputColumnInfo`] and [`ExtractedColumnInfo`] for an object that we wish to index.
/// `input_columns` are columns whose values must be provided to an extraction circuit as witness directly, for instance mapping keys for storage variables
/// or the transaction index for receipts. There will be fixed amount of them per object type that we are indexing so we can safely store them as a vec.
/// `extracted_columns` are columns whose values are stored in the value part of an MPT node.
/// `num_actual_columns` is the number of columns that aren't dummy columns. We need this since a circuit has to always have the same number of columns but not every table will need all of them.
///
/// We use this struct so we can store all information about the columns of a table easily and use it to calculate value and metadata digests.
pub struct TableMetadata {
    /// Columns that aren't extracted from the node, like the mapping keys
    pub(crate) input_columns: Vec<InputColumnInfo>,
    /// The extracted column info
    pub(crate) extracted_columns: Vec<ExtractedColumnInfo>,
    /// Actual column number
    pub(crate) num_actual_columns: usize,
}

impl TableMetadata {
    /// Create a new instance of [`TableMetadata`] from a slice of [`InputColumnInfo`] and a slice of [`ExtractedColumnInfo`] we assume that the columns are sorted into a predetermined order.
    pub fn new(
        input_columns: &[InputColumnInfo],
        extracted_columns: &[ExtractedColumnInfo],
    ) -> TableMetadata {
        let num_actual_columns = extracted_columns.len() + input_columns.len();

        TableMetadata {
            input_columns: input_columns.to_vec(),
            extracted_columns: extracted_columns.to_vec(),
            num_actual_columns,
        }
    }

    /// Create a sample MPT metadata. It could be used in testing.
    pub fn sample<const NUM_EXTRACTED_COLUMNS: usize>(
        flag: bool,
        input_prefixes: &[&[u8]],
        extraction_identifier: &[u8],
        location_offset: F,
    ) -> Self {
        let rng = &mut thread_rng();

        let input_columns = input_prefixes
            .iter()
            .map(|prefix| InputColumnInfo::new(extraction_identifier, rng.gen(), prefix, 32))
            .collect::<Vec<InputColumnInfo>>();

        let num_actual_columns = rng.gen_range(1..=NUM_EXTRACTED_COLUMNS);

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

        TableMetadata::new(&input_columns, &extracted_columns)
    }

    /// Get the input columns
    pub fn input_columns(&self) -> &[InputColumnInfo] {
        self.input_columns.as_slice()
    }

    /// Get the columns we actually extract from
    pub fn extracted_columns(&self) -> &[ExtractedColumnInfo] {
        &self.extracted_columns[..self.num_actual_columns - self.input_columns.len()]
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
    pub fn input_value_digest<T: Borrow<[u8; 32]>>(&self, input_vals: &[T]) -> (Point, HashOutput) {
        // Make sure we have the same number of input values and columns
        assert_eq!(input_vals.len(), self.input_columns.len());

        let point = self
            .input_columns()
            .iter()
            .zip(input_vals.iter())
            .fold(Point::NEUTRAL, |acc, (column, value)| {
                acc + column.value_digest(value.borrow())
            });

        let row_id_input = input_vals
            .iter()
            .flat_map(|key| {
                key.borrow()
                    .pack(Endianness::Big)
                    .into_iter()
                    .map(F::from_canonical_u32)
            })
            .collect::<Vec<F>>();

        (point, H::hash_no_pad(&row_id_input).into())
    }

    pub fn extracted_value_digest(&self, value: &[u8], slot: &StorageSlot) -> Point {
        let mut slot_extraction_id = [F::ZERO; 8];
        slot_extraction_id[7] = F::from_canonical_u8(slot.slot());
        let location_offset = F::from_canonical_u32(slot.evm_offset());
        self.extracted_columns()
            .iter()
            .fold(Point::NEUTRAL, |acc, column| {
                let correct_extraction_id = slot_extraction_id == column.extraction_id();
                let correct_location = location_offset == column.location_offset();
                if correct_location && correct_extraction_id {
                    acc + column.value_digest(value)
                } else {
                    acc
                }
            })
    }

    pub fn extracted_receipt_value_digest<const NO_TOPICS: usize, const MAX_DATA_WORDS: usize>(
        &self,
        value: &[u8],
        event: &EventLogInfo<NO_TOPICS, MAX_DATA_WORDS>,
    ) -> Point {
        // Get the relevant log offset
        let relevant_log_offset = event
            .get_log_offset(value)
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

    /// Create a new instance of [`TableMetadata`] from an [`EventLogInfo`]. Events
    /// always have two input columns relating to the transaction index and gas used for the transaction.
    pub fn from_event_info<const NO_TOPICS: usize, const MAX_DATA_WORDS: usize>(
        event: &EventLogInfo<NO_TOPICS, MAX_DATA_WORDS>,
    ) -> TableMetadata {
        TableMetadata::from(*event)
    }

    /// Function to calculate the full receipt value digest from a receipt leaf node and [`EventLogInfo`]
    pub fn receipt_value_digest<const NO_TOPICS: usize, const MAX_DATA_WORDS: usize>(
        &self,
        tx_index: u64,
        value: &[u8],
        event: &EventLogInfo<NO_TOPICS, MAX_DATA_WORDS>,
    ) -> Point {
        let mut tx_index_input = [0u8; 32];
        tx_index_input[31] = tx_index as u8;

        // The actual receipt data is item 1 in the list
        let node_rlp = rlp::Rlp::new(value);
        let receipt_rlp = node_rlp.at(1).unwrap();

        // We make a new `Rlp` struct that should be the encoding of the inner list representing the `ReceiptEnvelope`
        let receipt_list = rlp::Rlp::new(&receipt_rlp.data().unwrap()[1..]);

        // The logs themselves start are the item at index 3 in this list
        let gas_used_rlp = receipt_list.at(1).unwrap();

        let gas_used_bytes = left_pad32(gas_used_rlp.data().unwrap());

        let (input_d, row_unique_data) =
            self.input_value_digest(&[&tx_index_input, &gas_used_bytes]);
        let extracted_vd = self.extracted_receipt_value_digest(value, event);

        let total = input_d + extracted_vd;

        // row_id = H2int(row_unique_data || num_actual_columns)
        let inputs = HashOut::from(row_unique_data)
            .to_fields()
            .into_iter()
            .chain(std::iter::once(F::from_canonical_usize(
                self.num_actual_columns,
            )))
            .collect::<Vec<F>>();
        let hash = H::hash_no_pad(&inputs);
        let row_id = hash_to_int_value(hash);

        // values_digest = values_digest * row_id
        let row_id = Scalar::from_noncanonical_biguint(row_id);

        total * row_id
    }

    /// Computes storage values digest
    pub(crate) fn storage_values_digest(
        &self,
        input_vals: &[[u8; 32]],
        value: &[u8],
        slot: &StorageSlot,
    ) -> Point {
        let (input_vd, row_unique) = self.input_value_digest(input_vals);

        let extract_vd = self.extracted_value_digest(value, slot);

        let inputs = if self.input_columns().is_empty() {
            empty_poseidon_hash()
                .to_fields()
                .into_iter()
                .chain(once(F::from_canonical_usize(
                    self.input_columns().len() + self.extracted_columns().len(),
                )))
                .collect_vec()
        } else {
            HashOut::from(row_unique)
                .to_fields()
                .into_iter()
                .chain(once(F::from_canonical_usize(
                    self.input_columns().len() + self.extracted_columns().len(),
                )))
                .collect_vec()
        };
        let hash = H::hash_no_pad(&inputs);
        let row_id = hash_to_int_value(hash);

        // values_digest = values_digest * row_id
        let row_id = Scalar::from_noncanonical_biguint(row_id);
        if slot.evm_offset() == 0 {
            (extract_vd + input_vd) * row_id
        } else {
            extract_vd * row_id
        }
    }
}

pub struct TableMetadataGadget<const MAX_EXTRACTED_COLUMNS: usize, const INPUT_COLUMNS: usize>;

impl<const MAX_EXTRACTED_COLUMNS: usize, const INPUT_COLUMNS: usize>
    TableMetadataGadget<MAX_EXTRACTED_COLUMNS, INPUT_COLUMNS>
{
    pub(crate) fn build(
        b: &mut CBuilder,
    ) -> TableMetadataTarget<MAX_EXTRACTED_COLUMNS, INPUT_COLUMNS> {
        TableMetadataTarget {
            input_columns: array::from_fn(|_| b.add_virtual_input_column_info()),
            extracted_columns: array::from_fn(|_| b.add_virtual_extracted_column_info()),
            real_columns: array::from_fn(|_| b.add_virtual_bool_target_safe()),
            num_actual_columns: b.add_virtual_target(),
        }
    }

    pub(crate) fn assign(
        pw: &mut PartialWitness<F>,
        columns_metadata: &TableMetadata,
        metadata_target: &TableMetadataTarget<MAX_EXTRACTED_COLUMNS, INPUT_COLUMNS>,
    ) {
        // First we check that we are trying to assign from a `TableMetadata` with the correct
        // number of columns
        assert_eq!(
            columns_metadata.input_columns.len(),
            metadata_target.input_columns.len()
        );

        assert!(columns_metadata.extracted_columns.len() <= MAX_EXTRACTED_COLUMNS);

        pw.set_input_column_info_target_arr(
            metadata_target.input_columns.as_slice(),
            columns_metadata.input_columns.as_slice(),
        );

        let padded_extracted_columns = columns_metadata
            .extracted_columns
            .iter()
            .copied()
            .chain(std::iter::repeat(columns_metadata.extracted_columns[0]))
            .take(MAX_EXTRACTED_COLUMNS)
            .collect::<Vec<ExtractedColumnInfo>>();
        pw.set_extracted_column_info_target_arr(
            metadata_target.extracted_columns.as_slice(),
            padded_extracted_columns.as_slice(),
        );

        metadata_target
            .real_columns
            .iter()
            .enumerate()
            .for_each(|(i, &b_target)| {
                pw.set_bool_target(b_target, i < columns_metadata.extracted_columns.len())
            });

        pw.set_target(
            metadata_target.num_actual_columns,
            F::from_canonical_usize(columns_metadata.num_actual_columns),
        );
    }
}

impl<const NO_TOPICS: usize, const MAX_DATA_WORDS: usize>
    From<EventLogInfo<NO_TOPICS, MAX_DATA_WORDS>> for TableMetadata
{
    fn from(event: EventLogInfo<NO_TOPICS, MAX_DATA_WORDS>) -> Self {
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

        TableMetadata::new(
            &[tx_index_input_column, gas_used_index_column],
            &extracted_columns,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct TableMetadataTarget<
    const MAX_EXTRACTED_COLUMNS: usize,
    const INPUT_COLUMNS: usize,
> {
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
    pub(crate) extracted_columns: [ExtractedColumnInfoTarget; MAX_EXTRACTED_COLUMNS],
    /// An Array signaling whether an extracted column is real or not
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    pub(crate) real_columns: [BoolTarget; MAX_EXTRACTED_COLUMNS],
    /// The number of actual columns
    pub(crate) num_actual_columns: Target,
}

type ReceiptExtractedOutput = (
    Array<Target, 20>,
    Array<Target, 32>,
    CurveTarget,
    CurveTarget,
);

impl<const MAX_EXTRACTED_COLUMNS: usize, const INPUT_COLUMNS: usize>
    TableMetadataTarget<MAX_EXTRACTED_COLUMNS, INPUT_COLUMNS>
{
    #[cfg(test)]
    pub fn metadata_digest(&self, b: &mut CBuilder) -> CurveTarget {
        let input_points = self
            .input_columns
            .iter()
            .map(|column| column.digest(b))
            .collect::<Vec<CurveTarget>>();

        let curve_zero = b.curve_zero();
        let extracted_points = self
            .extracted_columns
            .iter()
            .zip(self.real_columns.iter())
            .map(|(column, &selector)| {
                let poss_digest = column.digest(b);
                b.select_curve_point(selector, poss_digest, curve_zero)
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
    /// The inputs `location_no_offset` and `location` represent the MPT key for the slot of this variable without an evm word offset
    /// and the MPT key of the current leaf node respectively. To determine whether we should extract a value or not we check to see if
    /// `location_no_offset + column.loction_offset == location`, if this is true we extract, if false we dummy the value.
    pub(crate) fn extracted_digests<const VALUE_LEN: usize>(
        &self,
        b: &mut CBuilder,
        value: &Array<Target, VALUE_LEN>,
        offset: Target,
        extraction_id: &[Target; 8],
    ) -> (CurveTarget, CurveTarget) {
        let one = b.one();

        let curve_zero = b.curve_zero();

        let ex_id_arr = Array::<Target, 8>::from(*extraction_id);

        let (metadata_points, value_points): (Vec<CurveTarget>, Vec<CurveTarget>) = self
            .extracted_columns
            .into_iter()
            .zip(self.real_columns)
            .map(|(column, selector)| {
                // Calculate the column digest
                let column_digest = column.digest(b);

                // Now we work out if the column is to be extracted, if it is we will take the value we recover from `value[column.byte_offset..column.byte_offset + column.length]`
                // left padded.
                let correct_offset = b.is_equal(offset, column.location_offset());

                // We check that we have the correct base extraction id
                let column_ex_id_arr = Array::<Target, 8>::from(column.extraction_id());
                let correct_extraction_id = column_ex_id_arr.equals(b, &ex_id_arr);

                // We only extract if we are in the correct location AND `column.is_extracted` is true
                let correct_location = b.and(correct_offset, correct_extraction_id);

                // We also make sure we should actually extract for this column, otherwise we have issues
                // when indexing into the array.
                let correct = b.and(selector, correct_location);

                // last_byte_found lets us know whether we continue extracting or not.
                // Hence if we want to extract values `extract` will be true so `last_byte_found` should be false
                let last_byte_found = b.not(correct);

                // We iterate over the result bytes in reverse order, the first element that we want to access
                // from `value` is `value[MAPPING_LEAF_VALUE_LEN - column.byte_offset - column.length]` and then
                // we keep extracting until we reach `value[column.byte_offset]`.

                let last_byte_offset = b.add(column.byte_offset, column.length);

                let start = b.sub(last_byte_offset, one);

                let result_packed = column.extract_value(b, last_byte_found, value, start);

                let inputs = once(column.identifier)
                    .chain(result_packed.arr.iter().map(|t| t.to_target()))
                    .collect_vec();
                let value_digest = b.map_to_curve_point(&inputs);
                let value_selector = b.not(correct);

                (
                    b.curve_select(selector, column_digest, curve_zero),
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
        let one = b.one();
        let curve_zero = b.curve_zero();

        let address_start = b.add(log_offset, address_offset);
        let address = value.extract_array_large::<_, _, 20>(b, address_start);

        let signature_start = b.add(log_offset, signature_offset);
        let signature = value.extract_array_large::<_, _, 32>(b, signature_start);

        let (metadata_points, value_points): (Vec<CurveTarget>, Vec<CurveTarget>) = self
            .extracted_columns
            .into_iter()
            .zip(self.real_columns)
            .map(|(column, selector)| {
                // Calculate the column digest
                let column_digest = column.digest(b);
                // If selector is true (from self.real_columns) we need it to be false when we feed it into `column.extract_value()` later.
                let selector = b.not(selector);

                let location = b.add(log_offset, column.byte_offset());

                // We iterate over the result bytes in reverse order, the first element that we want to access
                // from `value` is `value[location + column.length - 1]` and then
                // we keep extracting until we reach `value[location]`.

                let last_byte_offset = b.add(location, column.length);

                let start = b.sub(last_byte_offset, one);

                // Extract the value if selector is false
                let result_packed = column.extract_value(b, selector, value, start);

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
        columns_metadata: TableMetadata,
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

        let metadata = TableMetadata::sample::<TEST_MAX_COLUMNS>(
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
