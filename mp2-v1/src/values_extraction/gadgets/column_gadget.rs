//! The column gadget is used to extract either a single column when it’s a simple value or
//! multiple columns for struct.

use super::column_info::{ColumnInfo, ColumnInfoTarget};
use itertools::Itertools;
use mp2_common::{
    array::{Array, VectorWire},
    eth::left_pad32,
    group_hashing::{map_to_curve_point, CircuitBuilderGroupHashing},
    types::{CBuilder, MAPPING_LEAF_VALUE_LEN},
    utils::{Endianness, Packer, PackerTarget},
    F,
};
use plonky2::{
    field::types::{Field, PrimeField64},
    iop::target::{BoolTarget, Target},
};
use plonky2_ecgfp5::{
    curve::curve::Point,
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget},
};
use rand::{thread_rng, Rng};
use std::{array, iter::once};

/// Number of lookup tables for getting the first bits of a byte as a big-endian integer
const NUM_FIRST_BITS_LOOKUP_TABLES: usize = 7;
/// Number of lookup tables for getting the last bits of a byte as a big-endian integer
const NUM_LAST_BITS_LOOKUP_TABLES: usize = 7;

#[derive(Debug)]
pub(crate) struct ColumnGadget<'a, const MAX_FIELD_PER_EVM: usize> {
    /// Value bytes to extract the struct
    value: &'a [Target; MAPPING_LEAF_VALUE_LEN],
    /// Information about all columns of the table to be extracted
    table_info: &'a [ColumnInfoTarget],
    /// Boolean flags specifying whether the i-th field being processed has to be extracted into a column or not
    is_extracted_columns: &'a [BoolTarget],
}

impl<'a, const MAX_FIELD_PER_EVM: usize> ColumnGadget<'a, MAX_FIELD_PER_EVM> {
    pub(crate) fn new(
        value: &'a [Target; MAPPING_LEAF_VALUE_LEN],
        table_info: &'a [ColumnInfoTarget],
        is_extracted_columns: &'a [BoolTarget],
    ) -> Self {
        assert_eq!(table_info.len(), MAX_FIELD_PER_EVM);
        assert_eq!(is_extracted_columns.len(), MAX_FIELD_PER_EVM);

        Self {
            value,
            table_info,
            is_extracted_columns,
        }
    }

    pub(crate) fn build(&self, b: &mut CBuilder) -> CurveTarget {
        // Initialize the lookup tables for getting the first bits and last bits of a byte
        // as a big-endian integer.
        // The maxiumn lookup value is `u8::MAX + 8`, since the maxiumn `info.length` is 256,
        // and we need to compute `first_bits_5(info.length + 7)`.
        let all_bytes = (0..=u8::MAX as u16 + 8).collect_vec();
        let first_bits_lookup_indexes = add_first_bits_lookup_tables(b, &all_bytes);
        let last_bits_lookup_indexes = add_last_bits_lookup_tables(b, &all_bytes);

        // Accumulate to compute the value digest.
        let mut value_digest = b.curve_zero();
        (0..MAX_FIELD_PER_EVM).for_each(|i| {
            // Get the column info to extract.
            let info = &self.table_info[i];
            // Get the flag if the field has to be extracted.
            let is_extracted = self.is_extracted_columns[i];

            // Extract the value by column info.
            let extracted_value = extract_value(
                b,
                info,
                self.value,
                &first_bits_lookup_indexes,
                &last_bits_lookup_indexes,
            );

            // Compute and accumulate to the value digest only if the current field has to be
            // extracted in a column.
            // digest = D(info.identifier || pack(extracted_value))
            let inputs = once(info.identifier)
                .chain(extracted_value.pack(b, Endianness::Big))
                .collect_vec();
            let digest = b.map_to_curve_point(&inputs);
            // new_value_digest = value_digest + digest
            let new_value_digest = b.add_curve_point(&[value_digest, digest]);
            // value_digest = is_extracted ? new_value_digest : value_digest
            value_digest = b.curve_select(is_extracted, new_value_digest, value_digest);
        });

        value_digest
    }
}

/// Get the first bits of a byte as a big-endian integer.
const fn first_bits(byte: u16, n: u8) -> u16 {
    byte >> (8 - n)
}

/// Get the last bits of a byte as a big-endian integer.
const fn last_bits(byte: u16, n: u8) -> u16 {
    byte & ((1 << n) - 1)
}

/// Macro to generate the lookup functions for getting first bits of a byte
/// as a big-endian integer
macro_rules! first_bits_lookup_funs {
    ($($n:expr),*) => {
        [
            $(|byte: u16| first_bits(byte, $n)),*
        ]
    };
}

/// Macro to generate the lookup functions for getting last bits of a byte
/// as a big-endian integer
macro_rules! last_bits_lookup_funs {
    ($($n:expr),*) => {
        [
            $(|byte: u16| last_bits(byte, $n)),*
        ]
    };
}

/// Add the lookup tables for getting the first bits of a byte
/// as a big-endian integer. And return the indexes of lookup tables.
fn add_first_bits_lookup_tables(
    b: &mut CBuilder,
    input_bytes: &[u16],
) -> [usize; NUM_FIRST_BITS_LOOKUP_TABLES] {
    let lookup_funs = first_bits_lookup_funs!(1, 2, 3, 4, 5, 6, 7);

    lookup_funs.map(|fun| b.add_lookup_table_from_fn(fun, input_bytes))
}

/// Add the lookup tables for getting the last bits of a byte
/// as a big-endian integer. And return the indexes of lookup tables.
fn add_last_bits_lookup_tables(
    b: &mut CBuilder,
    input_bytes: &[u16],
) -> [usize; NUM_LAST_BITS_LOOKUP_TABLES] {
    let lookup_funs = last_bits_lookup_funs!(1, 2, 3, 4, 5, 6, 7);

    lookup_funs.map(|fun| b.add_lookup_table_from_fn(fun, input_bytes))
}

/// Extract the value by the column info.
fn extract_value(
    b: &mut CBuilder,
    info: &ColumnInfoTarget,
    value_bytes: &[Target; MAPPING_LEAF_VALUE_LEN],
    first_bits_lookup_indexes: &[usize; NUM_FIRST_BITS_LOOKUP_TABLES],
    last_bits_lookup_indexes: &[usize; NUM_LAST_BITS_LOOKUP_TABLES],
) -> [Target; MAPPING_LEAF_VALUE_LEN] {
    let zero = b.zero();

    // Extract all the bits of the field aligined with bytes.
    let mut aligned_bytes = Vec::with_capacity(MAPPING_LEAF_VALUE_LEN);
    for i in 0..MAPPING_LEAF_VALUE_LEN {
        // Get the current and next bytes.
        let current_byte = value_bytes[i];
        let next_byte = if i < MAPPING_LEAF_VALUE_LEN - 1 {
            value_bytes[i + 1]
        } else {
            zero
        };

        // Compute the possible bytes.
        let mut possible_bytes = Vec::with_capacity(8);
        // byte0 = last_bits_8(current_byte) * 2^0 + first_bits_0(next_byte) = current_byte
        possible_bytes.push(current_byte);
        // byte1 = last_bits_7(current_byte) * 2^1 + first_bits_1(next_byte)
        // byte2 = last_bits_6(current_byte) * 2^2 + first_bits_2(next_byte)
        // ...
        // byte7 = last_bits_1(current_byte) * 2^7 + first_bits_7(next_byte)
        for j in 0..7 {
            let first_part = if i < 31 {
                b.add_lookup_from_index(next_byte, first_bits_lookup_indexes[j])
            } else {
                zero
            };
            let last_part = b.add_lookup_from_index(
                current_byte,
                last_bits_lookup_indexes[NUM_LAST_BITS_LOOKUP_TABLES - 1 - j],
            );
            let last_part = b.mul_const(F::from_canonical_u8(1 << (j + 1)), last_part);
            let byte = b.add(first_part, last_part);
            possible_bytes.push(byte);
        }

        // Get the actual byte.
        let actual_byte = b.random_access(info.bit_offset, possible_bytes);
        aligned_bytes.push(actual_byte);
    }

    // Next we need to extract in a vector from aligned_bytes[info.byte_offset] to aligned_bytes[last_byte_offset].
    // last_byte_offset = info.byte_offset + ceil(info.length / 8) - 1
    // => length_bytes = ceil(info.length / 8) = first_bits_5(info.length + 7)
    // => last_byte_offset = info.byte_offset + length_bytes - 1
    let length = b.add_const(info.length, F::from_canonical_u8(7));
    let length_bytes = b.add_lookup_from_index(length, first_bits_lookup_indexes[4]);
    let last_byte_offset = b.add(info.byte_offset, length_bytes);
    let last_byte_offset = b.add_const(last_byte_offset, F::NEG_ONE);

    // Extract from aligned_bytes[info.byte_offset] to aligned_bytes[last_byte_offset].
    let mut last_byte_found = b._false();
    let mut result_bytes = Vec::with_capacity(MAPPING_LEAF_VALUE_LEN);
    for i in 0..MAPPING_LEAF_VALUE_LEN {
        // offset = info.byte_offset + i
        let offset = b.add_const(info.byte_offset, F::from_canonical_usize(i));
        // Set to 0 if found the last byte.
        let offset = b.select(last_byte_found, zero, offset);
        let byte = b.random_access(offset, aligned_bytes.clone());
        result_bytes.push(byte);
        // is_last_byte = offset == last_byte_offset
        let is_last_byte = b.is_equal(offset, last_byte_offset);
        // last_byte_found |= is_last_byte
        last_byte_found = b.or(last_byte_found, is_last_byte);
    }

    // real_len = last_byte_offset - byte_offset + 1 = length_bytes
    // result_vec = {result_bytes, real_len}
    // result = result_vec.normalize_left()
    let arr: Array<Target, MAPPING_LEAF_VALUE_LEN> = result_bytes.try_into().unwrap();
    let result_vec = VectorWire {
        arr,
        real_len: length_bytes,
    };
    let result: Array<Target, MAPPING_LEAF_VALUE_LEN> = result_vec.normalize_left(b);
    let mut result = result.arr;

    // At last we need to retain only the first `info.length % 8` bits for
    // the last byte of result.
    // length_mod_8 = last_bits_3(info.length)
    let length_mod_8 = b.add_lookup_from_index(info.length, last_bits_lookup_indexes[2]);
    let last_byte = result[31];
    // We need to compute `first_bits_{length_mod_8}(last_byte)`.
    let mut possible_bytes = Vec::with_capacity(8);
    // byte0 = last_byte
    possible_bytes.push(last_byte);
    first_bits_lookup_indexes.iter().for_each(|lookup_index| {
        // byte1 = first_bits_1(last_byte)
        // byte2 = first_bits_2(last_byte)
        // ...
        // byte7 = first_bits_7(last_byte)
        let byte = b.add_lookup_from_index(last_byte, *lookup_index);
        possible_bytes.push(byte);
    });
    result[31] = b.random_access(length_mod_8, possible_bytes);

    result
}

#[derive(Clone, Debug)]
pub struct ColumnGadgetData<const MAX_FIELD_PER_EVM: usize> {
    pub(crate) value: [F; MAPPING_LEAF_VALUE_LEN],
    pub(crate) table_info: [ColumnInfo; MAX_FIELD_PER_EVM],
    pub(crate) num_extracted_columns: usize,
}

impl<const MAX_FIELD_PER_EVM: usize> ColumnGadgetData<MAX_FIELD_PER_EVM> {
    /// Create a new data.
    pub fn new(
        value: [F; MAPPING_LEAF_VALUE_LEN],
        table_info: [ColumnInfo; MAX_FIELD_PER_EVM],
        num_extracted_columns: usize,
    ) -> Self {
        Self {
            value,
            table_info,
            num_extracted_columns,
        }
    }

    /// Create a sample data. It could be used in integration tests.
    pub fn sample() -> Self {
        let rng = &mut thread_rng();

        let value = array::from_fn(|_| F::from_canonical_u8(rng.gen()));
        let table_info = array::from_fn(|_| ColumnInfo::sample());
        let num_extracted_columns = rng.gen_range(1..=MAX_FIELD_PER_EVM);

        Self {
            value,
            table_info,
            num_extracted_columns,
        }
    }

    /// Compute the values digest.
    pub fn digest(&self) -> Point {
        self.table_info[..self.num_extracted_columns]
            .iter()
            .fold(Point::NEUTRAL, |acc, info| {
                let extracted_value = self.extract_value(info);

                // digest = D(info.identifier || pack(extracted_value))
                let inputs = once(info.identifier)
                    .chain(extracted_value.pack(Endianness::Big))
                    .collect_vec();
                let digest = map_to_curve_point(&inputs);

                acc + digest
            })
    }

    fn extract_value(&self, info: &ColumnInfo) -> [F; MAPPING_LEAF_VALUE_LEN] {
        let bit_offset = u8::try_from(info.bit_offset.to_canonical_u64()).unwrap();
        assert!(bit_offset <= 8);
        let [byte_offset, length] =
            [info.byte_offset, info.length].map(|f| usize::try_from(f.to_canonical_u64()).unwrap());

        let value_bytes = self
            .value
            .map(|f| u8::try_from(f.to_canonical_u64()).unwrap());

        // last_byte_offset = info.byte_offset + ceil(info.length / 8) - 1
        let last_byte_offset = byte_offset + length.div_ceil(8) - 1;

        // Extract all the bits of the field aligined with bytes.
        let mut result_bytes = Vec::with_capacity(last_byte_offset - byte_offset + 1);
        for i in byte_offset..=last_byte_offset {
            // Get the current and next bytes.
            let current_byte = u16::from(value_bytes[i]);
            let next_byte = if i < 31 {
                u16::from(value_bytes[i + 1])
            } else {
                0
            };

            // actual_byte = last_bits(current_byte, 8 - bit_offset) * 2^bit_offset + first_bits(next_byte, bit_offset)
            let actual_byte = (last_bits(current_byte, 8 - bit_offset) << bit_offset)
                + first_bits(next_byte, bit_offset);

            result_bytes.push(u8::try_from(actual_byte).unwrap());
        }

        // At last we need to retain only the first `info.length % 8` bits for
        // the last byte of result.
        let last_byte = u16::from(*result_bytes.last().unwrap());
        let last_byte = first_bits(last_byte, u8::try_from(length % 8).unwrap());
        *result_bytes.last_mut().unwrap() = u8::try_from(last_byte).unwrap();

        // Normalize left.
        left_pad32(&result_bytes).map(F::from_canonical_u8)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{super::column_info::ColumnInfoTarget, *};
    use crate::{
        values_extraction::gadgets::column_info::{
            CircuitBuilderColumnInfo, WitnessWriteColumnInfo,
        },
        DEFAULT_MAX_FIELD_PER_EVM,
    };
    use mp2_common::{C, D};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2_ecgfp5::gadgets::curve::PartialWitnessCurve;

    #[derive(Clone, Debug)]
    pub(crate) struct ColumnGadgetTarget<const MAX_FIELD_PER_EVM: usize> {
        value: [Target; MAPPING_LEAF_VALUE_LEN],
        table_info: [ColumnInfoTarget; MAX_FIELD_PER_EVM],
        is_extracted_columns: [BoolTarget; MAX_FIELD_PER_EVM],
    }

    impl<const MAX_FIELD_PER_EVM: usize> ColumnGadgetTarget<MAX_FIELD_PER_EVM> {
        fn column_gadget(&self) -> ColumnGadget<MAX_FIELD_PER_EVM> {
            ColumnGadget::new(&self.value, &self.table_info, &self.is_extracted_columns)
        }
    }

    pub(crate) trait CircuitBuilderColumnGadget {
        /// Add a virtual column gadget target.
        fn add_virtual_column_gadget_target(
            &mut self,
        ) -> ColumnGadgetTarget<DEFAULT_MAX_FIELD_PER_EVM>;
    }

    impl CircuitBuilderColumnGadget for CBuilder {
        fn add_virtual_column_gadget_target(
            &mut self,
        ) -> ColumnGadgetTarget<DEFAULT_MAX_FIELD_PER_EVM> {
            let value = self.add_virtual_target_arr();
            let table_info = array::from_fn(|_| self.add_virtual_column_info());
            let is_extracted_columns = array::from_fn(|_| self.add_virtual_bool_target_safe());

            ColumnGadgetTarget {
                value,
                table_info,
                is_extracted_columns,
            }
        }
    }

    pub(crate) trait WitnessWriteColumnGadget {
        fn set_column_gadget_target(
            &mut self,
            target: &ColumnGadgetTarget<DEFAULT_MAX_FIELD_PER_EVM>,
            value: &ColumnGadgetData<DEFAULT_MAX_FIELD_PER_EVM>,
        );
    }

    impl<T: WitnessWrite<F>> WitnessWriteColumnGadget for T {
        fn set_column_gadget_target(
            &mut self,
            target: &ColumnGadgetTarget<DEFAULT_MAX_FIELD_PER_EVM>,
            data: &ColumnGadgetData<DEFAULT_MAX_FIELD_PER_EVM>,
        ) {
            self.set_target_arr(&target.value, &data.value);
            self.set_column_info_target_arr(&target.table_info, &data.table_info);
            target
                .is_extracted_columns
                .iter()
                .enumerate()
                .for_each(|(i, t)| self.set_bool_target(*t, i < data.num_extracted_columns));
        }
    }

    #[derive(Clone, Debug)]
    struct TestColumnGadgetCircuit {
        column_gadget_data: ColumnGadgetData<DEFAULT_MAX_FIELD_PER_EVM>,
        expected_column_digest: Point,
    }

    impl UserCircuit<F, D> for TestColumnGadgetCircuit {
        // Column gadget target + expected column digest
        type Wires = (ColumnGadgetTarget<DEFAULT_MAX_FIELD_PER_EVM>, CurveTarget);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let column_gadget_target = b.add_virtual_column_gadget_target();
            let expected_column_digest = b.add_virtual_curve_target();

            let column_digest = column_gadget_target.column_gadget().build(b);
            b.connect_curve_points(column_digest, expected_column_digest);

            (column_gadget_target, expected_column_digest)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_column_gadget_target(&wires.0, &self.column_gadget_data);
            pw.set_curve_target(wires.1, self.expected_column_digest.to_weierstrass());
        }
    }

    #[test]
    fn test_values_extraction_column_gadget() {
        let column_gadget_data = ColumnGadgetData::sample();
        let expected_column_digest = column_gadget_data.digest();

        let test_circuit = TestColumnGadgetCircuit {
            column_gadget_data,
            expected_column_digest,
        };

        let _ = run_circuit::<F, D, C, _>(test_circuit);
    }
}
