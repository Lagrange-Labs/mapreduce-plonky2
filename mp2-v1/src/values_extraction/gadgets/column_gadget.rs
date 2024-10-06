//! The column gadget is used to extract either a single column when it’s a simple value or
//! multiple columns for struct.

use super::column_info::ColumnInfoTarget;
use itertools::Itertools;
use mp2_common::{
    array::{Array, VectorWire},
    group_hashing::CircuitBuilderGroupHashing,
    types::{CBuilder, MAPPING_LEAF_VALUE_LEN},
    F,
};
use plonky2::{
    field::types::Field,
    iop::target::{BoolTarget, Target},
};
use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget};
use std::iter::once;

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
        let all_bytes = (0..u8::MAX as u16).collect_vec();
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
            // digest = D(info.identifier || extracted_value)
            let inputs = once(info.identifier).chain(extracted_value).collect_vec();
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
        let next_byte = if i < 31 { value_bytes[i + 1] } else { zero };

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
            let last_part = b.add_lookup_from_index(current_byte, last_bits_lookup_indexes[7 - j]);
            let last_part = b.mul_const(F::from_canonical_u8(1 << (j + 1)), last_part);
            let byte = b.add(first_part, last_part);
            possible_bytes.push(byte);
        }

        // Get the actual byte.
        let acutal_byte = b.random_access(info.bit_offset, possible_bytes);
        aligned_bytes.push(acutal_byte);
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
        let offset = b.add_const(info.byte_offset, F::from_canonical_u8(i));
        // Set to 0 if found the last byte.
        let offset = b.select(last_byte_found, zero, offset);
        let byte = b.random_access(offset, aligned_bytes.clone());
        result_bytes.push(byte);
        // is_last_byte = offset == last_byte_offset
        let is_last_byte = b.is_equal(offset, last_byte_offset);
        // last_byte_found |= is_last_byte
        last_byte_found = b.or(last_byte_found, is_last_byte);
    }

    // real_len = last_byte_offset - byte_offset + 1
    let real_len = b.sub(last_byte_offset, info.byte_offset);
    let real_len = b.add_const(real_len, F::ONE);
    // result_vec = {result_bytes, real_len}
    // result = result_vec.normalize_left()
    let arr: Array<Target, MAPPING_LEAF_VALUE_LEN> = result_bytes.try_into().unwrap();
    let result_vec = VectorWire { arr, real_len };
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
    for i in 0..7 {
        // byte1 = first_bits_1(last_byte)
        // byte2 = first_bits_2(last_byte)
        // ...
        // byte7 = first_bits_7(last_byte)
        let byte = b.add_lookup_from_index(last_byte, first_bits_lookup_indexes[i]);
        possible_bytes.push(byte);
    }
    result[31] = b.random_access(length_mod_8, possible_bytes);

    result
}
