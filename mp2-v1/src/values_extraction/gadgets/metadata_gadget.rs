//! The metadata gadget is used to ensure the correct extraction from the set of all identifiers.

use super::column_info::{
    CircuitBuilderColumnInfo, ColumnInfo, ColumnInfoTarget, WitnessWriteColumnInfo,
};
use itertools::Itertools;
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    serialization::{
        deserialize_array, deserialize_long_array, serialize_array, serialize_long_array,
    },
    types::CBuilder,
    utils::less_than_or_equal_to_unsafe,
    CHasher, F,
};
use plonky2::{
    field::types::{Field, PrimeField64},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
};
use plonky2_ecgfp5::{
    curve::curve::Point,
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget},
};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::{array, iter::once};

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct MetadataGadget<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize> {
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    /// Information about all columns of the table
    pub(crate) table_info: [ColumnInfo; MAX_COLUMNS],
    /// Actual column number
    pub(crate) num_actual_columns: usize,
    /// Column number to be extracted
    pub(crate) num_extracted_columns: usize,
    /// EVM word that should be the same for all extracted columns
    pub(crate) evm_word: u32,
}

impl<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>
    MetadataGadget<MAX_COLUMNS, MAX_FIELD_PER_EVM>
{
    /// Create a new MPT metadata.
    pub fn new(
        mut table_info: Vec<ColumnInfo>,
        extracted_column_identifiers: &[u64],
        evm_word: u32,
    ) -> Self {
        let num_actual_columns = table_info.len();
        assert!(num_actual_columns <= MAX_COLUMNS);

        let num_extracted_columns = extracted_column_identifiers.len();
        assert!(num_extracted_columns <= MAX_FIELD_PER_EVM);

        // Move the extracted columns to the front the vector of column information.
        table_info.sort_by_key(|column_info| {
            !extracted_column_identifiers.contains(&column_info.identifier.to_canonical_u64())
        });

        // Extend the column information vector with the last element.
        let last_column_info = table_info.last().cloned().unwrap_or(ColumnInfo::default());
        table_info.resize(MAX_COLUMNS, last_column_info);
        let table_info = table_info.try_into().unwrap();

        Self {
            table_info,
            num_actual_columns,
            num_extracted_columns,
            evm_word,
        }
    }

    /// Get the actual column information.
    pub fn actual_table_info(&self) -> &[ColumnInfo] {
        &self.table_info[..self.num_actual_columns]
    }

    /// Get the extracted column information.
    pub fn extracted_table_info(&self) -> &[ColumnInfo] {
        &self.table_info[..self.num_extracted_columns]
    }

    /// Get the extracted column identifiers.
    pub fn extracted_column_identifiers(&self) -> Vec<u64> {
        self.table_info[..self.num_extracted_columns]
            .iter()
            .map(|column_info| column_info.identifier.to_canonical_u64())
            .collect_vec()
    }

    /// Create a sample MPT metadata. It could be used in integration tests.
    pub fn sample(slot: u8, evm_word: u32) -> Self {
        let rng = &mut thread_rng();

        let mut table_info = array::from_fn(|_| ColumnInfo::sample());
        let num_actual_columns = rng.gen_range(1..=MAX_COLUMNS);
        let max_extracted_columns = num_actual_columns.min(MAX_FIELD_PER_EVM);
        let num_extracted_columns = rng.gen_range(1..=max_extracted_columns);

        // if is_extracted:
        //      evm_word == info.evm_word && slot == info.slot
        let evm_word_field = F::from_canonical_u32(evm_word);
        let slot_field = F::from_canonical_u8(slot);
        table_info[..num_extracted_columns]
            .iter_mut()
            .for_each(|column_info| {
                column_info.evm_word = evm_word_field;
                column_info.slot = slot_field;
            });

        Self {
            table_info,
            num_actual_columns,
            num_extracted_columns,
            evm_word,
        }
    }

    /// Compute the metadata digest.
    pub fn digest(&self) -> Point {
        self.table_info[..self.num_actual_columns]
            .iter()
            .fold(Point::NEUTRAL, |acc, info| acc + info.digest())
    }

    pub fn table_info(&self) -> &[ColumnInfo; MAX_COLUMNS] {
        &self.table_info
    }

    pub fn num_actual_columns(&self) -> usize {
        self.num_actual_columns
    }

    pub fn num_extracted_columns(&self) -> usize {
        self.num_extracted_columns
    }

    pub fn evm_word(&self) -> u32 {
        self.evm_word
    }

    pub(crate) fn build(b: &mut CBuilder) -> MetadataTarget<MAX_COLUMNS, MAX_FIELD_PER_EVM> {
        let table_info = array::from_fn(|_| b.add_virtual_column_info());
        let [is_actual_columns, is_extracted_columns] =
            array::from_fn(|_| array::from_fn(|_| b.add_virtual_bool_target_safe()));
        let evm_word = b.add_virtual_target();

        MetadataTarget {
            table_info,
            is_actual_columns,
            is_extracted_columns,
            evm_word,
        }
    }

    pub(crate) fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        metadata_target: &MetadataTarget<MAX_COLUMNS, MAX_FIELD_PER_EVM>,
    ) {
        pw.set_column_info_target_arr(&metadata_target.table_info, &self.table_info);
        metadata_target
            .is_actual_columns
            .iter()
            .enumerate()
            .for_each(|(i, t)| pw.set_bool_target(*t, i < self.num_actual_columns));
        metadata_target
            .is_extracted_columns
            .iter()
            .enumerate()
            .for_each(|(i, t)| pw.set_bool_target(*t, i < self.num_extracted_columns));
        pw.set_target(
            metadata_target.evm_word,
            F::from_canonical_u32(self.evm_word),
        );
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct MetadataTarget<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize> {
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    /// Information about all columns of the table
    pub(crate) table_info: [ColumnInfoTarget; MAX_COLUMNS],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    /// Boolean flags specifying whether the i-th column is actual or not
    pub(crate) is_actual_columns: [BoolTarget; MAX_COLUMNS],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    /// Boolean flags specifying whether the i-th field being processed has to be extracted into a column or not
    pub(crate) is_extracted_columns: [BoolTarget; MAX_COLUMNS],
    /// EVM word that should be the same for all columns we’re extracting here
    pub(crate) evm_word: Target,
}

impl<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>
    MetadataTarget<MAX_COLUMNS, MAX_FIELD_PER_EVM>
{
    /// Compute the metadata digest.
    pub(crate) fn digest(&self, b: &mut CBuilder, slot: Target) -> CurveTarget {
        let mut partial = b.curve_zero();
        let mut non_extracted_column_found = b._false();
        let mut num_extracted_columns = b.zero();

        for i in 0..MAX_COLUMNS {
            let info = &self.table_info[i];
            let is_actual = self.is_actual_columns[i];
            let is_extracted = self.is_extracted_columns[i];

            // If the current column has to be extracted, we check that:
            // - The EVM word associated to this column is the same as the EVM word we are extracting data from.
            // - The slot associated to this column is the same as the slot we are extracting data from.
            // if is_extracted:
            //      evm_word == info.evm_word && slot == info.slot
            let is_evm_word_eq = b.is_equal(self.evm_word, info.evm_word);
            let is_slot_eq = b.is_equal(slot, info.slot);
            let acc = [is_extracted, is_evm_word_eq, is_slot_eq]
                .into_iter()
                .reduce(|acc, flag| b.and(acc, flag))
                .unwrap();
            b.connect(acc.target, is_extracted.target);

            // Ensure that once we found a non-extracted column, then there are no
            // extracted columns left.
            // if non_extracted_column_found:
            //      is_extracted == false
            // => non_extracted_column_found == non_extracted_column_found * (1 - is_extracted)
            let acc = b.arithmetic(
                F::NEG_ONE,
                F::ONE,
                is_extracted.target,
                non_extracted_column_found.target,
                non_extracted_column_found.target,
            );
            b.connect(acc, non_extracted_column_found.target);

            // non_extracted_column_found |= not is_extracted
            // => non_extracted_column_found =
            //      non_extracted_column_found + (1 - is_extracted) -
            //      non_extracted_column_found * (1 - is_extracted)
            // => non_extracted_column_found =
            //      1 - is_extracted + non_extracted_column_found * is_extracted
            let acc = b.arithmetic(
                F::ONE,
                F::NEG_ONE,
                non_extracted_column_found.target,
                is_extracted.target,
                is_extracted.target,
            );
            let acc = b.add_const(acc, F::ONE);
            non_extracted_column_found = BoolTarget::new_unsafe(acc);
            // num_extracted_columns += is_extracted
            num_extracted_columns = b.add(num_extracted_columns, is_extracted.target);

            // Compute the partial digest of all columns.
            // mpt_metadata = H(info.slot || info.evm_word || info.byte_offset || info.bit_offset || info.length)
            let inputs = vec![
                info.slot,
                info.evm_word,
                info.byte_offset,
                info.bit_offset,
                info.length,
            ];
            let mpt_metadata = b.hash_n_to_hash_no_pad::<CHasher>(inputs);
            // mpt_digest = D(mpt_metadata || info.identifier)
            let inputs = mpt_metadata
                .elements
                .into_iter()
                .chain(once(info.identifier))
                .collect_vec();
            let mpt_digest = b.map_to_curve_point(&inputs);
            // acc = partial + mpt_digest
            let acc = b.add_curve_point(&[partial, mpt_digest]);
            // partial = is_actual ? acc : partial
            partial = b.curve_select(is_actual, acc, partial);
        }

        // num_extracted_columns <= MAX_FIELD_PER_EVM
        let max_field_per_evm = b.constant(F::from_canonical_usize(MAX_FIELD_PER_EVM));
        let num_extracted_lt_or_eq_max =
            less_than_or_equal_to_unsafe(b, num_extracted_columns, max_field_per_evm, 8);
        b.assert_one(num_extracted_lt_or_eq_max.target);

        partial
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tests::{TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM};
    use mp2_common::{C, D};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2_ecgfp5::gadgets::curve::PartialWitnessCurve;

    #[derive(Clone, Debug)]
    struct TestMedataCircuit {
        metadata_gadget: MetadataGadget<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>,
        slot: u8,
        expected_metadata_digest: Point,
    }

    impl UserCircuit<F, D> for TestMedataCircuit {
        // Metadata target + slot + expected metadata digest
        type Wires = (
            MetadataTarget<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>,
            Target,
            CurveTarget,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let metadata_target = MetadataGadget::build(b);
            let slot = b.add_virtual_target();
            let expected_metadata_digest = b.add_virtual_curve_target();

            let metadata_digest = metadata_target.digest(b, slot);
            b.connect_curve_points(metadata_digest, expected_metadata_digest);

            (metadata_target, slot, expected_metadata_digest)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.metadata_gadget.assign(pw, &wires.0);
            pw.set_target(wires.1, F::from_canonical_u8(self.slot));
            pw.set_curve_target(wires.2, self.expected_metadata_digest.to_weierstrass());
        }
    }

    #[test]
    fn test_values_extraction_metadata_gadget() {
        let rng = &mut thread_rng();

        let slot = rng.gen();
        let evm_word = rng.gen();

        let metadata_gadget = MetadataGadget::sample(slot, evm_word);
        let expected_metadata_digest = metadata_gadget.digest();

        let test_circuit = TestMedataCircuit {
            metadata_gadget,
            slot,
            expected_metadata_digest,
        };

        let _ = run_circuit::<F, D, C, _>(test_circuit);
    }
}
