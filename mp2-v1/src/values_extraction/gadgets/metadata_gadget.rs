//! The metadata gadget is used to ensure the correct extraction from the set of all identifiers.

use super::column_info::ColumnInfoTarget;
use itertools::Itertools;
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing, types::CBuilder,
    utils::less_than_or_equal_to_unsafe, CHasher, F,
};
use plonky2::{
    field::types::Field,
    iop::target::{BoolTarget, Target},
};
use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget};
use std::iter::once;

#[derive(Debug)]
pub(crate) struct MetadataGadget<'a, const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize> {
    /// Information about all columns of the table
    table_info: &'a [ColumnInfoTarget; MAX_COLUMNS],
    /// Boolean flags specifying whether the i-th column is actual or not
    is_actual_columns: &'a [BoolTarget; MAX_COLUMNS],
    /// Boolean flags specifying whether the i-th field being processed has to be extracted into a column or not
    is_extracted_columns: &'a [BoolTarget; MAX_COLUMNS],
    /// EVM word that should be the same for all columns we’re extracting here
    evm_word: Target,
    /// Slot of the variable from which the columns we are extracting here belongs to
    slot: Target,
}

impl<'a, const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>
    MetadataGadget<'a, MAX_COLUMNS, MAX_FIELD_PER_EVM>
{
    pub(crate) fn new(
        table_info: &'a [ColumnInfoTarget; MAX_COLUMNS],
        is_actual_columns: &'a [BoolTarget; MAX_COLUMNS],
        is_extracted_columns: &'a [BoolTarget; MAX_COLUMNS],
        evm_word: Target,
        slot: Target,
    ) -> Self {
        Self {
            table_info,
            is_actual_columns,
            is_extracted_columns,
            evm_word,
            slot,
        }
    }

    /// Build the metadata and retturn the partial digest which is computed from
    /// all the indices and identifiers of the table.
    pub(crate) fn build(&self, b: &mut CBuilder) -> CurveTarget {
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
            let is_slot_eq = b.is_equal(self.slot, info.slot);
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
