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

#[cfg(test)]
mod tests {
    use super::{
        super::column_info::{ColumnInfo, ColumnInfoTarget},
        *,
    };
    use crate::{
        values_extraction::gadgets::column_info::{
            CircuitBuilderColumnInfo, WitnessWriteColumnInfo,
        },
        DEFAULT_MAX_COLUMNS, DEFAULT_MAX_FIELD_PER_EVM,
    };
    use mp2_common::{group_hashing::map_to_curve_point, poseidon::H, C, D};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::config::Hasher,
    };
    use plonky2_ecgfp5::{curve::curve::Point, gadgets::curve::PartialWitnessCurve};
    use rand::{thread_rng, Rng};
    use std::array;

    #[derive(Clone, Debug)]
    struct MetadataGadgetData<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize> {
        table_info: [ColumnInfo; MAX_COLUMNS],
        num_actual_columns: usize,
        num_extracted_columns: usize,
        evm_word: u32,
        slot: u8,
    }

    impl<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>
        MetadataGadgetData<MAX_COLUMNS, MAX_FIELD_PER_EVM>
    {
        fn sample() -> Self {
            let rng = &mut thread_rng();

            let mut table_info = array::from_fn(|_| ColumnInfo::sample());
            let num_actual_columns = rng.gen_range(1..=MAX_COLUMNS);
            let max_extracted_columns = num_actual_columns.min(MAX_FIELD_PER_EVM);
            let num_extracted_columns = rng.gen_range(1..=max_extracted_columns);
            let evm_word = rng.gen();
            let slot = rng.gen();

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
                slot,
            }
        }

        fn digest(&self) -> Point {
            self.table_info[..self.num_actual_columns]
                .iter()
                .fold(Point::NEUTRAL, |acc, info| {
                    // metadata = H(info.slot || info.evm_word || info.byte_offset || info.bit_offset || info.length)
                    let inputs = vec![
                        info.slot,
                        info.evm_word,
                        info.byte_offset,
                        info.bit_offset,
                        info.length,
                    ];
                    let metadata = H::hash_no_pad(&inputs);
                    // digest = D(mpt_metadata || info.identifier)
                    let inputs = metadata
                        .elements
                        .into_iter()
                        .chain(once(info.identifier))
                        .collect_vec();
                    let digest = map_to_curve_point(&inputs);

                    acc + digest
                })
        }
    }

    #[derive(Clone, Debug)]
    struct MetadataGadgetTarget<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize> {
        table_info: [ColumnInfoTarget; MAX_COLUMNS],
        is_actual_columns: [BoolTarget; MAX_COLUMNS],
        is_extracted_columns: [BoolTarget; MAX_COLUMNS],
        evm_word: Target,
        slot: Target,
    }

    impl<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>
        MetadataGadgetTarget<MAX_COLUMNS, MAX_FIELD_PER_EVM>
    {
        fn metadata_gadget(&self) -> MetadataGadget<MAX_COLUMNS, MAX_FIELD_PER_EVM> {
            MetadataGadget::new(
                &self.table_info,
                &self.is_actual_columns,
                &self.is_extracted_columns,
                self.evm_word,
                self.slot,
            )
        }
    }

    pub trait CircuitBuilderMetadataGadget {
        /// Add a virtual metadata gadget target.
        fn add_virtual_metadata_gadget_target(
            &mut self,
        ) -> MetadataGadgetTarget<DEFAULT_MAX_COLUMNS, DEFAULT_MAX_FIELD_PER_EVM>;
    }

    impl CircuitBuilderMetadataGadget for CBuilder {
        fn add_virtual_metadata_gadget_target(
            &mut self,
        ) -> MetadataGadgetTarget<DEFAULT_MAX_COLUMNS, DEFAULT_MAX_FIELD_PER_EVM> {
            let table_info = array::from_fn(|_| self.add_virtual_column_info());
            let [is_actual_columns, is_extracted_columns] =
                array::from_fn(|_| array::from_fn(|_| self.add_virtual_bool_target_safe()));
            let [evm_word, slot] = array::from_fn(|_| self.add_virtual_target());

            MetadataGadgetTarget {
                table_info,
                is_actual_columns,
                is_extracted_columns,
                evm_word,
                slot,
            }
        }
    }

    pub trait WitnessWriteMetadataGadget {
        fn set_metadata_gadget_target(
            &mut self,
            target: &MetadataGadgetTarget<DEFAULT_MAX_COLUMNS, DEFAULT_MAX_FIELD_PER_EVM>,
            value: &MetadataGadgetData<DEFAULT_MAX_COLUMNS, DEFAULT_MAX_FIELD_PER_EVM>,
        );
    }

    impl<T: WitnessWrite<F>> WitnessWriteMetadataGadget for T {
        fn set_metadata_gadget_target(
            &mut self,
            target: &MetadataGadgetTarget<DEFAULT_MAX_COLUMNS, DEFAULT_MAX_FIELD_PER_EVM>,
            data: &MetadataGadgetData<DEFAULT_MAX_COLUMNS, DEFAULT_MAX_FIELD_PER_EVM>,
        ) {
            self.set_column_info_target_arr(&target.table_info, &data.table_info);
            target
                .is_actual_columns
                .iter()
                .enumerate()
                .for_each(|(i, t)| self.set_bool_target(*t, i < data.num_actual_columns));
            target
                .is_extracted_columns
                .iter()
                .enumerate()
                .for_each(|(i, t)| self.set_bool_target(*t, i < data.num_extracted_columns));
            [
                (target.evm_word, F::from_canonical_u32(data.evm_word)),
                (target.slot, F::from_canonical_u8(data.slot)),
            ]
            .into_iter()
            .for_each(|(t, v)| self.set_target(t, v));
        }
    }

    #[derive(Clone, Debug)]
    struct TestMedataGadgetCircuit {
        metadata_gadget_data: MetadataGadgetData<DEFAULT_MAX_COLUMNS, DEFAULT_MAX_FIELD_PER_EVM>,
        expected_metadata_digest: Point,
    }

    impl UserCircuit<F, D> for TestMedataGadgetCircuit {
        // Metadata gadget target + expected metadata digest
        type Wires = (
            MetadataGadgetTarget<DEFAULT_MAX_COLUMNS, DEFAULT_MAX_FIELD_PER_EVM>,
            CurveTarget,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let metadata_gadget_target = b.add_virtual_metadata_gadget_target();
            let expected_metadata_digest = b.add_virtual_curve_target();

            let metadata_digest = metadata_gadget_target.metadata_gadget().build(b);
            b.curve_eq(metadata_digest, expected_metadata_digest);

            (metadata_gadget_target, expected_metadata_digest)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_metadata_gadget_target(&wires.0, &self.metadata_gadget_data);
            pw.set_curve_target(wires.1, self.expected_metadata_digest.to_weierstrass());
        }
    }

    #[test]
    fn test_values_extraction_metadata_gadget() {
        let metadata_gadget_data = MetadataGadgetData::sample();
        let expected_metadata_digest = metadata_gadget_data.digest();

        let test_circuit = TestMedataGadgetCircuit {
            metadata_gadget_data,
            expected_metadata_digest,
        };

        let _ = run_circuit::<F, D, C, _>(test_circuit);
    }
}
