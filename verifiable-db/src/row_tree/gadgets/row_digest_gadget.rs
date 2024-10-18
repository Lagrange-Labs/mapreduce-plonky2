use crate::cells_tree::{self, CellWire};
use itertools::Itertools;
use mp2_common::{
    array::{Array, VectorWire},
    eth::left_pad32,
    group_hashing::{map_to_curve_point, CircuitBuilderGroupHashing},
    poseidon::{empty_poseidon_hash, hash_to_int_target, H, HASH_TO_INT_LEN},
    types::{CBuilder, MAPPING_LEAF_VALUE_LEN},
    utils::{Endianness, Packer, PackerTarget},
    F,
};
use plonky2::{
    field::types::{Field, PrimeField64},
    hash::hash_types::{HashOut, HashOutTarget},
    iop::target::{BoolTarget, Target},
};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_ecgfp5::{
    curve::curve::Point,
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget},
};
use rand::{thread_rng, Rng};
use std::{array, iter::once};

#[derive(Debug)]
pub(crate) struct RowDigestGadget<'a> {
    // - `p :`  - cells proof for the row associated to the current node (from `cells_build_set`)
    cells_pi: cells_tree::PublicInputs<'a, Target>,
    // - `is_individual : bool` - Flag specifying whether the secondary index cell should be accumulated in `individual` or `multiplier` digest
    is_multiplier: BoolTarget,
    // - `mpt_metadata : [4]F` - Hash of the metadata associated to the secondary index cell, as computed in MPT extraction circuits
    mpt_metadata: &'a HashOutTarget,
    // - `row_unique_data : Hash` : Row unique data employed to compute the row id for individual cells, the same one employed in MPT extraction circuits
    row_unique_data: &'a HashOutTarget,
    current_cell: &'a CellWire,
}

impl<'a> RowDigestGadget<'a> {
    pub(crate) fn new(
        cells_pi: cells_tree::PublicInputs<'a, Target>,
        is_multiplier: BoolTarget,
        mpt_metadata: &'a HashOutTarget,
        row_unique_data: &'a HashOutTarget,
        current_cell: &'a CellWire,
    ) -> Self {
        Self {
            cells_pi,
            is_multiplier,
            mpt_metadata,
            row_unique_data,
            current_cell,
        }
    }

    pub(crate) fn compute_row_digest(
        &self,
        b: &mut CBuilder,
    ) -> (CurveTarget, CurveTarget, [Target; HASH_TO_INT_LEN]) {
        let (individual_vd, multiplier_vd) =
            self.current_cell.individual_multiplier_values_digests(b);
        let (individual_md, multiplier_md) =
            self.current_cell.individual_multiplier_metadata_digests(b);

        let individual_vd = b.add_curve_point(&[
            individual_vd,
            self.cells_pi.individual_values_digest_target(),
        ]);
        let multiplier_vd = b.add_curve_point(&[
            multiplier_vd,
            self.cells_pi.multiplier_values_digest_target(),
        ]);
        let individual_md = b.add_curve_point(&[
            individual_md,
            self.cells_pi.individual_metadata_digest_target(),
        ]);
        let multiplier_md = b.add_curve_point(&[
            multiplier_md,
            self.cells_pi.multiplier_metadata_digest_target(),
        ]);

        // # compute row id for individual cells
        // row_id_individual = H2Int(row_unique_data || individual_md)
        let inputs = self
            .row_unique_data
            .to_targets()
            .into_iter()
            .chain(individual_md.to_targets())
            .collect();
        let hash = b.hash_n_to_hash_no_pad::<H>(inputs);
        let row_id_individual = hash_to_int_target(b, hash);
        let row_id_individual = b.biguint_to_nonnative(&row_id_individual);

        // # multiply row id to individual value digest
        // individual_vd = row_id_individual * individual_vd # scalar mul
        let individual_vd = b.curve_scalar_mul(individual_vd, &row_id_individual);

        // # multiplier is always employed for set of scalar variables, and the
        // # row_unique_data for such a set is always H(""), so we can hardocode it
        // # in the circuit
        // row_id_multiplier = H2Int(H("") || multiplier_md)
        let empty_hash = b.constant_hash(*empty_poseidon_hash());
        let inputs = empty_hash
            .to_targets()
            .into_iter()
            .chain(multiplier_md.to_targets())
            .collect();
        let hash = b.hash_n_to_hash_no_pad::<H>(inputs);
        let row_id_multiplier = hash_to_int_target(b, hash)
            .into_iter()
            .map(|u32_target| u32_target.0)
            .collect();

        (individual_vd, multiplier_md, row_id_multiplier)
    }
}

/*
#[cfg(test)]
pub(crate) mod tests {
    use super::{super::column_info::ColumnInfoTarget, *};
    use crate::{
        tests::TEST_MAX_FIELD_PER_EVM,
        values_extraction::gadgets::column_info::{
            CircuitBuilderColumnInfo, WitnessWriteColumnInfo,
        },
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
        ) -> ColumnGadgetTarget<TEST_MAX_FIELD_PER_EVM>;
    }

    impl CircuitBuilderColumnGadget for CBuilder {
        fn add_virtual_column_gadget_target(
            &mut self,
        ) -> ColumnGadgetTarget<TEST_MAX_FIELD_PER_EVM> {
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
            target: &ColumnGadgetTarget<TEST_MAX_FIELD_PER_EVM>,
            value: &ColumnGadgetData<TEST_MAX_FIELD_PER_EVM>,
        );
    }

    impl<T: WitnessWrite<F>> WitnessWriteColumnGadget for T {
        fn set_column_gadget_target(
            &mut self,
            target: &ColumnGadgetTarget<TEST_MAX_FIELD_PER_EVM>,
            data: &ColumnGadgetData<TEST_MAX_FIELD_PER_EVM>,
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
        column_gadget_data: ColumnGadgetData<TEST_MAX_FIELD_PER_EVM>,
        expected_column_digest: Point,
    }

    impl UserCircuit<F, D> for TestColumnGadgetCircuit {
        // Column gadget target + expected column digest
        type Wires = (ColumnGadgetTarget<TEST_MAX_FIELD_PER_EVM>, CurveTarget);

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
*/
