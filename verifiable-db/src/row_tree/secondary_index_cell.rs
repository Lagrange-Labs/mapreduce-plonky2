//! Row information for the rows tree

use crate::cells_tree::{Cell, CellWire, PublicInputs as CellsPublicInputs};
use derive_more::Constructor;
use itertools::Itertools;
use mp2_common::{
    poseidon::{hash_to_int_target, hash_to_int_value, H},
    serialization::{deserialize, serialize},
    types::{CBuilder, CURVE_TARGET_LEN},
    u256::UInt256Target,
    utils::{FromFields, ToFields, ToTargets},
    F,
};
use plonky2::{
    field::types::Field,
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::config::Hasher,
};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_ecgfp5::{
    curve::{curve::Point, scalar_field::Scalar},
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget},
};
use serde::{Deserialize, Serialize};
use std::iter::once;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RowDigest {
    pub(crate) multiplier_cnt: F,
    pub(crate) individual_vd: Point,
    pub(crate) multiplier_vd: Point,
}

impl FromFields<F> for RowDigest {
    fn from_fields(t: &[F]) -> Self {
        let mut pos = 0;

        let multiplier_cnt = t[0];
        pos += 1;

        let individual_vd = Point::from_fields(&t[pos..pos + CURVE_TARGET_LEN]);
        pos += CURVE_TARGET_LEN;

        let multiplier_vd = Point::from_fields(&t[pos..pos + CURVE_TARGET_LEN]);

        Self {
            multiplier_cnt,
            individual_vd,
            multiplier_vd,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RowDigestTarget {
    pub(crate) multiplier_cnt: Target,
    pub(crate) individual_vd: CurveTarget,
    pub(crate) multiplier_vd: CurveTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize, Constructor)]
pub(crate) struct SecondaryIndexCell {
    pub(crate) cell: Cell,
    pub(crate) row_unique_data: HashOut<F>,
}

impl SecondaryIndexCell {
    pub(crate) fn assign(&self, pw: &mut PartialWitness<F>, wires: &SecondaryIndexCellWire) {
        self.cell.assign(pw, &wires.cell);
        pw.set_hash_target(wires.row_unique_data, self.row_unique_data);
    }

    pub fn is_individual(&self) -> bool {
        self.cell.is_individual()
    }

    pub fn is_multiplier(&self) -> bool {
        self.cell.is_multiplier()
    }

    pub(crate) fn digest(&self, cells_pi: &CellsPublicInputs<F>) -> RowDigest {
        let values_digests = self
            .cell
            .split_and_accumulate_values_digest(cells_pi.split_values_digest_point());

        // individual_counter = p.individual_counter + is_individual
        let individual_cnt =
            cells_pi.individual_counter() + F::from_bool(self.cell.is_individual());

        // multiplier_counter = p.multiplier_counter + not is_individual
        let multiplier_cnt =
            cells_pi.multiplier_counter() + F::from_bool(self.cell.is_multiplier());

        // Compute row ID for individual cells:
        // row_id_individual = H2Int(row_unique_data || individual_counter)
        let inputs = self
            .row_unique_data
            .to_fields()
            .into_iter()
            .chain(once(individual_cnt))
            .collect_vec();
        let hash = H::hash_no_pad(&inputs);
        let row_id_individual = hash_to_int_value(hash);
        let row_id_individual = Scalar::from_noncanonical_biguint(row_id_individual);

        // Multiply row ID to individual value digest:
        // individual_vd = row_id_individual * individual_vd
        let individual_vd = values_digests.individual * row_id_individual;

        let multiplier_vd = values_digests.multiplier;

        RowDigest {
            multiplier_cnt,
            individual_vd,
            multiplier_vd,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SecondaryIndexCellWire {
    pub(crate) cell: CellWire,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub(crate) row_unique_data: HashOutTarget,
}

impl SecondaryIndexCellWire {
    pub(crate) fn new(b: &mut CBuilder) -> Self {
        Self {
            cell: CellWire::new(b),
            row_unique_data: b.add_virtual_hash(),
        }
    }

    pub(crate) fn identifier(&self) -> Target {
        self.cell.identifier
    }

    pub(crate) fn value(&self) -> &UInt256Target {
        &self.cell.value
    }

    pub(crate) fn digest(
        &self,
        b: &mut CBuilder,
        cells_pi: &CellsPublicInputs<Target>,
    ) -> RowDigestTarget {
        let values_digests = self
            .cell
            .split_and_accumulate_values_digest(b, &cells_pi.split_values_digest_target());

        // individual_counter = p.individual_counter + is_individual
        let is_individual = self.cell.is_individual(b);
        let individual_cnt = b.add(cells_pi.individual_counter_target(), is_individual.target);

        // multiplier_counter = p.multiplier_counter + not is_individual
        let is_multiplier = self.cell.is_multiplier();
        let multiplier_cnt = b.add(cells_pi.multiplier_counter_target(), is_multiplier.target);

        // Compute row ID for individual cells:
        // row_id_individual = H2Int(row_unique_data || individual_counter)
        let inputs = self
            .row_unique_data
            .to_targets()
            .into_iter()
            .chain(once(individual_cnt))
            .collect();
        let hash = b.hash_n_to_hash_no_pad::<H>(inputs);
        let row_id_individual = hash_to_int_target(b, hash);
        let row_id_individual = b.biguint_to_nonnative(&row_id_individual);

        // Multiply row ID to individual value digest:
        // individual_vd = row_id_individual * individual_vd
        let individual_vd = b.curve_scalar_mul(values_digests.individual, &row_id_individual);

        let multiplier_vd = values_digests.multiplier;

        RowDigestTarget {
            multiplier_cnt,
            individual_vd,
            multiplier_vd,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use mp2_common::{utils::FromFields, C, D, F};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::field::types::Sample;
    use rand::{thread_rng, Rng};

    impl SecondaryIndexCell {
        pub(crate) fn sample(is_multiplier: bool) -> Self {
            let cell = Cell::sample(is_multiplier);
            let row_unique_data = HashOut::rand();

            SecondaryIndexCell::new(cell, row_unique_data)
        }
    }

    #[derive(Clone, Debug)]
    struct TestRowCircuit<'a> {
        row: &'a SecondaryIndexCell,
        cells_pi: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestRowCircuit<'a> {
        // Row wire + cells PI
        type Wires = (SecondaryIndexCellWire, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let secondary_index_cell = SecondaryIndexCellWire::new(b);
            let cells_proof = b.add_virtual_targets(CellsPublicInputs::<Target>::total_len());
            let cells_pi = CellsPublicInputs::from_slice(&cells_proof);

            let digest = secondary_index_cell.digest(b, &cells_pi);

            b.register_public_inputs(&digest.multiplier_cnt.to_targets());
            b.register_public_inputs(&digest.individual_vd.to_targets());
            b.register_public_inputs(&digest.multiplier_vd.to_targets());

            (secondary_index_cell, cells_proof)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.row.assign(pw, &wires.0);
            pw.set_target_arr(&wires.1, self.cells_pi);
        }
    }

    #[test]
    fn test_rows_tree_row_circuit() {
        let rng = &mut thread_rng();

        let cells_pi = &CellsPublicInputs::sample(rng.gen());
        let secondary_index_cell = &SecondaryIndexCell::sample(rng.gen());
        let exp_row_digest = secondary_index_cell.digest(&CellsPublicInputs::from_slice(cells_pi));

        let test_circuit = TestRowCircuit {
            row: secondary_index_cell,
            cells_pi,
        };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let row_digest = RowDigest::from_fields(&proof.public_inputs);

        assert_eq!(row_digest, exp_row_digest);
    }
}
