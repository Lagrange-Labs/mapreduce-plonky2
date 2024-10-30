//! Row information for the rows tree

use crate::cells_tree::{Cell, CellWire, PublicInputs as CellsPublicInputs};
use derive_more::Constructor;
use itertools::Itertools;
use mp2_common::{
    poseidon::{empty_poseidon_hash, hash_to_int_target, hash_to_int_value, H, HASH_TO_INT_LEN},
    serialization::{deserialize, serialize},
    types::{CBuilder, CURVE_TARGET_LEN},
    u256::UInt256Target,
    utils::{FromFields, ToFields, ToTargets},
    F,
};
use num::BigUint;
use plonky2::{
    field::types::{Field, PrimeField64},
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::config::Hasher,
};
use plonky2_ecdsa::gadgets::{biguint::BigUintTarget, nonnative::CircuitBuilderNonNative};
use plonky2_ecgfp5::{
    curve::{curve::Point, scalar_field::Scalar},
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RowDigest {
    pub(crate) row_id_multiplier: BigUint,
    pub(crate) individual_vd: Point,
    pub(crate) multiplier_vd: Point,
}

impl FromFields<F> for RowDigest {
    fn from_fields(t: &[F]) -> Self {
        let mut pos = 0;

        let row_id_multiplier = BigUint::new(
            t[pos..pos + HASH_TO_INT_LEN]
                .iter()
                .map(|f| u32::try_from(f.to_canonical_u64()).unwrap())
                .collect_vec(),
        );
        pos += HASH_TO_INT_LEN;

        let individual_vd = Point::from_fields(&t[pos..pos + CURVE_TARGET_LEN]);
        pos += CURVE_TARGET_LEN;

        let multiplier_vd = Point::from_fields(&t[pos..pos + CURVE_TARGET_LEN]);

        Self {
            row_id_multiplier,
            individual_vd,
            multiplier_vd,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RowDigestTarget {
    pub(crate) row_id_multiplier: BigUintTarget,
    pub(crate) individual_vd: CurveTarget,
    pub(crate) multiplier_vd: CurveTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize, Constructor)]
pub(crate) struct Row {
    pub(crate) cell: Cell,
    pub(crate) row_unique_data: HashOut<F>,
}

impl Row {
    pub(crate) fn assign_wires(&self, pw: &mut PartialWitness<F>, wires: &RowWire) {
        self.cell.assign_wires(pw, &wires.cell);
        pw.set_hash_target(wires.row_unique_data, self.row_unique_data);
    }

    pub(crate) fn digest(&self, cells_pi: &CellsPublicInputs<F>) -> RowDigest {
        let metadata_digests = self.cell.split_metadata_digest();
        let values_digests = self.cell.split_values_digest();

        let metadata_digests = metadata_digests.accumulate(&cells_pi.split_metadata_digest_point());
        let values_digests = values_digests.accumulate(&cells_pi.split_values_digest_point());

        // Compute row ID for individual cells:
        // row_id_individual = H2Int(row_unique_data || individual_md)
        let inputs = self
            .row_unique_data
            .to_fields()
            .into_iter()
            .chain(metadata_digests.individual.to_fields())
            .collect_vec();
        let hash = H::hash_no_pad(&inputs);
        let row_id_individual = hash_to_int_value(hash);
        let row_id_individual = Scalar::from_noncanonical_biguint(row_id_individual);

        // Multiply row ID to individual value digest:
        // individual_vd = row_id_individual * individual_vd
        let individual_vd = values_digests.individual * row_id_individual;

        // Multiplier is always employed for set of scalar variables, and `row_unique_data`
        // for such a set is always `H("")``, so we can hardocode it in the circuit:
        // row_id_multiplier = H2Int(H("") || multiplier_md)
        let empty_hash = empty_poseidon_hash();
        let inputs = empty_hash
            .to_fields()
            .into_iter()
            .chain(metadata_digests.multiplier.to_fields())
            .collect_vec();
        let hash = H::hash_no_pad(&inputs);
        let row_id_multiplier = hash_to_int_value(hash);

        let multiplier_vd = values_digests.multiplier;

        RowDigest {
            row_id_multiplier,
            individual_vd,
            multiplier_vd,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RowWire {
    pub(crate) cell: CellWire,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub(crate) row_unique_data: HashOutTarget,
}

impl RowWire {
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
        let metadata_digests = self.cell.split_metadata_digest(b);
        let values_digests = self.cell.split_values_digest(b);

        let metadata_digests =
            metadata_digests.accumulate(b, &cells_pi.split_metadata_digest_target());
        let values_digests = values_digests.accumulate(b, &cells_pi.split_values_digest_target());

        // Compute row ID for individual cells:
        // row_id_individual = H2Int(row_unique_data || individual_md)
        let inputs = self
            .row_unique_data
            .to_targets()
            .into_iter()
            .chain(metadata_digests.individual.to_targets())
            .collect();
        let hash = b.hash_n_to_hash_no_pad::<H>(inputs);
        let row_id_individual = hash_to_int_target(b, hash);
        let row_id_individual = b.biguint_to_nonnative(&row_id_individual);

        // Multiply row ID to individual value digest:
        // individual_vd = row_id_individual * individual_vd
        let individual_vd = b.curve_scalar_mul(values_digests.individual, &row_id_individual);

        // Multiplier is always employed for set of scalar variables, and `row_unique_data`
        // for such a set is always `H("")``, so we can hardocode it in the circuit:
        // row_id_multiplier = H2Int(H("") || multiplier_md)
        let empty_hash = b.constant_hash(*empty_poseidon_hash());
        let inputs = empty_hash
            .to_targets()
            .into_iter()
            .chain(metadata_digests.multiplier.to_targets())
            .collect();
        let hash = b.hash_n_to_hash_no_pad::<H>(inputs);
        let row_id_multiplier = hash_to_int_target(b, hash);
        assert_eq!(row_id_multiplier.num_limbs(), HASH_TO_INT_LEN);

        let multiplier_vd = values_digests.multiplier;

        RowDigestTarget {
            row_id_multiplier,
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

    impl Row {
        pub(crate) fn sample(is_multiplier: bool) -> Self {
            let cell = Cell::sample(is_multiplier);
            let row_unique_data = HashOut::rand();

            Row::new(cell, row_unique_data)
        }
    }

    #[derive(Clone, Debug)]
    struct TestRowCircuit<'a> {
        row: &'a Row,
        cells_pi: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestRowCircuit<'a> {
        // Row wire + cells PI
        type Wires = (RowWire, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let row = RowWire::new(b);
            let cells_proof = b.add_virtual_targets(CellsPublicInputs::<Target>::total_len());
            let cells_pi = CellsPublicInputs::from_slice(&cells_proof);

            let digest = row.digest(b, &cells_pi);

            b.register_public_inputs(&digest.row_id_multiplier.to_targets());
            b.register_public_inputs(&digest.individual_vd.to_targets());
            b.register_public_inputs(&digest.multiplier_vd.to_targets());

            (row, cells_proof)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.row.assign_wires(pw, &wires.0);
            pw.set_target_arr(&wires.1, self.cells_pi);
        }
    }

    #[test]
    fn test_rows_tree_row_circuit() {
        let rng = &mut thread_rng();

        let cells_pi = &CellsPublicInputs::sample(rng.gen());
        let row = &Row::sample(rng.gen());
        let exp_row_digest = row.digest(&CellsPublicInputs::from_slice(cells_pi));

        let test_circuit = TestRowCircuit { row, cells_pi };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let row_digest = RowDigest::from_fields(&proof.public_inputs);

        assert_eq!(row_digest, exp_row_digest);
    }
}
