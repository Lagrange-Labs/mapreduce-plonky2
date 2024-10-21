//! Row information for the rows tree

use crate::cells_tree::{Cell, CellWire, PublicInputs};
use derive_more::Constructor;
use mp2_common::{
    poseidon::{empty_poseidon_hash, hash_to_int_target, H, HASH_TO_INT_LEN},
    serialization::{deserialize, serialize},
    types::CBuilder,
    u256::UInt256Target,
    utils::ToTargets,
    F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
};
use plonky2_ecdsa::gadgets::{biguint::BigUintTarget, nonnative::CircuitBuilderNonNative};
use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget};
use serde::{Deserialize, Serialize};

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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RowWire {
    pub(crate) cell: CellWire,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub(crate) row_unique_data: HashOutTarget,
}

/// Row digest result
#[derive(Clone, Debug)]
pub(crate) struct RowDigest {
    pub(crate) is_merge: BoolTarget,
    pub(crate) row_id_multiplier: BigUintTarget,
    pub(crate) individual_vd: CurveTarget,
    pub(crate) multiplier_vd: CurveTarget,
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

    pub(crate) fn digest(&self, b: &mut CBuilder, cells_pi: &PublicInputs<Target>) -> RowDigest {
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

        let is_merge = values_digests.is_merge_case(b);
        let multiplier_vd = values_digests.multiplier;

        RowDigest {
            is_merge,
            row_id_multiplier,
            individual_vd,
            multiplier_vd,
        }
    }
}

/*
#[cfg(test)]
mod test {
}
*/
