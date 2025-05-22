mod api;
mod empty_node;
mod full_node;
mod leaf;
mod partial_node;
mod public_inputs;

use crate::{CBuilder, F};
use alloy::primitives::U256;
pub use api::{build_circuits_params, extract_hash_from_proof, CircuitInput, PublicParameters};
use derive_more::Constructor;
use itertools::Itertools;
use mp2_common::{
    digest::{Digest, SplitDigestPoint, SplitDigestTarget},
    group_hashing::{map_to_curve_point, CircuitBuilderGroupHashing},
    serialization::{deserialize, serialize},
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{ToFields, ToTargets},
};
use serde::{Deserialize, Serialize};
use std::iter::once;

use plonky2::iop::{
    target::{BoolTarget, Target},
    witness::{PartialWitness, WitnessWrite},
};
use plonky2_ecgfp5::gadgets::curve::CurveTarget;
pub use public_inputs::PublicInputs;

/// A cell represents a column || value tuple. it can be given in the cells tree or as the
/// secondary index value in the row tree.
#[derive(Clone, Debug, Serialize, Deserialize, Constructor)]
pub struct Cell {
    /// identifier of the column for the secondary index
    pub(crate) identifier: F,
    /// secondary index value
    pub(crate) value: U256,
    /// is the secondary value should be included in multiplier digest or not
    pub(crate) is_multiplier: bool,
}

impl Cell {
    pub(crate) fn assign(&self, pw: &mut PartialWitness<F>, wires: &CellWire) {
        pw.set_u256_target(&wires.value, self.value);
        pw.set_target(wires.identifier, self.identifier);
        pw.set_bool_target(wires.is_multiplier, self.is_multiplier);
    }
    pub fn is_multiplier(&self) -> bool {
        self.is_multiplier
    }
    pub fn is_individual(&self) -> bool {
        !self.is_multiplier
    }
    pub fn split_values_digest(&self) -> SplitDigestPoint {
        let digest = self.values_digest();
        SplitDigestPoint::from_single_digest_point(digest, self.is_multiplier)
    }
    pub fn split_and_accumulate_values_digest(
        &self,
        child_digest: SplitDigestPoint,
    ) -> SplitDigestPoint {
        let split_digest = self.split_values_digest();
        split_digest.accumulate(&child_digest)
    }
    fn values_digest(&self) -> Digest {
        // D(identifier || pack_u32(value))
        let inputs = once(self.identifier)
            .chain(self.value.to_fields())
            .collect_vec();

        map_to_curve_point(&inputs)
    }
}

/// The basic wires generated for each circuit of the row tree
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CellWire {
    pub(crate) value: UInt256Target,
    pub(crate) identifier: Target,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub(crate) is_multiplier: BoolTarget,
}

impl CellWire {
    pub fn new(b: &mut CBuilder) -> Self {
        Self {
            value: b.add_virtual_u256(),
            identifier: b.add_virtual_target(),
            is_multiplier: b.add_virtual_bool_target_safe(),
        }
    }
    pub fn is_multiplier(&self) -> BoolTarget {
        self.is_multiplier
    }
    pub fn is_individual(&self, b: &mut CBuilder) -> BoolTarget {
        b.not(self.is_multiplier)
    }
    pub fn split_values_digest(&self, b: &mut CBuilder) -> SplitDigestTarget {
        let digest = self.values_digest(b);
        SplitDigestTarget::from_single_digest_target(b, digest, self.is_multiplier)
    }
    pub fn split_and_accumulate_values_digest(
        &self,
        b: &mut CBuilder,
        child_digest: &SplitDigestTarget,
    ) -> SplitDigestTarget {
        let split_digest = self.split_values_digest(b);
        split_digest.accumulate(b, child_digest)
    }
    fn values_digest(&self, b: &mut CBuilder) -> CurveTarget {
        // D(identifier || pack_u32(value))
        let inputs = once(self.identifier)
            .chain(self.value.to_targets())
            .collect_vec();

        b.map_to_curve_point(&inputs)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use mp2_common::{
        types::CURVE_TARGET_LEN,
        utils::{Fieldable, FromFields},
        C, D, F,
    };
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::field::types::Sample;
    use plonky2_ecgfp5::{
        curve::curve::Point,
        gadgets::curve::{CircuitBuilderEcGFp5, PartialWitnessCurve},
    };
    use rand::{thread_rng, Rng};
    use std::array;

    impl Cell {
        pub(crate) fn sample(is_multiplier: bool) -> Self {
            let rng = &mut thread_rng();

            let identifier = rng.gen::<u32>().to_field();
            let value = U256::from_limbs(rng.gen());

            Cell::new(identifier, value, is_multiplier)
        }
    }

    #[derive(Clone, Debug)]
    struct TestCellCircuit<'a> {
        cell: &'a Cell,
        child_values_digest: &'a SplitDigestPoint,
    }

    impl UserCircuit<F, D> for TestCellCircuit<'_> {
        // Cell wire + child values digest + child metadata digest
        type Wires = (CellWire, SplitDigestTarget);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let [values_individual, values_multiplier] =
                array::from_fn(|_| b.add_virtual_curve_target());

            let child_values_digest = SplitDigestTarget {
                individual: values_individual,
                multiplier: values_multiplier,
            };

            let cell = CellWire::new(b);
            let values_digest = cell.split_and_accumulate_values_digest(b, &child_values_digest);

            b.register_curve_public_input(values_digest.individual);
            b.register_curve_public_input(values_digest.multiplier);

            (cell, child_values_digest)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.cell.assign(pw, &wires.0);
            pw.set_curve_target(
                wires.1.individual,
                self.child_values_digest.individual.to_weierstrass(),
            );
            pw.set_curve_target(
                wires.1.multiplier,
                self.child_values_digest.multiplier.to_weierstrass(),
            );
        }
    }

    #[test]
    fn test_cells_tree_cell_circuit() {
        let rng = &mut thread_rng();

        let [values_individual, values_multiplier] = array::from_fn(|_| Point::sample(rng));
        let child_values_digest = &SplitDigestPoint {
            individual: values_individual,
            multiplier: values_multiplier,
        };

        let cell = &Cell::sample(rng.gen());
        let values_digests = cell.split_values_digest();
        let exp_values_digests = values_digests.accumulate(child_values_digest);

        let test_circuit = TestCellCircuit {
            cell,
            child_values_digest,
        };

        let proof = run_circuit::<F, D, C, _>(test_circuit);

        let [values_individual, values_multiplier] = array::from_fn(|i| {
            Point::from_fields(
                &proof.public_inputs[i * CURVE_TARGET_LEN..(i + 1) * CURVE_TARGET_LEN],
            )
        });

        assert_eq!(values_individual, exp_values_digests.individual);
        assert_eq!(values_multiplier, exp_values_digests.multiplier);
    }
}
