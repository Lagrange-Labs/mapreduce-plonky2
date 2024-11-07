//! Module handling the intermediate node with 2 children inside a cells tree

use super::{public_inputs::PublicInputs, Cell, CellWire};
use anyhow::Result;
use derive_more::{From, Into};
use mp2_common::{
    poseidon::H, public_inputs::PublicInputCommon, types::CBuilder, utils::ToTargets, D, F,
};
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::proof::ProofWithPublicInputsTarget,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::{array, iter::once};

#[derive(Clone, Debug, Serialize, Deserialize, Into, From)]
pub struct FullNodeWires(CellWire);

#[derive(Clone, Debug, Serialize, Deserialize, From, Into)]
pub struct FullNodeCircuit(Cell);

impl FullNodeCircuit {
    pub fn build(b: &mut CBuilder, child_proofs: [PublicInputs<Target>; 2]) -> FullNodeWires {
        let [p1, p2] = child_proofs;

        let cell = CellWire::new(b);
        let values_digests =
            cell.split_and_accumulate_values_digest(b, &p1.split_values_digest_target());
        let values_digests = values_digests.accumulate(b, &p2.split_values_digest_target());

        let is_individual = cell.is_individual(b);
        let individual_cnt = b.add_many([
            is_individual.target,
            p1.individual_counter_target(),
            p2.individual_counter_target(),
        ]);
        let multiplier_cnt = b.add_many([
            cell.is_multiplier().target,
            p1.multiplier_counter_target(),
            p2.multiplier_counter_target(),
        ]);

        // H(p1.H || p2.H || identifier || value)
        let inputs = p1
            .node_hash_target()
            .into_iter()
            .chain(p2.node_hash_target())
            .chain(once(cell.identifier))
            .chain(cell.value.to_targets())
            .collect();
        let h = b.hash_n_to_hash_no_pad::<H>(inputs);

        // Register the public inputs.
        PublicInputs::new(
            &h.to_targets(),
            &values_digests.individual.to_targets(),
            &values_digests.multiplier.to_targets(),
            &individual_cnt,
            &multiplier_cnt,
        )
        .register(b);

        cell.into()
    }

    /// Assign the wires.
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &FullNodeWires) {
        self.0.assign(pw, &wires.0);
    }
}

/// Num of children = 2
impl CircuitLogicWires<F, D, 2> for FullNodeWires {
    type CircuitBuilderParams = ();

    type Inputs = FullNodeCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::total_len();

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; 2],
        _: Self::CircuitBuilderParams,
    ) -> Self {
        let child_proofs: [PublicInputs<Target>; 2] =
            array::from_fn(|i| PublicInputs::from_slice(&verified_proofs[i].public_inputs));
        FullNodeCircuit::build(builder, child_proofs)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use mp2_common::{poseidon::H, utils::ToFields, C};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{field::types::Field, iop::witness::WitnessWrite, plonk::config::Hasher};

    #[derive(Clone, Debug)]
    struct TestFullNodeCircuit<'a> {
        c: FullNodeCircuit,
        child_pis: &'a [Vec<F>; 2],
    }

    impl UserCircuit<F, D> for TestFullNodeCircuit<'_> {
        // Full node wires + child public inputs
        type Wires = (FullNodeWires, [Vec<Target>; 2]);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let child_pis =
                [0; 2].map(|_| b.add_virtual_targets(PublicInputs::<Target>::total_len()));

            let wires = FullNodeCircuit::build(
                b,
                array::from_fn(|i| PublicInputs::from_slice(&child_pis[i])),
            );

            (wires, child_pis)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);

            assert_eq!(self.child_pis.len(), wires.1.len());
            for i in 0..2 {
                pw.set_target_arr(&wires.1[i], &self.child_pis[i]);
            }
        }
    }

    #[test]
    fn test_cells_tree_full_node_individual() {
        [true, false]
            .into_iter()
            .cartesian_product([true, false])
            .for_each(|(is_left_child_multiplier, is_right_child_multiplier)| {
                test_cells_tree_full_multiplier(
                    false,
                    is_left_child_multiplier,
                    is_right_child_multiplier,
                );
            });
    }

    #[test]
    fn test_cells_tree_full_node_multiplier() {
        [true, false]
            .into_iter()
            .cartesian_product([true, false])
            .for_each(|(is_left_child_multiplier, is_right_child_multiplier)| {
                test_cells_tree_full_multiplier(
                    true,
                    is_left_child_multiplier,
                    is_right_child_multiplier,
                );
            });
    }

    fn test_cells_tree_full_multiplier(
        is_multiplier: bool,
        is_left_child_multiplier: bool,
        is_right_child_multiplier: bool,
    ) {
        let cell = Cell::sample(is_multiplier);
        let id = cell.identifier;
        let value = cell.value;
        let values_digests = cell.split_values_digest();

        let child_pis = &[
            PublicInputs::<F>::sample(is_left_child_multiplier),
            PublicInputs::<F>::sample(is_right_child_multiplier),
        ];

        let test_circuit = TestFullNodeCircuit {
            c: cell.into(),
            child_pis,
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);

        let child_pis = child_pis
            .iter()
            .map(|pi| PublicInputs::from_slice(pi))
            .collect_vec();

        let values_digests = child_pis.iter().fold(values_digests, |acc, pi| {
            acc.accumulate(&pi.split_values_digest_point())
        });

        // Check the node hash
        {
            let inputs = child_pis[0]
                .node_hash()
                .to_fields()
                .into_iter()
                .chain(child_pis[1].node_hash().to_fields())
                .chain(once(id))
                .chain(value.to_fields())
                .collect_vec();
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.h, exp_hash.elements);
        }
        // Check individual values digest
        assert_eq!(
            pi.individual_values_digest_point(),
            values_digests.individual.to_weierstrass(),
        );
        // Check multiplier values digest
        assert_eq!(
            pi.multiplier_values_digest_point(),
            values_digests.multiplier.to_weierstrass(),
        );
        // Check individual counter
        let multiplier_cnt = F::from_bool(is_multiplier);
        assert_eq!(
            pi.individual_counter(),
            child_pis.iter().fold(F::ONE - multiplier_cnt, |acc, pi| acc
                + pi.individual_counter()),
        );
        // Check multiplier counter
        assert_eq!(
            pi.multiplier_counter(),
            child_pis
                .iter()
                .fold(multiplier_cnt, |acc, pi| acc + pi.multiplier_counter()),
        );
    }
}
