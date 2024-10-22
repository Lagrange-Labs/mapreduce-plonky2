//! Module handling the intermediate node with 1 child inside a cells tree

use super::{public_inputs::PublicInputs, Cell, CellWire};
use anyhow::Result;
use derive_more::{From, Into};
use mp2_common::{
    poseidon::{empty_poseidon_hash, H},
    public_inputs::PublicInputCommon,
    types::CBuilder,
    utils::ToTargets,
    D, F,
};
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::proof::ProofWithPublicInputsTarget,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::iter::once;

#[derive(Clone, Debug, Serialize, Deserialize, From, Into)]
pub struct PartialNodeWires(CellWire);

#[derive(Clone, Debug, Serialize, Deserialize, From, Into)]
pub struct PartialNodeCircuit(Cell);

impl PartialNodeCircuit {
    pub fn build(b: &mut CBuilder, p: PublicInputs<Target>) -> PartialNodeWires {
        let cell = CellWire::new(b);
        let metadata_digests = cell.split_metadata_digest(b);
        let values_digests = cell.split_values_digest(b);

        let metadata_digests = metadata_digests.accumulate(b, &p.split_metadata_digest_target());
        let values_digests = values_digests.accumulate(b, &p.split_values_digest_target());

        /*
        # since there is no sorting constraint among the nodes of this tree, to simplify
        # the circuits, when we build a node with only one child, we can always place
        # it as the left child
        # NOTE: this is true only if we the "block" tree
        h = H(p.H || H("") || identifier || value)
        */
        let empty_hash = b.constant_hash(*empty_poseidon_hash()).to_targets();
        let inputs = p
            .node_hash_target()
            .into_iter()
            .chain(empty_hash)
            .chain(once(cell.identifier))
            .chain(cell.value.to_targets())
            .collect();
        let h = b.hash_n_to_hash_no_pad::<H>(inputs);

        // Register the public inputs.
        PublicInputs::new(
            &h.to_targets(),
            &values_digests.individual.to_targets(),
            &values_digests.multiplier.to_targets(),
            &metadata_digests.individual.to_targets(),
            &metadata_digests.multiplier.to_targets(),
        )
        .register(b);

        cell.into()
    }

    /// Assign the wires.
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &PartialNodeWires) {
        self.0.assign_wires(pw, &wires.0);
    }
}

/// Num of children = 1
impl CircuitLogicWires<F, D, 1> for PartialNodeWires {
    type CircuitBuilderParams = ();

    type Inputs = PartialNodeCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::total_len();

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; 1],
        _: Self::CircuitBuilderParams,
    ) -> Self {
        let child_proof = PublicInputs::from_slice(&verified_proofs[0].public_inputs);
        PartialNodeCircuit::build(builder, child_proof)
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
    use plonky2::{iop::witness::WitnessWrite, plonk::config::Hasher};

    #[derive(Clone, Debug)]
    struct TestPartialNodeCircuit<'a> {
        c: PartialNodeCircuit,
        child_pi: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestPartialNodeCircuit<'a> {
        // Partial node wires + child public inputs
        type Wires = (PartialNodeWires, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let child_pi = b.add_virtual_targets(PublicInputs::<Target>::total_len());
            let wires = PartialNodeCircuit::build(b, PublicInputs::from_slice(&child_pi));

            (wires, child_pi)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);
            pw.set_target_arr(&wires.1, self.child_pi);
        }
    }

    #[test]
    fn test_cells_tree_partial_node_circuit() {
        test_cells_tree_partial_multiplier(true);
        test_cells_tree_partial_multiplier(false);
    }

    fn test_cells_tree_partial_multiplier(is_multiplier: bool) {
        let cell = Cell::sample(is_multiplier);
        let id = cell.identifier;
        let value = cell.value;
        let values_digests = cell.split_values_digest();
        let metadata_digests = cell.split_metadata_digest();

        let child_pi = &PublicInputs::<F>::sample(is_multiplier);

        let test_circuit = TestPartialNodeCircuit {
            c: cell.into(),
            child_pi,
        };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        let child_pi = PublicInputs::from_slice(child_pi);

        let values_digests = values_digests.accumulate(&child_pi.split_values_digest_point());
        let metadata_digests = metadata_digests.accumulate(&child_pi.split_metadata_digest_point());

        // Check the node hash
        {
            let empty_hash = empty_poseidon_hash();
            let inputs = child_pi
                .node_hash()
                .to_fields()
                .into_iter()
                .chain(empty_hash.elements)
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
        // Check individual metadata digest
        assert_eq!(
            pi.individual_metadata_digest_point(),
            metadata_digests.individual.to_weierstrass(),
        );
        // Check multiplier metadata digest
        assert_eq!(
            pi.multiplier_metadata_digest_point(),
            metadata_digests.multiplier.to_weierstrass(),
        );
    }
}
