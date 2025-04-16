use super::secondary_index_cell::{SecondaryIndexCell, SecondaryIndexCellWire};
use crate::cells_tree;
use derive_more::{From, Into};
use mp2_common::{
    default_config, group_hashing::CircuitBuilderGroupHashing, poseidon::H, proof::ProofWithVK,
    public_inputs::PublicInputCommon, u256::CircuitBuilderU256, utils::ToTargets, C, D, F,
};
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::{circuit_builder::CircuitBuilder, proof::ProofWithPublicInputsTarget},
};
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    framework::{
        RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
};
use serde::{Deserialize, Serialize};
use std::{array::from_fn as create_array, iter::once};

use super::public_inputs::PublicInputs;
// Arity not strictly needed now but may be an easy way to increase performance
// easily down the line with less recursion. Best to provide code which is easily
// amenable to a different arity rather than hardcoding binary tree only
#[derive(Clone, Debug, From, Into, Serialize, Deserialize)]
pub struct FullNodeCircuit(SecondaryIndexCell);

#[derive(Clone, Serialize, Deserialize, From, Into)]
pub(crate) struct FullNodeWires(SecondaryIndexCellWire);

impl FullNodeCircuit {
    pub(crate) fn build(
        b: &mut CircuitBuilder<F, D>,
        left_pi: &[Target],
        right_pi: &[Target],
        cells_pi: &[Target],
    ) -> FullNodeWires {
        let min_child = PublicInputs::from_slice(left_pi);
        let max_child = PublicInputs::from_slice(right_pi);
        let cells_pi = cells_tree::PublicInputs::from_slice(cells_pi);
        let secondary_index_cell = SecondaryIndexCellWire::new(b);
        let id = secondary_index_cell.identifier();
        let value = secondary_index_cell.value();
        let digest = secondary_index_cell.digest(b, &cells_pi);

        // Check multiplier_vd and multiplier_counter are the same as children proofs.
        // assert multiplier_vd == p1.multiplier_vd == p2.multiplier_vd
        b.connect_curve_points(digest.multiplier_vd, min_child.multiplier_digest_target());
        b.connect_curve_points(digest.multiplier_vd, max_child.multiplier_digest_target());
        // assert multiplier_counter == p1.multiplier_counter == p2.multiplier_counter
        b.connect(digest.multiplier_cnt, min_child.multiplier_counter_target());
        b.connect(digest.multiplier_cnt, max_child.multiplier_counter_target());

        let node_min = min_child.min_value_target();
        let node_max = max_child.max_value_target();
        // enforcing BST property
        let _true = b._true();
        let left_comparison = b.is_less_or_equal_than_u256(&min_child.max_value_target(), value);
        let right_comparison = b.is_less_or_equal_than_u256(value, &max_child.min_value_target());
        b.connect(left_comparison.target, _true.target);
        b.connect(right_comparison.target, _true.target);

        // Poseidon(p1.H || p2.H || node_min || node_max || index_id || index_value ||p.H)) as H
        let inputs = min_child
            .root_hash_target()
            .iter()
            .chain(max_child.root_hash_target().iter())
            .chain(node_min.to_targets().iter())
            .chain(node_max.to_targets().iter())
            .chain(once(&id))
            .chain(value.to_targets().iter())
            .chain(cells_pi.node_hash_target().iter())
            .cloned()
            .collect::<Vec<_>>();
        let hash = b.hash_n_to_hash_no_pad::<H>(inputs);

        let individual_vd = b.add_curve_point(&[
            digest.individual_vd,
            min_child.individual_digest_target(),
            max_child.individual_digest_target(),
        ]);

        PublicInputs::new(
            &hash.to_targets(),
            &individual_vd.to_targets(),
            &digest.multiplier_vd.to_targets(),
            &node_min.to_targets(),
            &node_max.to_targets(),
            &digest.multiplier_cnt,
        )
        .register(b);
        FullNodeWires(secondary_index_cell)
    }
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &FullNodeWires) {
        self.0.assign(pw, &wires.0);
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct RecursiveFullWires {
    cells_verifier: RecursiveCircuitsVerifierTarget<D>,
    full_wires: FullNodeWires,
}

#[derive(Clone, Debug)]
pub(crate) struct RecursiveFullInput {
    pub(crate) witness: FullNodeCircuit,
    pub(crate) cells_proof: ProofWithVK,
    pub(crate) cells_set: RecursiveCircuits<F, C, D>,
}

pub(crate) const NUM_CHILDREN: usize = 2;
impl CircuitLogicWires<F, D, NUM_CHILDREN> for RecursiveFullWires {
    type CircuitBuilderParams = RecursiveCircuits<F, C, D>;

    type Inputs = RecursiveFullInput;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<Target>::total_len();

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; NUM_CHILDREN],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        const CELLS_IO: usize = cells_tree::PublicInputs::<Target>::total_len();
        let verifier_gadget = RecursiveCircuitsVerifierGagdet::<F, C, D, CELLS_IO>::new(
            default_config(),
            &builder_parameters,
        );
        let cells_verifier_gadget = verifier_gadget.verify_proof_in_circuit_set(builder);
        let cells_pi = cells_verifier_gadget.get_public_input_targets::<F, CELLS_IO>();
        let children_pi: [&[Target]; 2] =
            create_array(|i| Self::public_input_targets(verified_proofs[i]));
        RecursiveFullWires {
            // run the row leaf circuit just with the public inputs of the cells proof
            full_wires: FullNodeCircuit::build(builder, children_pi[0], children_pi[1], cells_pi),
            cells_verifier: cells_verifier_gadget,
        }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.witness.assign(pw, &self.full_wires);
        let (proof, vd) = inputs.cells_proof.into();
        self.cells_verifier
            .set_target(pw, &inputs.cells_set, &proof, &vd)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use alloy::primitives::U256;
    use itertools::Itertools;
    use mp2_common::{group_hashing::weierstrass_to_point, utils::ToFields, C, D, F};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{field::types::PrimeField64, iop::witness::WitnessWrite, plonk::config::Hasher};

    #[derive(Clone, Debug)]
    struct TestFullNodeCircuit {
        circuit: FullNodeCircuit,
        left_pi: Vec<F>,
        right_pi: Vec<F>,
        cells_pi: Vec<F>,
    }

    impl UserCircuit<F, D> for TestFullNodeCircuit {
        type Wires = (FullNodeWires, Vec<Target>, Vec<Target>, Vec<Target>);

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let cells_pi = c.add_virtual_targets(cells_tree::PublicInputs::<Target>::total_len());
            let left_pi = c.add_virtual_targets(PublicInputs::<Target>::total_len());
            let right_pi = c.add_virtual_targets(PublicInputs::<Target>::total_len());
            (
                FullNodeCircuit::build(c, &left_pi, &right_pi, &cells_pi),
                left_pi,
                right_pi,
                cells_pi,
            )
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.circuit.assign(pw, &wires.0);
            pw.set_target_arr(&wires.1, &self.left_pi);
            pw.set_target_arr(&wires.2, &self.right_pi);
            pw.set_target_arr(&wires.3, &self.cells_pi);
        }
    }

    fn test_row_tree_full_circuit(is_multiplier: bool, cells_multiplier: bool) {
        let mut row = SecondaryIndexCell::sample(is_multiplier);
        row.cell.value = U256::from(18);
        let id = row.cell.identifier;
        let value = row.cell.value;
        let cells_pi = cells_tree::PublicInputs::sample(cells_multiplier);
        // Compute the row digest.
        let row_digest = row.digest(&cells_tree::PublicInputs::from_slice(&cells_pi));
        let node_circuit = FullNodeCircuit::from(row.clone());
        let (left_min, left_max) = (10, 15);
        // this should work since we allow multipleicities of indexes in the row tree
        let (right_min, right_max) = (18, 30);
        let multiplier_cnt = row_digest.multiplier_cnt.to_canonical_u64();
        let left_pi =
            PublicInputs::sample(row_digest.multiplier_vd, left_min, left_max, multiplier_cnt);
        let right_pi = PublicInputs::sample(
            row_digest.multiplier_vd,
            right_min,
            right_max,
            multiplier_cnt,
        );
        let test_circuit = TestFullNodeCircuit {
            circuit: node_circuit,
            left_pi: left_pi.clone(),
            right_pi: right_pi.clone(),
            cells_pi: cells_pi.clone(),
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        let left_pi = PublicInputs::from_slice(&left_pi);
        let right_pi = PublicInputs::from_slice(&right_pi);
        let cells_pi = cells_tree::PublicInputs::from_slice(&cells_pi);

        // Check root hash
        {
            // Poseidon(p1.H || p2.H || node_min || node_max || index_id || index_value ||p.H)) as H
            let inputs = left_pi
                .root_hash()
                .to_fields()
                .into_iter()
                .chain(right_pi.root_hash().to_fields())
                .chain(left_pi.min_value().to_fields())
                .chain(right_pi.max_value().to_fields())
                .chain(once(id))
                .chain(value.to_fields())
                .chain(cells_pi.node_hash().to_fields())
                .collect_vec();
            let hash = H::hash_no_pad(&inputs);
            assert_eq!(hash, pi.root_hash());
        }
        // Check individual digest
        assert_eq!(
            pi.individual_digest_point(),
            (row_digest.individual_vd
                + weierstrass_to_point(&left_pi.individual_digest_point())
                + weierstrass_to_point(&right_pi.individual_digest_point()))
            .to_weierstrass()
        );
        // Check multiplier digest
        assert_eq!(
            pi.multiplier_digest_point(),
            row_digest.multiplier_vd.to_weierstrass()
        );
        // Check minimum value
        assert_eq!(pi.min_value(), U256::from(left_min));
        // Check maximum value
        assert_eq!(pi.max_value(), U256::from(right_max));
        // Check multiplier counter
        assert_eq!(pi.multiplier_counter(), row_digest.multiplier_cnt);
    }

    #[test]
    fn row_tree_full() {
        test_row_tree_full_circuit(false, false);
    }

    #[test]
    fn row_tree_full_node_multiplier() {
        test_row_tree_full_circuit(true, false);
    }

    #[test]
    fn row_tree_full_cells_multiplier() {
        test_row_tree_full_circuit(false, true);
    }

    #[test]
    fn row_tree_full_all_multipliers() {
        test_row_tree_full_circuit(true, true);
    }
}
