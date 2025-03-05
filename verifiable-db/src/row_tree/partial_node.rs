use super::secondary_index_cell::{SecondaryIndexCell, SecondaryIndexCellWire};
use crate::cells_tree;
use mp2_common::{
    default_config,
    group_hashing::CircuitBuilderGroupHashing,
    hash::hash_maybe_first,
    poseidon::empty_poseidon_hash,
    proof::ProofWithVK,
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    u256::CircuitBuilderU256,
    utils::ToTargets,
    C, D, F,
};
use plonky2::{
    self,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, proof::ProofWithPublicInputsTarget},
};
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    framework::{
        RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
};
use serde::{Deserialize, Serialize};
use std::iter::once;

use super::public_inputs::PublicInputs;

#[derive(Clone, Debug)]
pub struct PartialNodeCircuit {
    pub(crate) row: SecondaryIndexCell,
    pub(crate) is_child_at_left: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PartialNodeWires {
    row: SecondaryIndexCellWire,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_child_at_left: BoolTarget,
}

impl PartialNodeCircuit {
    pub(crate) fn new(row: SecondaryIndexCell, is_child_at_left: bool) -> Self {
        Self {
            row,
            is_child_at_left,
        }
    }
    fn build(
        b: &mut CircuitBuilder<F, D>,
        child_pi: &[Target],
        cells_pi: &[Target],
    ) -> PartialNodeWires {
        let child_pi = PublicInputs::from_slice(child_pi);
        let cells_pi = cells_tree::PublicInputs::from_slice(cells_pi);
        let secondary_index_cell = SecondaryIndexCellWire::new(b);
        let id = secondary_index_cell.identifier();
        let value = secondary_index_cell.value();
        let digest = secondary_index_cell.digest(b, &cells_pi);

        // Check multiplier_vd and multiplier_counter are the same as children proof.
        // assert multiplier_vd == p.multiplier_vd
        b.connect_curve_points(digest.multiplier_vd, child_pi.multiplier_digest_target());
        // assert multiplier_counter == p.multiplier_counter
        b.connect(digest.multiplier_cnt, child_pi.multiplier_counter_target());

        // bool target range checked in poseidon gate
        let is_child_at_left = b.add_virtual_bool_target_unsafe();
        // max_left = left ? child_proof.max : index_value
        // min_right = left ? index_value : child_proof.min
        let max_left = b.select_u256(is_child_at_left, &child_pi.max_value_target(), value);
        let min_right = b.select_u256(is_child_at_left, value, &child_pi.min_value_target());
        let bst_enforced = b.is_less_or_equal_than_u256(&max_left, &min_right);
        let _true = b._true();
        b.connect(bst_enforced.target, _true.target);
        // node_min = left ? child_proof.min : index_value
        // node_max = left ? index_value : child_proof.max
        let node_min = b.select_u256(is_child_at_left, &child_pi.min_value_target(), value);
        let node_max = b.select_u256(is_child_at_left, value, &child_pi.max_value_target());

        let empty_hash = b.constant_hash(*empty_poseidon_hash());
        // left_hash = left ? child_proof.H : H("")
        // right_hash = left ? H("") : child_proof.H
        // Note this is equal to swap_if_condition_true(is_left, H(""),child_proof.H)
        // hence we can do the first with a single poseidon call
        // h = Poseidon(left_hash || right_hash || node_min || node_max || index_id || index_value || cells_proof.H)
        let rest = node_min
            .to_targets()
            .iter()
            .chain(node_max.to_targets().iter())
            .chain(once(&id))
            .chain(value.to_targets().iter())
            .chain(cells_pi.node_hash_target().iter())
            .cloned()
            .collect::<Vec<_>>();
        //  if child at left, then hash should be child_proof.H || H("") || rest
        //  if child at right, then hash should be H("") || child_proof.H || rest
        let node_hash = hash_maybe_first(
            b,
            is_child_at_left,
            empty_hash.elements,
            child_pi.root_hash_target(),
            &rest,
        );

        let individual_vd =
            b.add_curve_point(&[digest.individual_vd, child_pi.individual_digest_target()]);

        PublicInputs::new(
            &node_hash,
            &individual_vd.to_targets(),
            &digest.multiplier_vd.to_targets(),
            &node_min.to_targets(),
            &node_max.to_targets(),
            &digest.multiplier_cnt,
        )
        .register(b);
        PartialNodeWires {
            row: secondary_index_cell,
            is_child_at_left,
        }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &PartialNodeWires) {
        self.row.assign(pw, &wires.row);
        pw.set_bool_target(wires.is_child_at_left, self.is_child_at_left);
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct RecursivePartialWires {
    cells_verifier: RecursiveCircuitsVerifierTarget<D>,
    partial_wires: PartialNodeWires,
}

pub(crate) struct RecursivePartialInput {
    pub(crate) witness: PartialNodeCircuit,
    pub(crate) cells_proof: ProofWithVK,
    pub(crate) cells_set: RecursiveCircuits<F, C, D>,
}

pub(crate) const NUM_CHILDREN: usize = 1;
impl CircuitLogicWires<F, D, NUM_CHILDREN> for RecursivePartialWires {
    type CircuitBuilderParams = RecursiveCircuits<F, C, D>;

    type Inputs = RecursivePartialInput;

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
        let child_pi = Self::public_input_targets(verified_proofs[0]);
        RecursivePartialWires {
            // run the row leaf circuit just with the public inputs of the cells proof
            partial_wires: PartialNodeCircuit::build(builder, child_pi, cells_pi),
            cells_verifier: cells_verifier_gadget,
        }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.witness.assign(pw, &self.partial_wires);
        let (proof, vd) = inputs.cells_proof.into();
        self.cells_verifier
            .set_target(pw, &inputs.cells_set, &proof, &vd)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use alloy::primitives::U256;
    use itertools::Itertools;
    use mp2_common::{
        group_hashing::weierstrass_to_point,
        poseidon::{empty_poseidon_hash, H},
        types::CBuilder,
        utils::ToFields,
        C, D, F,
    };
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{field::types::PrimeField64, plonk::config::Hasher};
    use std::iter::once;

    #[derive(Clone, Debug)]
    struct TestPartialNodeCircuit {
        child_pi: Vec<F>,
        cells_pi: Vec<F>,
        circuit: PartialNodeCircuit,
    }

    impl UserCircuit<F, D> for TestPartialNodeCircuit {
        type Wires = (PartialNodeWires, Vec<Target>, Vec<Target>);

        fn build(c: &mut CBuilder) -> Self::Wires {
            let child_pi = c.add_virtual_targets(PublicInputs::<Target>::total_len());
            let cells_pi = c.add_virtual_targets(cells_tree::PublicInputs::<Target>::total_len());
            let wires = PartialNodeCircuit::build(c, &child_pi, &cells_pi);

            (wires, child_pi, cells_pi)
        }

        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.1, &self.child_pi);
            pw.set_target_arr(&wires.2, &self.cells_pi);
            self.circuit.assign(pw, &wires.0);
        }
    }

    #[test]
    fn partial_node_child_left() {
        partial_node_circuit(true, false, false)
    }

    #[test]
    fn partial_node_child_left_node_multiplier() {
        partial_node_circuit(true, true, false)
    }

    #[test]
    fn partial_node_child_left_cell_multiplier() {
        partial_node_circuit(true, false, true)
    }

    #[test]
    fn partial_node_child_left_all_multipliers() {
        partial_node_circuit(true, true, true)
    }

    #[test]
    fn partial_node_child_right() {
        partial_node_circuit(false, false, false)
    }

    #[test]
    fn partial_node_child_right_node_multiplier() {
        partial_node_circuit(false, true, false)
    }

    #[test]
    fn partial_node_child_right_cell_multiplier() {
        partial_node_circuit(false, false, true)
    }

    #[test]
    fn partial_node_child_right_all_multipliers() {
        partial_node_circuit(false, true, true)
    }

    pub fn partial_safety_check<T: Into<U256>>(
        child_min: T,
        child_max: T,
        node_value: U256,
        child_at_left: bool,
    ) {
        // max_left = left ? child_proof.max : index_value
        // min_right = left ? index_value : child_proof.min
        let (max_left, min_right) = match child_at_left {
            true => (child_max.into(), node_value),
            false => (node_value, child_min.into()),
        };
        assert!(max_left <= min_right);
    }

    fn partial_node_circuit(child_at_left: bool, is_multiplier: bool, is_cell_multiplier: bool) {
        let mut row = SecondaryIndexCell::sample(is_multiplier);
        row.cell.value = U256::from(18);
        let id = row.cell.identifier;
        let value = row.cell.value;
        let cells_pi = cells_tree::PublicInputs::sample(is_cell_multiplier);
        // Compute the row digest.
        let row_digest = row.digest(&cells_tree::PublicInputs::from_slice(&cells_pi));
        let (child_min, child_max) = match child_at_left {
            true => (U256::from(10), U256::from(15)),
            false => (U256::from(20), U256::from(25)),
        };
        partial_safety_check(child_min, child_max, value, child_at_left);
        let node_circuit = PartialNodeCircuit::new(row.clone(), child_at_left);
        let child_pi = PublicInputs::sample(
            row_digest.multiplier_vd,
            child_min.to(),
            child_max.to(),
            row_digest.multiplier_cnt.to_canonical_u64(),
        );
        let test_circuit = TestPartialNodeCircuit {
            circuit: node_circuit,
            cells_pi: cells_pi.clone(),
            child_pi: child_pi.clone(),
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);

        let child_pi = PublicInputs::from_slice(&child_pi);
        let cells_pi = cells_tree::PublicInputs::from_slice(&cells_pi);

        // Check root hash
        {
            // node_min = left ? child_proof.min : index_value
            // node_max = left ? index_value : child_proof.max
            let (node_min, node_max) = match child_at_left {
                true => (pi.min_value(), value),
                false => (value, pi.max_value()),
            };
            // Poseidon(p1.H || p2.H || node_min || node_max || index_id || index_value ||p.H)) as H
            let child_hash = child_pi.root_hash().to_fields();
            let empty_hash = empty_poseidon_hash().to_fields();
            let input_hash = match child_at_left {
                true => [child_hash, empty_hash].concat(),
                false => [empty_hash, child_hash].concat(),
            };
            let inputs = input_hash
                .into_iter()
                .chain(node_min.to_fields())
                .chain(node_max.to_fields())
                .chain(once(id))
                .chain(value.to_fields())
                .chain(cells_pi.node_hash().to_fields())
                .collect_vec();
            let exp_root_hash = H::hash_no_pad(&inputs);
            assert_eq!(pi.root_hash(), exp_root_hash);
        }
        // Check individual digest
        assert_eq!(
            pi.individual_digest_point(),
            (row_digest.individual_vd + weierstrass_to_point(&child_pi.individual_digest_point()))
                .to_weierstrass()
        );
        // Check multiplier digest
        assert_eq!(
            pi.multiplier_digest_point(),
            row_digest.multiplier_vd.to_weierstrass()
        );
        // Check minimum value
        assert_eq!(pi.min_value(), value.min(child_min));
        // Check maximum value
        assert_eq!(pi.max_value(), value.max(child_max));
        // Check multiplier counter
        assert_eq!(pi.multiplier_counter(), row_digest.multiplier_cnt);
    }
}
