use crate::results_tree::extraction::PublicInputs;
use anyhow::Result;
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    poseidon::{empty_poseidon_hash, H},
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    types::CBuilder,
    u256::CircuitBuilderU256,
    utils::{SelectCurveBuilder, SelectHashBuilder, ToTargets},
    D, F,
};
use plonky2::{
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::iter;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullNodeWires {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    left_child_exists: BoolTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    right_child_exists: BoolTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_rows_tree: BoolTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullNodeCircuit {
    /// Boolean flag specifying whether the node has a left child
    pub(crate) left_child_exists: bool,
    /// Boolean flag specifying whether the node has a right child
    pub(crate) right_child_exists: bool,
    /// Boolean flag specifying whether this node is a node of rows tree or of the index tree
    pub(crate) is_rows_tree: bool,
}

impl FullNodeCircuit {
    pub fn build(
        b: &mut CBuilder,
        subtree_proof: &PublicInputs<Target>,
        child_proofs: &[PublicInputs<Target>; 2],
    ) -> FullNodeWires {
        let empty_hash = b.constant_hash(*empty_poseidon_hash());
        let curve_zero = b.curve_zero();
        let one = b.one();

        let [child_proof1, child_proof2] = child_proofs;
        let [left_child_exists, right_child_exists, is_rows_tree] =
            [0; 3].map(|_| b.add_virtual_bool_target_safe());
        let index_value = subtree_proof.primary_index_value_target();

        let left_hash = b.select_hash(
            left_child_exists,
            &child_proof1.tree_hash_target(),
            &empty_hash,
        );
        let right_hash = b.select_hash(
            right_child_exists,
            &child_proof2.tree_hash_target(),
            &empty_hash,
        );
        let column_id = b.select(
            is_rows_tree,
            subtree_proof.index_ids_target()[1],
            subtree_proof.index_ids_target()[0],
        );
        let node_value = b.select_u256(
            is_rows_tree,
            &subtree_proof.min_value_target(),
            &index_value,
        );
        let node_min = b.select_u256(
            left_child_exists,
            &child_proof1.min_value_target(),
            &node_value,
        );
        let node_max = b.select_u256(
            right_child_exists,
            &child_proof2.max_value_target(),
            &node_value,
        );

        // H(left_hash || right_hash || node_min || node_max || column_id || node_value || p.H)
        let hash_inputs = left_hash
            .to_targets()
            .into_iter()
            .chain(right_hash.to_targets())
            .chain(node_min.to_targets())
            .chain(node_max.to_targets())
            .chain(iter::once(column_id))
            .chain(node_value.to_targets())
            .chain(subtree_proof.tree_hash_target().to_targets())
            .collect();
        let node_hash = b.hash_n_to_hash_no_pad::<H>(hash_inputs);

        // Ensure the proofs in the same rows tree are employing the same value
        // of the primary indexed column:
        // is_rows_tree == (is_rows_tree AND (p.I == p1.I AND p.I == p2.I))
        let [is_equal1, is_equal2] = [child_proof1, child_proof2]
            .map(|p| b.is_equal_u256(&index_value, &p.primary_index_value_target()));
        let is_equal = b.and(is_equal1, is_equal2);
        let is_equal = b.and(is_equal, is_rows_tree);
        b.connect(is_equal.target, is_rows_tree.target);

        // Enforce consistency of counters
        let min_minus_one = b.sub(subtree_proof.min_counter_target(), one);
        let max_plus_one = b.add(subtree_proof.max_counter_target(), one);
        let max_left = b.select(
            left_child_exists,
            child_proof1.max_counter_target(),
            min_minus_one,
        );
        let min_right = b.select(
            right_child_exists,
            child_proof2.min_counter_target(),
            max_plus_one,
        );
        // assert max_left + 1 == p.min_counter
        let left_plus_one = b.add(max_left, one);
        b.connect(left_plus_one, subtree_proof.min_counter_target());
        // assert p.max_counter + 1 == min_right
        b.connect(max_plus_one, min_right);

        // aggregate accumulators
        let left_acc = b.select_curve(
            left_child_exists,
            &child_proof1.accumulator_target(),
            &curve_zero,
        );
        let right_acc = b.select_curve(
            right_child_exists,
            &child_proof2.accumulator_target(),
            &curve_zero,
        );
        let accumulator =
            b.add_curve_point(&[left_acc, right_acc, subtree_proof.accumulator_target()]);

        let min_counter = b.select(
            left_child_exists,
            child_proof1.min_counter_target(),
            subtree_proof.min_counter_target(),
        );
        let max_counter = b.select(
            right_child_exists,
            child_proof2.max_counter_target(),
            subtree_proof.max_counter_target(),
        );

        // Register the public inputs.
        PublicInputs::<_>::new(
            &node_hash.to_targets(),
            &node_min.to_targets(),
            &node_max.to_targets(),
            subtree_proof.to_primary_index_value_raw(),
            subtree_proof.to_index_ids_raw(),
            &[min_counter],
            &[max_counter],
            &[*subtree_proof.to_offset_range_min_raw()],
            &[*subtree_proof.to_offset_range_max_raw()],
            &accumulator.to_targets(),
        )
        .register(b);

        FullNodeWires {
            left_child_exists,
            right_child_exists,
            is_rows_tree,
        }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &FullNodeWires) {
        pw.set_bool_target(wires.left_child_exists, self.left_child_exists);
        pw.set_bool_target(wires.right_child_exists, self.right_child_exists);
        pw.set_bool_target(wires.is_rows_tree, self.is_rows_tree);
    }
}

/// Subtree proof number = 1, child proof number = 2
pub(crate) const NUM_VERIFIED_PROOFS: usize = 3;

impl CircuitLogicWires<F, D, NUM_VERIFIED_PROOFS> for FullNodeWires {
    type CircuitBuilderParams = ();
    type Inputs = FullNodeCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::total_len();

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; NUM_VERIFIED_PROOFS],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        // The first one is the subtree proof, and the remainings are child proofs.
        let [subtree_proof, child_proof1, child_proof2] =
            verified_proofs.map(|p| PublicInputs::from_slice(&p.public_inputs));

        Self::Inputs::build(builder, &subtree_proof, &[child_proof1, child_proof2])
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::results_tree::extraction::{
        tests::{random_results_extraction_public_inputs, unify_child_proof, unify_subtree_proof},
        PI_LEN,
    };
    use mp2_common::{group_hashing::add_weierstrass_point, utils::ToFields, C};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::plonk::config::Hasher;
    use plonky2_ecgfp5::curve::curve::WeierstrassPoint;
    use std::array;

    #[derive(Clone, Debug)]
    struct TestFullNodeCircuit<'a> {
        c: FullNodeCircuit,
        subtree_proof: &'a [F],
        left_child_proof: &'a [F],
        right_child_proof: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestFullNodeCircuit<'a> {
        // Circuit wires + subtree proof + left child proof + right child proof
        type Wires = (FullNodeWires, Vec<Target>, Vec<Target>, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let proofs = array::from_fn(|_| b.add_virtual_target_arr::<{ PI_LEN }>().to_vec());

            let [subtree_pi, left_child_pi, right_child_pi] =
                array::from_fn(|i| PublicInputs::<Target>::from_slice(&proofs[i]));

            let wires = FullNodeCircuit::build(b, &subtree_pi, &[left_child_pi, right_child_pi]);

            let [subtree_proof, left_child_proof, right_child_proof] = proofs;

            (wires, subtree_proof, left_child_proof, right_child_proof)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);
            pw.set_target_arr(&wires.1, self.subtree_proof);
            pw.set_target_arr(&wires.2, self.left_child_proof);
            pw.set_target_arr(&wires.3, self.right_child_proof);
        }
    }

    fn test_full_node_circuit(
        is_rows_tree: bool,
        left_child_exists: bool,
        right_child_exists: bool,
    ) {
        // Generate the input proofs.
        let [mut subtree_proof, mut left_child_proof, mut right_child_proof] =
            random_results_extraction_public_inputs::<3>();
        unify_subtree_proof(&mut subtree_proof);
        let subtree_pi = PublicInputs::from_slice(&subtree_proof);
        [
            (&mut left_child_proof, true),
            (&mut right_child_proof, false),
        ]
        .iter_mut()
        .for_each(|(p, is_left_child)| {
            unify_child_proof(p, is_rows_tree, *is_left_child, &subtree_pi)
        });
        let left_child_pi = PublicInputs::from_slice(&left_child_proof);
        let right_child_pi = PublicInputs::from_slice(&right_child_proof);

        // Construct the expected public input values.
        let index_ids = subtree_pi.index_ids();
        let primary_index_value = subtree_pi.primary_index_value();
        let node_value = if is_rows_tree {
            subtree_pi.min_value()
        } else {
            primary_index_value
        };
        let node_min = if left_child_exists {
            left_child_pi.min_value()
        } else {
            node_value
        };
        let node_max = if right_child_exists {
            right_child_pi.max_value()
        } else {
            node_value
        };
        let min_counter = if left_child_exists {
            left_child_pi.min_counter()
        } else {
            subtree_pi.min_counter()
        };
        let max_counter = if right_child_exists {
            right_child_pi.max_counter()
        } else {
            subtree_pi.max_counter()
        };

        // Construct the test circuit.
        let test_circuit = TestFullNodeCircuit {
            c: FullNodeCircuit {
                left_child_exists,
                right_child_exists,
                is_rows_tree,
            },
            subtree_proof: &subtree_proof,
            left_child_proof: &left_child_proof,
            right_child_proof: &right_child_proof,
        };

        // Prove for the test circuit.
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::<_>::from_slice(&proof.public_inputs);

        // Check the public inputs.
        // Tree hash
        {
            let column_id = if is_rows_tree {
                index_ids[1]
            } else {
                index_ids[0]
            };
            let empty_hash = empty_poseidon_hash();
            let left_hash = if left_child_exists {
                left_child_pi.tree_hash()
            } else {
                *empty_hash
            };
            let right_hash = if right_child_exists {
                right_child_pi.tree_hash()
            } else {
                *empty_hash
            };
            let hash_inputs: Vec<_> = left_hash
                .to_fields()
                .into_iter()
                .chain(right_hash.to_fields())
                .chain(node_min.to_fields())
                .chain(node_max.to_fields())
                .chain(iter::once(column_id))
                .chain(node_value.to_fields())
                .chain(subtree_pi.tree_hash().to_fields())
                .collect();
            let exp_hash = H::hash_no_pad(&hash_inputs);
            assert_eq!(pi.tree_hash(), exp_hash);
        }

        // Minimum value
        assert_eq!(pi.min_value(), node_min);

        // Maximum value
        assert_eq!(pi.max_value(), node_max);

        // Primary index value
        assert_eq!(pi.primary_index_value(), subtree_pi.primary_index_value());

        // Index IDs
        assert_eq!(pi.index_ids(), index_ids);

        // Minimum counter
        assert_eq!(pi.min_counter(), min_counter);

        // Maximum counter
        assert_eq!(pi.max_counter(), max_counter);

        // Offset range min
        assert_eq!(pi.offset_range_min(), subtree_pi.offset_range_min());

        // Offset range max
        assert_eq!(pi.offset_range_max(), subtree_pi.offset_range_max());

        // Accumulator
        {
            let left_acc = if left_child_exists {
                left_child_pi.accumulator()
            } else {
                WeierstrassPoint::NEUTRAL
            };
            let right_acc = if right_child_exists {
                right_child_pi.accumulator()
            } else {
                WeierstrassPoint::NEUTRAL
            };
            let exp_accumulator =
                add_weierstrass_point(&[left_acc, right_acc, subtree_pi.accumulator()]);

            assert_eq!(pi.accumulator(), exp_accumulator);
        }
    }

    #[test]
    fn test_full_node_circuit_for_row_node_with_no_child() {
        test_full_node_circuit(true, false, false);
    }
    #[test]
    fn test_full_node_circuit_for_row_node_with_left_child() {
        test_full_node_circuit(true, true, false);
    }
    #[test]
    fn test_full_node_circuit_for_row_node_with_right_child() {
        test_full_node_circuit(true, false, true);
    }
    #[test]
    fn test_full_node_circuit_for_row_node_with_both_children() {
        test_full_node_circuit(true, true, true);
    }
    #[test]
    fn test_full_node_circuit_for_index_node_with_no_child() {
        test_full_node_circuit(false, false, false);
    }
    #[test]
    fn test_full_node_circuit_for_index_node_with_left_child() {
        test_full_node_circuit(false, true, false);
    }
    #[test]
    fn test_full_node_circuit_for_index_node_with_right_child() {
        test_full_node_circuit(false, false, true);
    }
    #[test]
    fn test_full_node_circuit_for_index_node_with_both_children() {
        test_full_node_circuit(false, true, true);
    }
}
