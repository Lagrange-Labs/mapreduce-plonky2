use crate::results_tree::extraction::PublicInputs;
use anyhow::Result;
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    hash::hash_maybe_first,
    poseidon::H,
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    types::CBuilder,
    u256::CircuitBuilderU256,
    utils::{greater_than, less_than, ToTargets},
    D, F,
};
use plonky2::{
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::iter;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialNodeWires {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_left_child: BoolTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_rows_tree: BoolTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialNodeCircuit {
    /// Boolean flag specifying whether the included child is the left child or not
    pub(crate) is_left_child: bool,
    /// Boolean flag specifying whether the current node is a node
    /// of a rows tree or of the index tree
    pub(crate) is_rows_tree: bool,
}

impl PartialNodeCircuit {
    pub fn build(
        b: &mut CBuilder,
        subtree_proof: &PublicInputs<Target>,
        included_chid_proof: &PublicInputs<Target>,
        excluded_child_proof: &PublicInputs<Target>,
    ) -> PartialNodeWires {
        let one = b.one();

        let [is_left_child, is_rows_tree] = [0; 2].map(|_| b.add_virtual_bool_target_safe());

        let column_id = b.select(
            is_rows_tree,
            subtree_proof.index_ids_target()[1],
            subtree_proof.index_ids_target()[0],
        );
        let node_value = b.select_u256(
            is_rows_tree,
            &subtree_proof.min_value_target(),
            &subtree_proof.primary_index_value_target(),
        );
        let node_min = b.select_u256(
            is_left_child,
            &included_chid_proof.min_value_target(),
            &excluded_child_proof.min_value_target(),
        );
        let node_max = b.select_u256(
            is_left_child,
            &excluded_child_proof.max_value_target(),
            &included_chid_proof.max_value_target(),
        );

        // Compute the node hash:
        // H(left_hash||right_hash||node_min||node_max||column_id||node_value||pR.H)
        let rest: Vec<_> = node_min
            .to_targets()
            .into_iter()
            .chain(node_max.to_targets())
            .chain(iter::once(column_id))
            .chain(node_value.to_targets())
            .chain(subtree_proof.tree_hash_target().elements)
            .collect();

        let node_hash = hash_maybe_first(
            b,
            is_left_child,
            excluded_child_proof.tree_hash_target().elements,
            included_chid_proof.tree_hash_target().elements,
            &rest,
        );

        // Ensure the proofs in the same record subtree are employing the same value
        // of the indexed item
        // is_rows_tree == (is_rows_tree AND (pR.I == pI.I))
        let is_equal = b.is_equal_u256(
            &subtree_proof.primary_index_value_target(),
            &included_chid_proof.primary_index_value_target(),
        );
        let condition = b.and(is_equal, is_rows_tree);
        b.connect(condition.target, is_rows_tree.target);

        // Enforce consistency of counters
        let max_left = b.select(
            is_left_child,
            included_chid_proof.max_counter_target(),
            excluded_child_proof.max_counter_target(),
        );
        let min_right = b.select(
            is_left_child,
            excluded_child_proof.min_counter_target(),
            included_chid_proof.min_counter_target(),
        );
        // Verifying proof guarantees:
        // If the excluded child has N rows in its subtree,
        // then pC.max_counter - pC.min_counter == N
        // assert max_left + 1 == pR.min_counter
        let left_plus_one = b.add(max_left, one);
        b.connect(left_plus_one, subtree_proof.min_counter_target());
        // assert pR.max_counter + 1 == min_right
        let max_cnt_plus_one = b.add(subtree_proof.max_counter_target(), one);
        b.connect(max_cnt_plus_one, min_right);

        // Ensure that the subtree rooted in the sibling of the included child
        // contains only records outside of [query_min; query_max] range
        // left == (left AND (pC.min_counter > offset_range_max))
        let is_greater = greater_than(
            b,
            excluded_child_proof.min_counter_target(),
            subtree_proof.offset_range_max_target(),
            32,
        );
        let is_greater = b.and(is_greater, is_left_child);
        b.connect(is_greater.target, is_left_child.target);
        // NOT(left) == (NOT(left) AND( pC.max_counter < offset_range_min))
        let is_right_child = b.not(is_left_child);
        let is_less = less_than(
            b,
            excluded_child_proof.max_counter_target(),
            subtree_proof.offset_range_min_target(),
            32,
        );
        let is_less = b.and(is_less, is_right_child);
        b.connect(is_less.target, is_right_child.target);

        // Compute `min_counter` and `max_counter` for current node
        let min_counter = b.select(
            is_left_child,
            included_chid_proof.min_counter_target(),
            excluded_child_proof.min_counter_target(),
        );
        let max_counter = b.select(
            is_left_child,
            excluded_child_proof.max_counter_target(),
            included_chid_proof.max_counter_target(),
        );

        // pR.D + pI.D
        let accumulator = b.add_curve_point(&[
            subtree_proof.accumulator_target(),
            included_chid_proof.accumulator_target(),
        ]);

        // Register the public inputs.
        PublicInputs::new(
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

        PartialNodeWires {
            is_left_child,
            is_rows_tree,
        }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &PartialNodeWires) {
        pw.set_bool_target(wires.is_left_child, self.is_left_child);
        pw.set_bool_target(wires.is_rows_tree, self.is_rows_tree);
    }
}

/// Subtree proof number = 1, child proof number = 2
pub(crate) const NUM_VERIFIED_PROOFS: usize = 3;

impl CircuitLogicWires<F, D, NUM_VERIFIED_PROOFS> for PartialNodeWires {
    type CircuitBuilderParams = ();
    type Inputs = PartialNodeCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::total_len();

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; NUM_VERIFIED_PROOFS],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        // The first one is the subtree proof, and the remainings are child proofs.
        let [subtree_proof, included_child_proof, excluded_child_proof] =
            verified_proofs.map(|p| PublicInputs::from_slice(&p.public_inputs));

        Self::Inputs::build(
            builder,
            &subtree_proof,
            &included_child_proof,
            &excluded_child_proof,
        )
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
    use std::array;

    #[derive(Clone, Debug)]
    struct TestPartialNodeCircuit<'a> {
        c: PartialNodeCircuit,
        subtree_proof: &'a [F],
        included_child_proof: &'a [F],
        excluded_child_proof: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestPartialNodeCircuit<'a> {
        // Circuit wires + subtree proof + included child proof + excluded child proof
        type Wires = (PartialNodeWires, Vec<Target>, Vec<Target>, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let proofs = array::from_fn(|_| b.add_virtual_target_arr::<{ PI_LEN }>().to_vec());

            let [subtree_pi, included_child_pi, excluded_child_pi] =
                array::from_fn(|i| PublicInputs::<Target>::from_slice(&proofs[i]));

            let wires =
                PartialNodeCircuit::build(b, &subtree_pi, &included_child_pi, &excluded_child_pi);

            let [subtree_proof, included_child_proof, excluded_child_proof] = proofs;

            (
                wires,
                subtree_proof,
                included_child_proof,
                excluded_child_proof,
            )
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);
            pw.set_target_arr(&wires.1, self.subtree_proof);
            pw.set_target_arr(&wires.2, self.included_child_proof);
            pw.set_target_arr(&wires.3, self.excluded_child_proof);
        }
    }

    fn test_partial_node_circuit(is_rows_tree: bool, is_left_child: bool) {
        let [mut subtree_proof, mut included_child_proof, mut excluded_child_proof] =
            random_results_extraction_public_inputs::<3>();
        unify_subtree_proof(&mut subtree_proof);
        let subtree_pi = PublicInputs::from_slice(&subtree_proof);
        [
            (&mut included_child_proof, is_left_child),
            (&mut excluded_child_proof, !is_left_child),
        ]
        .iter_mut()
        .for_each(|(p, is_left_child)| {
            unify_child_proof(p, is_rows_tree, *is_left_child, &subtree_pi)
        });
        let included_child_pi = PublicInputs::from_slice(&included_child_proof);
        let excluded_child_pi = PublicInputs::from_slice(&excluded_child_proof);

        // Construct the expected public input values.
        let index_ids = subtree_pi.index_ids();
        let primary_index_value = subtree_pi.primary_index_value();
        let node_value = if is_rows_tree {
            subtree_pi.min_value()
        } else {
            primary_index_value
        };
        let node_min = if is_left_child {
            included_child_pi.min_value()
        } else {
            excluded_child_pi.min_value()
        };
        let node_max = if is_left_child {
            excluded_child_pi.max_value()
        } else {
            included_child_pi.max_value()
        };
        let min_counter = if is_left_child {
            included_child_pi.min_counter()
        } else {
            excluded_child_pi.min_counter()
        };
        let max_counter = if is_left_child {
            excluded_child_pi.max_counter()
        } else {
            included_child_pi.max_counter()
        };

        // Construct the test circuit.
        let test_circuit = TestPartialNodeCircuit {
            c: PartialNodeCircuit {
                is_left_child,
                is_rows_tree,
            },
            subtree_proof: &subtree_proof,
            included_child_proof: &included_child_proof,
            excluded_child_proof: &excluded_child_proof,
        };

        // Prove for the test circuit.
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);

        // Check the public inputs.
        // Tree hash
        {
            let column_id = if is_rows_tree {
                index_ids[1]
            } else {
                index_ids[0]
            };
            let left_hash = if is_left_child {
                included_child_pi.tree_hash()
            } else {
                excluded_child_pi.tree_hash()
            };
            let right_hash = if is_left_child {
                excluded_child_pi.tree_hash()
            } else {
                included_child_pi.tree_hash()
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
            let exp_accumulator =
                add_weierstrass_point(&[subtree_pi.accumulator(), included_child_pi.accumulator()]);

            assert_eq!(pi.accumulator(), exp_accumulator);
        }
    }

    #[test]
    fn test_partial_node_for_row_node_with_left_child() {
        test_partial_node_circuit(true, true);
    }
    #[test]
    fn test_partial_node_for_row_node_with_right_child() {
        test_partial_node_circuit(true, false);
    }
    #[test]
    fn test_partial_node_for_index_node_with_left_child() {
        test_partial_node_circuit(false, true);
    }
    #[test]
    fn test_partial_node_for_index_node_with_right_child() {
        test_partial_node_circuit(false, false);
    }
}
