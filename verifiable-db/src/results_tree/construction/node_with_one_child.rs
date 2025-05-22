//! Module handling the node with one child of the results tree for query circuits

use crate::{results_tree::construction::public_inputs::PublicInputs, D};
use anyhow::Result;
use itertools::Itertools;
use mp2_common::{
    array::Array,
    group_hashing::CircuitBuilderGroupHashing,
    hash::hash_maybe_first,
    poseidon::empty_poseidon_hash,
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    types::CBuilder,
    u256::CircuitBuilderU256,
    utils::ToTargets,
    F,
};
use plonky2::{
    field::types::Field,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::{iter, slice};

/// Node with one child wires
/// The constant generic parameter is only used for impl `CircuitLogicWires`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeWithOneChildWires<const S: usize> {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_rows_tree_node: BoolTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_left_child: BoolTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeWithOneChildCircuit<const S: usize> {
    /// The flag specified if the proof is generated for a node in a rows tree or
    /// for a node in the index tree
    pub(crate) is_rows_tree_node: bool,
    /// The flag specified if the child node is the left or right child
    pub(crate) is_left_child: bool,
}

impl<const S: usize> NodeWithOneChildCircuit<S> {
    pub fn build(
        b: &mut CBuilder,
        subtree_proof: &PublicInputs<Target, S>,
        child_proof: &PublicInputs<Target, S>,
    ) -> NodeWithOneChildWires<S>
    where
        [(); S - 2]:,
    {
        let ffalse = b._false();
        let one = b.one();
        let empty_hash = b.constant_hash(*empty_poseidon_hash());

        let is_rows_tree_node = b.add_virtual_bool_target_safe();
        let is_left_child = b.add_virtual_bool_target_unsafe();

        let index_ids = subtree_proof.index_ids_target();
        let column_id = b.select(is_rows_tree_node, index_ids[1], index_ids[0]);
        let primary_index_value = subtree_proof.primary_index_value_target();
        let node_value = b.select_u256(
            is_rows_tree_node,
            &subtree_proof.min_value_target(),
            &primary_index_value,
        );
        let child_min = &child_proof.min_value_target();
        let child_max = &child_proof.max_value_target();
        let node_min = b.select_u256(is_left_child, child_min, &node_value);
        let node_max = b.select_u256(is_left_child, &node_value, child_max);
        // lower_value = left ? pC.max : node_value
        let lower_value = b.select_u256(is_left_child, child_max, &node_value);
        // upper_value = left ? node_value : pC.min
        let upper_value = b.select_u256(is_left_child, &node_value, child_min);
        // lower_value < upper_value
        let is_lower_val_less_than_upper = b.is_less_than_u256(&lower_value, &upper_value);
        // lower_value == upper_value
        let is_lower_val_equal_to_upper = b.is_equal_u256(&lower_value, &upper_value);

        // Compute the node hash:
        // H(left_child.H || right_child.H || node_min || node_max || column_id || node_value || pR.H))
        let rest = node_min
            .to_targets()
            .into_iter()
            .chain(node_max.to_targets())
            .chain(iter::once(column_id))
            .chain(node_value.to_targets())
            .chain(subtree_proof.tree_hash_target().to_targets())
            .collect_vec();
        let node_hash = hash_maybe_first(
            b,
            is_left_child,
            empty_hash.elements,
            child_proof.tree_hash_target().elements,
            &rest,
        );

        // if is_rows_tree:
        //     assert pC.I == pR.I
        //     assert pR.min_counter == pR.max_counter
        //     assert lower_value < upper_value or lower_value == upper_value
        let is_idx_val_equal = b.is_equal_u256(
            &child_proof.primary_index_value_target(),
            &primary_index_value,
        );
        let is_cnt_equal = b.is_equal(
            subtree_proof.min_counter_target(),
            subtree_proof.max_counter_target(),
        );
        let is_lower_val_not_greater_than_upper =
            b.or(is_lower_val_less_than_upper, is_lower_val_equal_to_upper);
        let acc = [
            is_idx_val_equal,
            is_cnt_equal,
            is_lower_val_not_greater_than_upper,
        ]
        .into_iter()
        .fold(is_rows_tree_node, |acc, flag| b.and(acc, flag));
        b.connect(acc.target, is_rows_tree_node.target);
        // else:
        //     assert lower_value < upper_value
        let is_idx_tree_node = b.not(is_rows_tree_node);
        let acc = b.and(is_idx_tree_node, is_lower_val_less_than_upper);
        b.connect(acc.target, is_idx_tree_node.target);

        // assert pC.no_duplicates == pR.no_duplicates
        b.connect(
            child_proof.no_duplicates_flag_target().target,
            subtree_proof.no_duplicates_flag_target().target,
        );
        // We need to check for duplicates only in rows tree nodes:
        // check_duplicates = pR.no_duplicates and is_rows_tree
        let check_duplicates = b.and(subtree_proof.no_duplicates_flag_target(), is_rows_tree_node);

        // child_items = left ? pC.max_items : pC.min_items
        let child_items = b.select_u256_arr(
            is_left_child,
            &child_proof.max_items_target(),
            &child_proof.min_items_target(),
        );
        // node_items = left ? pR.min_items : pR.max_items
        let node_items = b.select_u256_arr(
            is_left_child,
            &subtree_proof.min_items_target(),
            &subtree_proof.max_items_target(),
        );
        // If we need to check that there are no duplicates, we enforce that
        // the records being inserted in the subtree rooted in the current node
        // are sorted and distinct.
        // (less_than, equal) = less_than_and_equal(child_items, node_items)
        let (is_items_less_than, is_items_equal) =
            b.is_less_than_or_equal_to_u256_arr(&child_items, &node_items);
        // condition = check_duplicates and lower_value == upper_value
        let cond = b.and(check_duplicates, is_lower_val_equal_to_upper);
        // if condition and is_left_child:
        //      # we enforce that pC.max_items < pR.min_items
        //      assert less_than
        let is_cond_and_left = b.and(cond, is_left_child);
        let acc = b.and(is_cond_and_left, is_items_less_than);
        b.connect(acc.target, is_cond_and_left.target);
        // if condition and (1 - is_left_child):
        //      # we need to enforce that pC.min_items > pR.max_items
        //      assert less_than + equal == 0
        // => condition * (1 - is_left_child) * (less_than + equal) = 0
        // Assume: acc = condition * (less_than + equal)
        // => acc - acc * is_left_child = 0
        let addition = b.add(is_items_less_than.target, is_items_equal.target);
        let acc = b.mul(cond.target, addition);
        let acc = b.arithmetic(F::NEG_ONE, F::ONE, is_left_child.target, acc, acc);
        b.connect(acc, ffalse.target);

        // Enforce counter values are consecutive:
        // - max_counter of left child (if left child exists) should be equal to
        //   min_counter of the record/rows tree stored in the current node
        // - max_counter of the record/rows tree stored in the current node must be
        //   equal to min_counter of the right child (if right child exists)
        // max_left = left ? pC.max_counter : pR.max_counter
        // min_right = left ? pR.min_counter : pC.min_counter
        // assert max_left + 1 == min_right
        let max_left = b.select(
            is_left_child,
            child_proof.max_counter_target(),
            subtree_proof.max_counter_target(),
        );
        let min_right = b.select(
            is_left_child,
            subtree_proof.min_counter_target(),
            child_proof.min_counter_target(),
        );
        let acc = b.add(max_left, one);
        b.connect(acc, min_right);

        // min_counter = left ? pC.min_counter : pR.min_counter
        let min_counter = b.select(
            is_left_child,
            child_proof.min_counter_target(),
            subtree_proof.min_counter_target(),
        );
        // max_counter = left ? pR.max_counter : pC.max_counter
        let max_counter = b.select(
            is_left_child,
            subtree_proof.max_counter_target(),
            child_proof.max_counter_target(),
        );
        // min_items = left ? pC.min_items : pR.min_items
        let min_items = b.select_u256_arr(
            is_left_child,
            &child_proof.min_items_target(),
            &subtree_proof.min_items_target(),
        );
        // max_items = left ? pR.max_items : pC.max_items
        let max_items = b.select_u256_arr(
            is_left_child,
            &subtree_proof.max_items_target(),
            &child_proof.max_items_target(),
        );

        // pC.index_ids == pR.index_ids
        Array::from(index_ids).enforce_equal(b, &Array::from(child_proof.index_ids_target()));

        // pR.D + pC.D
        let accumulator = b.add_curve_point(&[
            subtree_proof.accumulator_target(),
            child_proof.accumulator_target(),
        ]);

        let min_items = min_items.iter().flat_map(|i| i.to_targets()).collect_vec();
        let max_items = max_items.iter().flat_map(|i| i.to_targets()).collect_vec();

        // Register the public inputs.
        PublicInputs::<_, S>::new(
            &node_hash.to_targets(),
            &node_min.to_targets(),
            &node_max.to_targets(),
            &min_items,
            &max_items,
            &[min_counter],
            &[max_counter],
            subtree_proof.to_primary_index_value_raw(),
            &index_ids,
            slice::from_ref(subtree_proof.to_no_duplicates_raw()),
            &accumulator.to_targets(),
        )
        .register(b);

        NodeWithOneChildWires {
            is_rows_tree_node,
            is_left_child,
        }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &NodeWithOneChildWires<S>) {
        pw.set_bool_target(wires.is_rows_tree_node, self.is_rows_tree_node);
        pw.set_bool_target(wires.is_left_child, self.is_left_child);
    }
}

/// Subtree proof number = 1, child proof number = 1
pub(crate) const NUM_VERIFIED_PROOFS: usize = 2;

impl<const S: usize> CircuitLogicWires<F, D, NUM_VERIFIED_PROOFS> for NodeWithOneChildWires<S>
where
    [(); S - 2]:,
{
    type CircuitBuilderParams = ();
    type Inputs = NodeWithOneChildCircuit<S>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F, S>::total_len();

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; NUM_VERIFIED_PROOFS],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        // The first one is the subtree proof, and the second is the child proof.
        let [subtree_proof, child_proof] =
            verified_proofs.map(|p| PublicInputs::from_slice(&p.public_inputs));

        Self::Inputs::build(builder, &subtree_proof, &child_proof)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::results_tree::construction::tests::{
        pi_len, random_results_construction_public_inputs, unify_child_proof, unify_subtree_proof,
    };
    use mp2_common::{group_hashing::add_weierstrass_point, poseidon::H, utils::ToFields, C};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::plonk::config::Hasher;
    use std::array;

    const S: usize = 20;

    #[derive(Clone, Debug)]
    struct TestNodeWithOneChildCircuit<'a> {
        c: NodeWithOneChildCircuit<S>,
        subtree_proof: &'a [F],
        child_proof: &'a [F],
    }

    impl UserCircuit<F, D> for TestNodeWithOneChildCircuit<'_> {
        // Circuit wires + subtree proof + child proof
        type Wires = (NodeWithOneChildWires<S>, Vec<Target>, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let proofs =
                array::from_fn(|_| b.add_virtual_target_arr::<{ pi_len::<S>() }>().to_vec());
            let [subtree_pi, child_pi] =
                array::from_fn(|i| PublicInputs::<Target, S>::from_slice(&proofs[i]));

            let wires = NodeWithOneChildCircuit::build(b, &subtree_pi, &child_pi);

            let [subtree_proof, child_proof] = proofs;

            (wires, subtree_proof, child_proof)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);
            pw.set_target_arr(&wires.1, self.subtree_proof);
            pw.set_target_arr(&wires.2, self.child_proof);
        }
    }

    fn test_node_with_one_child_circuit(is_rows_tree_node: bool, is_left_child: bool) {
        // Generate the input proofs.
        let [mut subtree_proof, mut child_proof] =
            random_results_construction_public_inputs::<2, S>();
        unify_subtree_proof::<S>(&mut subtree_proof, is_rows_tree_node);
        let subtree_pi = PublicInputs::<_, S>::from_slice(&subtree_proof);
        unify_child_proof::<S>(
            &mut child_proof,
            is_rows_tree_node,
            is_left_child,
            &subtree_pi,
        );
        let child_pi = PublicInputs::<_, S>::from_slice(&child_proof);

        // Construct the expected public input values.
        let index_ids = subtree_pi.index_ids();
        let primary_index_value = subtree_pi.primary_index_value();
        let node_value = if is_rows_tree_node {
            subtree_pi.min_value()
        } else {
            primary_index_value
        };
        let [node_min, node_max] = if is_left_child {
            [child_pi.min_value(), node_value]
        } else {
            [node_value, child_pi.max_value()]
        };

        // Construct the test circuit.
        let test_circuit = TestNodeWithOneChildCircuit {
            c: NodeWithOneChildCircuit {
                is_rows_tree_node,
                is_left_child,
            },
            subtree_proof: &subtree_proof,
            child_proof: &child_proof,
        };

        // Prove for the test circuit.
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::<_, S>::from_slice(&proof.public_inputs);

        // Check the public inputs.
        // Tree hash
        {
            let column_id = if is_rows_tree_node {
                index_ids[1]
            } else {
                index_ids[0]
            };
            let empty_hash = empty_poseidon_hash();
            let child_hash = child_pi.tree_hash();
            let [left_child_hash, right_child_hash] = if is_left_child {
                [child_hash, *empty_hash]
            } else {
                [*empty_hash, child_hash]
            };

            // H(left_child.H || right_child.H || node_min || node_max || column_id || node_value || p.H))
            let inputs: Vec<_> = left_child_hash
                .to_fields()
                .into_iter()
                .chain(right_child_hash.to_fields())
                .chain(node_min.to_fields())
                .chain(node_max.to_fields())
                .chain(iter::once(column_id))
                .chain(node_value.to_fields())
                .chain(subtree_pi.tree_hash().to_fields())
                .collect();
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.tree_hash(), exp_hash);
        }
        // Minimum value
        assert_eq!(pi.min_value(), node_min);
        // Maximum value
        assert_eq!(pi.max_value(), node_max);
        // Minimum items
        {
            // min_items = left ? pC.min_items : pR.min_items
            let exp_min_items = if is_left_child {
                child_pi.min_items()
            } else {
                subtree_pi.min_items()
            };

            assert_eq!(pi.min_items(), exp_min_items);
        }
        // Maximum items
        {
            // max_items = left ? pR.max_items : pC.max_items
            let exp_max_items = if is_left_child {
                subtree_pi.max_items()
            } else {
                child_pi.max_items()
            };

            assert_eq!(pi.max_items(), exp_max_items);
        }
        // Minimum counter
        {
            // min_counter = left ? pC.min_counter : pR.min_counter
            let exp_min_counter = if is_left_child {
                child_pi.min_counter()
            } else {
                subtree_pi.min_counter()
            };

            assert_eq!(pi.min_counter(), exp_min_counter);
        }
        // Maximum counter
        {
            // max_counter = left ? pR.max_counter : pC.max_counter
            let exp_max_counter = if is_left_child {
                subtree_pi.max_counter()
            } else {
                child_pi.max_counter()
            };

            assert_eq!(pi.max_counter(), exp_max_counter);
        }
        // Primary index value
        assert_eq!(pi.primary_index_value(), subtree_pi.primary_index_value());
        // Index IDs
        assert_eq!(pi.index_ids(), index_ids);
        // No duplicates flag
        assert_eq!(pi.no_duplicates_flag(), subtree_pi.no_duplicates_flag());
        // Accumulator
        {
            let exp_accumulator =
                add_weierstrass_point(&[subtree_pi.accumulator(), child_pi.accumulator()]);
            assert_eq!(pi.accumulator(), exp_accumulator);
        }
    }

    #[test]
    fn test_results_construction_node_with_one_child_for_row_node_with_left_child() {
        test_node_with_one_child_circuit(true, true);
    }

    #[test]
    fn test_results_construction_node_with_one_child_for_row_node_with_right_child() {
        test_node_with_one_child_circuit(true, false);
    }

    #[test]
    fn test_results_construction_node_with_one_child_for_index_node_with_left_child() {
        test_node_with_one_child_circuit(false, true);
    }

    #[test]
    fn test_results_construction_node_with_one_child_for_index_node_with_right_child() {
        test_node_with_one_child_circuit(false, false);
    }
}
