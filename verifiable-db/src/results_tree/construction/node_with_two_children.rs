//! Module handling the node with two children of the results tree for query circuits

use crate::results_tree::construction::public_inputs::PublicInputs;
use anyhow::Result;
use mp2_common::{
    array::Array,
    group_hashing::CircuitBuilderGroupHashing,
    poseidon::H,
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    types::CBuilder,
    u256::CircuitBuilderU256,
    utils::ToTargets,
    D, F,
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

/// Node with two children wires
/// The constant generic parameter is only used for impl `CircuitLogicWires`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeWithTwoChildrenWires<const S: usize> {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_rows_tree_node: BoolTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeWithTwoChildrenCircuit<const S: usize> {
    /// The flag specified if the proof is generated for a node in a rows tree or
    /// for a node in the index tree
    pub(crate) is_rows_tree_node: bool,
}

impl<const S: usize> NodeWithTwoChildrenCircuit<S> {
    pub fn build(
        b: &mut CBuilder,
        subtree_proof: &PublicInputs<Target, S>,
        child_proofs: &[PublicInputs<Target, S>; 2],
    ) -> NodeWithTwoChildrenWires<S>
    where
        [(); S - 2]:,
    {
        let ffalse = b._false();
        let one = b.one();

        let is_rows_tree_node = b.add_virtual_bool_target_safe();

        // Choose the column ID and node value to be hashed depending on which tree
        // the current node belongs to.
        let index_ids = subtree_proof.index_ids_target();
        let column_id = b.select(is_rows_tree_node, index_ids[1], index_ids[0]);
        let primary_index_value = subtree_proof.primary_index_value_target();
        let node_value = b.select_u256(
            is_rows_tree_node,
            &subtree_proof.min_value_target(),
            &primary_index_value,
        );
        let no_duplicates = subtree_proof.no_duplicates_flag_target();

        // Compute the node hash:
        // H(p1.H || p2.H || p1.min || p2.max || column_id || node_value || p.H)
        let [child_proof1, child_proof2] = child_proofs;
        let inputs = child_proof1
            .to_tree_hash_raw()
            .iter()
            .chain(child_proof2.to_tree_hash_raw())
            .chain(child_proof1.to_min_value_raw())
            .chain(child_proof2.to_max_value_raw())
            .chain(iter::once(&column_id))
            .chain(&node_value.to_targets())
            .chain(subtree_proof.to_tree_hash_raw())
            .cloned()
            .collect();
        let node_hash = b.hash_n_to_hash_no_pad::<H>(inputs);

        // is_left_child_max_smaller = p1.max < node_value
        let is_left_child_max_smaller =
            b.is_less_than_u256(&child_proof1.max_value_target(), &node_value);
        // is_right_child_min_greater = node_value < p2.min
        let is_right_child_min_greater =
            b.is_less_than_u256(&node_value, &child_proof2.min_value_target());

        // if is_rows_tree:
        //      assert p1.I == p2.I == p.I
        //      assert p.min_counter == p.max_counter
        //      assert is_left_child_max_smaller or p1.max == node_value
        //      assert is_right_child_min_greater or p2.min == node_value
        let is_idx_val_equal = b.is_equal_u256_slice(
            &[subtree_proof, child_proof1, child_proof2].map(|p| p.primary_index_value_target()),
        );
        let is_cnt_equal = b.is_equal(
            subtree_proof.min_counter_target(),
            subtree_proof.max_counter_target(),
        );
        let is_left_equal_node = b.is_equal_u256(&child_proof1.max_value_target(), &node_value);
        let is_right_equal_node = b.is_equal_u256(&child_proof2.min_value_target(), &node_value);
        // assert is_left_child_max_smaller or p1.max == node_value
        let left_cond = b.or(is_left_child_max_smaller, is_left_equal_node);
        // assert is_right_child_min_greater or p2.min == node_value
        let right_cond = b.or(is_right_child_min_greater, is_right_equal_node);
        let acc = [is_idx_val_equal, is_cnt_equal, left_cond, right_cond]
            .into_iter()
            .fold(is_rows_tree_node, |acc, flag| b.and(acc, flag));
        b.connect(acc.target, is_rows_tree_node.target);
        // else:
        //      assert is_left_child_max_smaller and is_right_child_min_greater
        let is_index_tree_node = b.not(is_rows_tree_node);
        let acc = [is_left_child_max_smaller, is_right_child_min_greater]
            .into_iter()
            .fold(is_index_tree_node, |acc, flag| b.and(acc, flag));
        b.connect(acc.target, is_index_tree_node.target);

        // assert p.no_duplicates == p1.no_duplicates == p2.no_duplicates
        b.connect(
            no_duplicates.target,
            child_proof1.no_duplicates_flag_target().target,
        );
        b.connect(
            no_duplicates.target,
            child_proof2.no_duplicates_flag_target().target,
        );
        // Determine whether we need to enforce there are no duplicates or not.
        // We need to check for duplicates only in rows tree nodes.
        let check_duplicates = b.and(no_duplicates, is_rows_tree_node);

        // If we need to check that there are no duplicates, we enforce that
        // the records being inserted in the subtree rooted in the current node
        // are sorted and distinct:
        // is_smaller = less_than(p1.max_items, p.min_items)
        let is_smaller = b.is_less_than_u256_arr(
            &child_proof1.max_items_target(),
            &subtree_proof.min_items_target(),
        );
        // `is_smaller` must be true only if we need to check for duplicates and `p1.max == node_value`:
        // assert not check_duplicates or is_left_child_max_smaller or is_smaller
        // => check_duplicates * (1 - is_left_child_max_smaller) * (1 - is_smaller) = 0
        let acc = b.arithmetic(
            F::NEG_ONE,
            F::ONE,
            is_left_child_max_smaller.target,
            check_duplicates.target,
            check_duplicates.target,
        );
        let acc = b.arithmetic(F::NEG_ONE, F::ONE, is_smaller.target, acc, acc);
        b.connect(acc, ffalse.target);
        // is_smaller = less_than(p.max_items, p2.min_items)
        let is_smaller = b.is_less_than_u256_arr(
            &subtree_proof.max_items_target(),
            &child_proof2.min_items_target(),
        );
        // `is_smaller` must be true only if we need to check for duplicates and `p2.min == node_value`:
        // assert not check_duplicates or is_right_child_min_greater or is_smaller
        // => check_duplicates * (1 - is_right_child_min_greater) * (1 - is_smaller) = 0
        let acc = b.arithmetic(
            F::NEG_ONE,
            F::ONE,
            is_right_child_min_greater.target,
            check_duplicates.target,
            check_duplicates.target,
        );
        let acc = b.arithmetic(F::NEG_ONE, F::ONE, is_smaller.target, acc, acc);
        b.connect(acc, ffalse.target);

        // Enforce counters provided as witness in the record construction circuit are consistent.
        // assert p1.max_counter + 1 == p.min_counter
        let acc = b.add(child_proof1.max_counter_target(), one);
        b.connect(acc, subtree_proof.min_counter_target());
        // assert p.max_counter + 1 == p2.min_counter
        let acc = b.add(subtree_proof.max_counter_target(), one);
        b.connect(acc, child_proof2.min_counter_target());

        // assert p.index_ids == p1.index_ids == p2.index_ids
        let index_ids_arr = Array::from(index_ids);
        child_proofs
            .iter()
            .for_each(|p| index_ids_arr.enforce_equal(b, &Array::from(p.index_ids_target())));

        // p.D + p1.D + p2.D
        let accumulator = b.add_curve_point(&[
            subtree_proof.accumulator_target(),
            child_proof1.accumulator_target(),
            child_proof2.accumulator_target(),
        ]);

        // Register the public inputs.
        PublicInputs::<_, S>::new(
            &node_hash.to_targets(),
            child_proof1.to_min_value_raw(),
            child_proof2.to_max_value_raw(),
            child_proof1.to_min_items_raw(),
            child_proof2.to_max_items_raw(),
            slice::from_ref(child_proof1.to_min_counter_raw()),
            slice::from_ref(child_proof2.to_max_counter_raw()),
            subtree_proof.to_primary_index_value_raw(),
            &index_ids,
            &[no_duplicates.target],
            &accumulator.to_targets(),
        )
        .register(b);

        NodeWithTwoChildrenWires { is_rows_tree_node }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &NodeWithTwoChildrenWires<S>) {
        pw.set_bool_target(wires.is_rows_tree_node, self.is_rows_tree_node);
    }
}

/// Subtree proof number = 1, child proof number = 2
pub(crate) const NUM_VERIFIED_PROOFS: usize = 3;

impl<const S: usize> CircuitLogicWires<F, D, NUM_VERIFIED_PROOFS> for NodeWithTwoChildrenWires<S>
where
    [(); S - 2]:,
{
    type CircuitBuilderParams = ();
    type Inputs = NodeWithTwoChildrenCircuit<S>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F, S>::total_len();

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
    use crate::results_tree::construction::tests::{
        pi_len, random_results_construction_public_inputs, unify_child_proof, unify_subtree_proof,
    };
    use mp2_common::{group_hashing::add_weierstrass_point, utils::ToFields, C};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::plonk::config::Hasher;
    use std::array;

    const S: usize = 20;

    #[derive(Clone, Debug)]
    struct TestNodeWithTwoChildrenCircuit<'a> {
        c: NodeWithTwoChildrenCircuit<S>,
        subtree_proof: &'a [F],
        left_child_proof: &'a [F],
        right_child_proof: &'a [F],
    }

    impl UserCircuit<F, D> for TestNodeWithTwoChildrenCircuit<'_> {
        // Circuit wires + subtree proof + left child proof + right child proof
        type Wires = (
            NodeWithTwoChildrenWires<S>,
            Vec<Target>,
            Vec<Target>,
            Vec<Target>,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let proofs =
                array::from_fn(|_| b.add_virtual_target_arr::<{ pi_len::<S>() }>().to_vec());
            let [subtree_pi, left_child_pi, right_child_pi] =
                array::from_fn(|i| PublicInputs::<Target, S>::from_slice(&proofs[i]));

            let wires =
                NodeWithTwoChildrenCircuit::build(b, &subtree_pi, &[left_child_pi, right_child_pi]);

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

    fn test_full_node_with_two_children_circuit(is_rows_tree_node: bool) {
        // Generate the input proofs.
        let [mut subtree_proof, mut left_child_proof, mut right_child_proof] =
            random_results_construction_public_inputs::<3, S>();
        unify_subtree_proof::<S>(&mut subtree_proof, is_rows_tree_node);
        let subtree_pi = PublicInputs::<_, S>::from_slice(&subtree_proof);
        [
            (&mut left_child_proof, true),
            (&mut right_child_proof, false),
        ]
        .iter_mut()
        .for_each(|(p, is_left_child)| {
            unify_child_proof::<S>(p, is_rows_tree_node, *is_left_child, &subtree_pi)
        });
        let left_child_pi = PublicInputs::<_, S>::from_slice(&left_child_proof);
        let right_child_pi = PublicInputs::<_, S>::from_slice(&right_child_proof);

        // Construct the expected public input values.
        let index_ids = subtree_pi.index_ids();
        let primary_index_value = subtree_pi.primary_index_value();
        let node_value = if is_rows_tree_node {
            subtree_pi.min_value()
        } else {
            primary_index_value
        };

        // Construct the test circuit.
        let test_circuit = TestNodeWithTwoChildrenCircuit {
            c: NodeWithTwoChildrenCircuit { is_rows_tree_node },
            subtree_proof: &subtree_proof,
            left_child_proof: &left_child_proof,
            right_child_proof: &right_child_proof,
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

            // H(p1.H || p2.H || p1.min || p2.max || column_id || node_value || p.H)
            let inputs: Vec<_> = left_child_pi
                .tree_hash()
                .to_fields()
                .into_iter()
                .chain(right_child_pi.tree_hash().to_fields())
                .chain(left_child_pi.min_value().to_fields())
                .chain(right_child_pi.max_value().to_fields())
                .chain(iter::once(column_id))
                .chain(node_value.to_fields())
                .chain(subtree_pi.tree_hash().to_fields())
                .collect();
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.tree_hash(), exp_hash);
        }
        // Minimum value
        assert_eq!(pi.min_value(), left_child_pi.min_value());
        // Maximum value
        assert_eq!(pi.max_value(), right_child_pi.max_value());
        // Minimum items
        assert_eq!(pi.min_items(), left_child_pi.min_items());
        // Maximum items
        assert_eq!(pi.max_items(), right_child_pi.max_items());
        // Minimum counter
        assert_eq!(pi.min_counter(), left_child_pi.min_counter());
        // Maximum counter
        assert_eq!(pi.max_counter(), right_child_pi.max_counter());
        // Primary index value
        assert_eq!(pi.primary_index_value(), subtree_pi.primary_index_value());
        // Index IDs
        assert_eq!(pi.index_ids(), index_ids);
        // No duplicates flag
        assert_eq!(pi.no_duplicates_flag(), subtree_pi.no_duplicates_flag());
        // Accumulator
        {
            let exp_accumulator = add_weierstrass_point(&[
                subtree_pi.accumulator(),
                left_child_pi.accumulator(),
                right_child_pi.accumulator(),
            ]);

            assert_eq!(pi.accumulator(), exp_accumulator);
        }
    }

    #[test]
    fn test_results_construction_node_with_two_children_for_row_node() {
        test_full_node_with_two_children_circuit(true);
    }

    #[test]
    fn test_results_construction_node_with_two_children_for_index_node() {
        test_full_node_with_two_children_circuit(false);
    }
}
