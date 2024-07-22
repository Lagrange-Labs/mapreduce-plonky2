//! Module handling the full node with two children for query aggregation circuits

use crate::simple_query_circuits::{
    aggregation::{output_computation::compute_output_item, utils::constrain_input_proofs},
    public_inputs::PublicInputs,
};
use alloy::primitives::U256;
use anyhow::Result;
use mp2_common::{
    poseidon::H,
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::ToTargets,
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

/// Full node wires with two children
/// The constant generic parameter is only used for impl `CircuitLogicWires`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullNodeWithTwoChildrenWires<const MAX_NUM_RESULTS: usize> {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_rows_tree_node: BoolTarget,
    min_query: UInt256Target,
    max_query: UInt256Target,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullNodeWithTwoChildrenCircuit<const MAX_NUM_RESULTS: usize> {
    /// The flag specified if the proof is generated for a node in a rows tree or
    /// for a node in the index tree
    pub(crate) is_rows_tree_node: bool,
    /// Minimum range bound specified in the query for the indexed column
    /// It's a range bound for the primary indexed column for index tree,
    /// and secondary indexed column for rows tree.
    pub(crate) min_query: U256,
    /// Maximum range bound specified in the query for the indexed column
    pub(crate) max_query: U256,
}

impl<const MAX_NUM_RESULTS: usize> FullNodeWithTwoChildrenCircuit<MAX_NUM_RESULTS> {
    pub fn build(
        b: &mut CBuilder,
        subtree_proof: &PublicInputs<Target, MAX_NUM_RESULTS>,
        child_proofs: &[PublicInputs<Target, MAX_NUM_RESULTS>; 2],
    ) -> FullNodeWithTwoChildrenWires<MAX_NUM_RESULTS>
    where
        [(); MAX_NUM_RESULTS - 1]:,
    {
        let zero = b.zero();

        let is_rows_tree_node = b.add_virtual_bool_target_safe();
        let [min_query, max_query] = [0; 2].map(|_| b.add_virtual_u256_unsafe());

        // Check the consistency for the subtree proof and child proofs.
        constrain_input_proofs(
            b,
            is_rows_tree_node,
            &min_query,
            &max_query,
            subtree_proof,
            child_proofs,
        );

        // Choose the column ID and node value to be hashed depending on which tree
        // the current node belongs to.
        let index_ids = subtree_proof.index_ids_target();
        let column_id = b.select(is_rows_tree_node, index_ids[1], index_ids[0]);
        let index_value = subtree_proof.index_value_target();
        let node_value = b.select_u256(
            is_rows_tree_node,
            &subtree_proof.min_value_target(),
            &index_value,
        );

        // Compute the node hash:
        // node_hash = H(p1.H || p2.H || p1.min || p2.max || column_id || node_value || p.H)
        let [child_proof1, child_proof2] = child_proofs;
        let inputs = child_proof1
            .tree_hash_target()
            .to_targets()
            .into_iter()
            .chain(child_proof2.tree_hash_target().to_targets())
            .chain(child_proof1.min_value_target().to_targets())
            .chain(child_proof2.max_value_target().to_targets())
            .chain(iter::once(column_id))
            .chain(node_value.to_targets())
            .chain(subtree_proof.tree_hash_target().to_targets())
            .collect();
        let node_hash = b.hash_n_to_hash_no_pad::<H>(inputs);

        // Aggregate the output values of children and the overflow number.
        let mut num_overflows = zero;
        let mut aggregated_values = vec![];
        for i in 0..MAX_NUM_RESULTS {
            let (mut output, overflow) =
                compute_output_item(b, i, &[subtree_proof, child_proof1, child_proof2]);

            aggregated_values.append(&mut output);
            num_overflows = b.add(num_overflows, overflow);
        }

        // count = p1.count + p2.count + p.count
        let count = b.add(
            child_proof1.num_matching_rows_target(),
            child_proof2.num_matching_rows_target(),
        );
        let count = b.add(count, subtree_proof.num_matching_rows_target());

        // overflow = (p.overflow + p1.overflow + p2.overflow + num_overflows) != 0
        let overflow = b.add_many([
            subtree_proof.to_overflow_raw(),
            child_proof1.to_overflow_raw(),
            child_proof2.to_overflow_raw(),
            &num_overflows,
        ]);
        let overflow = b.is_not_equal(overflow, zero);

        // Register the public inputs.
        PublicInputs::<_, MAX_NUM_RESULTS>::new(
            &node_hash.to_targets(),
            &aggregated_values.as_slice(),
            &[count],
            subtree_proof.to_ops_raw(),
            subtree_proof.to_index_value_raw(),
            child_proof1.to_min_value_raw(),
            child_proof2.to_max_value_raw(),
            subtree_proof.to_index_ids_raw(),
            &min_query.to_targets(),
            &max_query.to_targets(),
            &[overflow.target],
            subtree_proof.to_computational_hash_raw(),
            subtree_proof.to_placeholder_hash_raw(),
        )
        .register(b);

        FullNodeWithTwoChildrenWires {
            is_rows_tree_node,
            min_query,
            max_query,
        }
    }

    fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &FullNodeWithTwoChildrenWires<MAX_NUM_RESULTS>,
    ) {
        pw.set_bool_target(wires.is_rows_tree_node, self.is_rows_tree_node);
        pw.set_u256_target(&wires.min_query, self.min_query);
        pw.set_u256_target(&wires.max_query, self.max_query);
    }
}

/// Subtree proof number = 1, child proof number = 2
pub(crate) const NUM_VERIFIED_PROOFS: usize = 3;

impl<const MAX_NUM_RESULTS: usize> CircuitLogicWires<F, D, NUM_VERIFIED_PROOFS>
    for FullNodeWithTwoChildrenWires<MAX_NUM_RESULTS>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    type CircuitBuilderParams = ();
    type Inputs = FullNodeWithTwoChildrenCircuit<MAX_NUM_RESULTS>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F, MAX_NUM_RESULTS>::total_len();

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
    use crate::simple_query_circuits::{
        aggregation::{
            tests::{
                compute_output_item_value, random_aggregation_operations,
                random_aggregation_public_inputs,
            },
            utils::tests::{unify_child_proof, unify_subtree_proof},
        },
        public_inputs::QueryPublicInputs,
        PI_LEN,
    };
    use mp2_common::{utils::ToFields, C};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{iop::witness::WitnessWrite, plonk::config::Hasher};
    use std::array;

    const MAX_NUM_RESULTS: usize = 20;

    #[derive(Clone, Debug)]
    struct TestFullNodeWithTwoChildrenCircuit<'a> {
        c: FullNodeWithTwoChildrenCircuit<MAX_NUM_RESULTS>,
        subtree_proof: &'a [F],
        left_child_proof: &'a [F],
        right_child_proof: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestFullNodeWithTwoChildrenCircuit<'a> {
        // Circuit wires + subtree proof + left child proof + right child proof
        type Wires = (
            FullNodeWithTwoChildrenWires<MAX_NUM_RESULTS>,
            Vec<Target>,
            Vec<Target>,
            Vec<Target>,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let proofs = array::from_fn(|_| {
                b.add_virtual_target_arr::<{ PI_LEN::<MAX_NUM_RESULTS> }>()
                    .to_vec()
            });
            let [subtree_pi, left_child_pi, right_child_pi] =
                array::from_fn(|i| PublicInputs::<Target, MAX_NUM_RESULTS>::from_slice(&proofs[i]));

            let wires = FullNodeWithTwoChildrenCircuit::build(
                b,
                &subtree_pi,
                &[left_child_pi, right_child_pi],
            );

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
        let min_query = U256::from(100);
        let max_query = U256::from(200);

        // Generate the input proofs.
        let ops: [_; MAX_NUM_RESULTS] = random_aggregation_operations();
        let [mut subtree_proof, mut left_child_proof, mut right_child_proof] =
            random_aggregation_public_inputs(&ops);
        unify_subtree_proof::<MAX_NUM_RESULTS>(
            &mut subtree_proof,
            is_rows_tree_node,
            min_query,
            max_query,
        );
        let subtree_pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&subtree_proof);
        [&mut left_child_proof, &mut right_child_proof]
            .iter_mut()
            .for_each(|p| {
                unify_child_proof::<MAX_NUM_RESULTS>(
                    p,
                    is_rows_tree_node,
                    min_query,
                    max_query,
                    &subtree_pi,
                )
            });
        let left_child_pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&left_child_proof);
        let right_child_pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&right_child_proof);

        // Construct the expected public input values.
        let index_ids = subtree_pi.index_ids();
        let index_value = subtree_pi.index_value();
        let node_value = if is_rows_tree_node {
            subtree_pi.min_value()
        } else {
            index_value
        };

        // Construct the test circuit.
        let test_circuit = TestFullNodeWithTwoChildrenCircuit {
            c: FullNodeWithTwoChildrenCircuit {
                is_rows_tree_node,
                min_query,
                max_query,
            },
            subtree_proof: &subtree_proof,
            left_child_proof: &left_child_proof,
            right_child_proof: &right_child_proof,
        };

        // Prove for the test circuit.
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&proof.public_inputs);

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
        // Output values and overflow flag
        {
            let mut num_overflows = 0;
            let mut aggregated_values = vec![];

            for i in 0..MAX_NUM_RESULTS {
                let (mut output, overflow) =
                    compute_output_item_value(i, &[&subtree_pi, &left_child_pi, &right_child_pi]);

                aggregated_values.append(&mut output);
                num_overflows += overflow;
            }

            assert_eq!(pi.to_values_raw(), aggregated_values);
            assert_eq!(
                pi.overflow_flag(),
                subtree_pi.overflow_flag()
                    || left_child_pi.overflow_flag()
                    || right_child_pi.overflow_flag()
                    || num_overflows != 0
            );
        }
        // Count
        assert_eq!(
            pi.num_matching_rows(),
            subtree_pi.num_matching_rows()
                + left_child_pi.num_matching_rows()
                + right_child_pi.num_matching_rows(),
        );
        // Operation IDs
        assert_eq!(pi.operation_ids(), subtree_pi.operation_ids());
        // Index value
        assert_eq!(pi.index_value(), index_value);
        // Minimum value
        assert_eq!(pi.min_value(), left_child_pi.min_value());
        // Maximum value
        assert_eq!(pi.max_value(), right_child_pi.max_value());
        // Index IDs
        assert_eq!(pi.index_ids(), index_ids);
        // Minimum query
        assert_eq!(pi.min_query_value(), min_query);
        // Maximum query
        assert_eq!(pi.max_query_value(), max_query);
        // Computational hash
        assert_eq!(pi.computational_hash(), subtree_pi.computational_hash());
        // Placeholder hash
        assert_eq!(pi.placeholder_hash(), subtree_pi.placeholder_hash());
    }

    #[test]
    fn test_query_agg_full_node_with_two_children_for_row_node() {
        test_full_node_with_two_children_circuit(true);
    }

    #[test]
    fn test_query_agg_full_node_with_two_children_for_index_node() {
        test_full_node_with_two_children_circuit(false);
    }
}
