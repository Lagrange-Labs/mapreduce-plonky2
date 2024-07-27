use std::iter;

use alloy::primitives::U256;
use anyhow::Result;
use mp2_common::{
    poseidon::{empty_poseidon_hash, H},
    public_inputs::PublicInputCommon,
    serialization::{deserialize, deserialize_array, serialize, serialize_array},
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{SelectHashBuilder, ToTargets},
    D, F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::array;

use crate::query::public_inputs::PublicInputs;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubtreeProvenSinglePathNodeWires<const MAX_NUM_RESULTS: usize> {
    left_child_min: UInt256Target,
    left_child_max: UInt256Target,
    left_child_value: UInt256Target,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    left_tree_hash: HashOutTarget,
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    left_grand_children: [HashOutTarget; 2],
    right_child_min: UInt256Target,
    right_child_max: UInt256Target,
    right_child_value: UInt256Target,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    right_tree_hash: HashOutTarget,
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    right_grand_children: [HashOutTarget; 2],
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    left_child_exists: BoolTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    right_child_exists: BoolTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_rows_tree_node: BoolTarget,
    min_query: UInt256Target,
    max_query: UInt256Target,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubtreeProvenSinglePathNodeCircuit<const MAX_NUM_RESULTS: usize> {
    /// Minimum value associated to the left child
    pub(crate) left_child_min: U256,
    /// Maximum value associated to the left child
    pub(crate) left_child_max: U256,
    /// Value stored in the left child
    pub(crate) left_child_value: U256,
    /// Hashes of the row/rows tree stored in the left child
    pub(crate) left_tree_hash: HashOut<F>,
    /// Hashes of the children nodes of the left child
    pub(crate) left_grand_children: [HashOut<F>; 2],
    /// Minimum value associated to the right child
    pub(crate) right_child_min: U256,
    /// Maximum value associated to the right child
    pub(crate) right_child_max: U256,
    /// Value stored in the right child
    pub(crate) right_child_value: U256,
    /// Hashes of the row/rows tree stored in the right child
    pub(crate) right_tree_hash: HashOut<F>,
    /// Hashes of the children nodes of the right child
    pub(crate) right_grand_children: [HashOut<F>; 2],
    /// Boolean flag specifying whether there is a left child for the current node
    pub(crate) left_child_exists: bool,
    /// Boolean flag specifying whether there is a right child for the current node
    pub(crate) right_child_exists: bool,
    /// Boolean flag specifying whether the proof is being generated
    /// for a node in a rows tree or for a node in the index tree
    pub(crate) is_rows_tree_node: bool,
    /// Minimum range bound specified in the query for the indexed column
    pub(crate) min_query: U256,
    /// Maximum range bound specified in the query for the indexed column
    pub(crate) max_query: U256,
}

impl<const MAX_NUM_RESULTS: usize> SubtreeProvenSinglePathNodeCircuit<MAX_NUM_RESULTS> {
    pub fn build(
        b: &mut CBuilder,
        subtree_proof: &PublicInputs<Target, MAX_NUM_RESULTS>,
    ) -> SubtreeProvenSinglePathNodeWires<MAX_NUM_RESULTS> {
        let empty_hash = b.constant_hash(*empty_poseidon_hash());

        let [left_child_min, left_child_max, left_child_value, right_child_min, right_child_max, right_child_value, min_query, max_query] =
            array::from_fn(|_| b.add_virtual_u256_unsafe());
        let [left_tree_hash, right_tree_hash] = array::from_fn(|_| b.add_virtual_hash());
        let left_grand_children: [HashOutTarget; 2] = array::from_fn(|_| b.add_virtual_hash());
        let right_grand_children: [HashOutTarget; 2] = array::from_fn(|_| b.add_virtual_hash());
        let [left_child_exists, right_child_exists, is_rows_tree_node] =
            array::from_fn(|_| b.add_virtual_bool_target_safe());

        let index_value = subtree_proof.index_value_target();

        let column_id = b.select(
            is_rows_tree_node,
            subtree_proof.index_ids_target()[1],
            subtree_proof.index_ids_target()[0],
        );

        let node_value = b.select_u256(
            is_rows_tree_node,
            &subtree_proof.min_value_target(),
            &index_value,
        );

        // H(left_grandchild_1||left_grandchild_2||left_min||left_max||column_id||left_value||left_tree_hash)
        let left_child_inputs = left_grand_children[0]
            .to_targets()
            .into_iter()
            .chain(left_grand_children[1].to_targets())
            .chain(left_child_min.to_targets())
            .chain(left_child_max.to_targets())
            .chain(iter::once(column_id))
            .chain(left_child_value.to_targets())
            .chain(left_tree_hash.to_targets())
            .collect();
        let left_hash_exists = b.hash_n_to_hash_no_pad::<H>(left_child_inputs);
        let left_child_hash = b.select_hash(left_child_exists, &left_hash_exists, &empty_hash);

        // H(right_grandchild_1||right_grandchild_2||right_min||right_max||column_id||right_value||right_tree_hash)
        let right_child_inputs = right_grand_children[0]
            .to_targets()
            .into_iter()
            .chain(right_grand_children[1].to_targets())
            .chain(right_child_min.to_targets())
            .chain(right_child_max.to_targets())
            .chain(iter::once(column_id))
            .chain(right_child_value.to_targets())
            .chain(right_tree_hash.to_targets())
            .collect();
        let right_hash_exists = b.hash_n_to_hash_no_pad::<H>(right_child_inputs);
        let right_child_hash = b.select_hash(right_child_exists, &right_hash_exists, &empty_hash);

        let node_min = b.select_u256(left_child_exists, &left_child_min, &node_value);
        let node_max = b.select_u256(right_child_exists, &right_child_max, &node_value);

        // If the current nod is not a rows tree, we need to ensure that
        // the value of the indexed column for all the records stored in the records subtree
        // found in this node is within the range specified by the query
        // min_query <= index_value <= max_query
        // -> NOT((index_value < min_query) OR (index_value > max_query))
        let is_less_than = b.is_less_than_u256(&index_value, &min_query);
        let is_greater_than = b.is_greater_than_u256(&index_value, &max_query);
        let is_out_of_range = b.or(is_less_than, is_greater_than);
        let is_within_range = b.not(is_out_of_range);

        // If the current node is in a rows tree, we need to ensure that
        // the query bounds exposed as public inputs are the same as the one exposed
        // by the proof for the row associated to the current node
        let is_min_same = b.is_equal_u256(&subtree_proof.min_query_target(), &min_query);
        let is_max_same = b.is_equal_u256(&subtree_proof.max_query_target(), &max_query);
        let are_query_bounds_same = b.and(is_min_same, is_max_same);

        // if is_rows_tree_node:
        //   subtree_proof.min_query == min_query &&
        //   subtree_proof.max_query == max_query
        // else if not is_rows_tree_node:
        //   min_query <= index_value <= max_query
        let rows_tree_condition = b.select(
            is_rows_tree_node,
            are_query_bounds_same.target,
            is_within_range.target,
        );
        let ttrue = b._true();
        b.connect(rows_tree_condition, ttrue.target);

        // Enforce that the subtree rooted in the left child contains
        // only nodes outside of the range specified by the query
        let left_child_inexists = b.not(left_child_exists);
        let is_less_than_min = b.is_less_than_u256(&left_child_max, &min_query);
        // NOT(left_child_exists) OR (left_child_max < min_query)
        let left_condition = b.or(left_child_inexists, is_less_than_min);
        b.connect(left_condition.target, ttrue.target);

        // Enforce that the subtree rooted in the right child contains
        // only nodes outside of the range specified by the query
        let right_child_inexists = b.not(right_child_exists);
        let is_greater_than_max = b.is_greater_than_u256(&right_child_min, &max_query);
        // NOT(right_child_exists) OR (right_child_min > max_query)
        let right_condition = b.or(right_child_inexists, is_greater_than_max);
        b.connect(right_condition.target, ttrue.target);

        // H(left_child_hash||right_child_hash||node_min||node_max||column_id||node_value||p.H)
        let node_hash_inputs = left_child_hash
            .elements
            .into_iter()
            .chain(right_child_hash.elements)
            .chain(node_min.to_targets())
            .chain(node_max.to_targets())
            .chain(iter::once(column_id))
            .chain(node_value.to_targets())
            .chain(subtree_proof.tree_hash_target().to_targets())
            .collect();
        let node_hash = b.hash_n_to_hash_no_pad::<H>(node_hash_inputs);

        // Register the public inputs.
        PublicInputs::<_, MAX_NUM_RESULTS>::new(
            &node_hash.to_targets(),
            subtree_proof.to_values_raw(),
            &[subtree_proof.num_matching_rows_target()],
            subtree_proof.to_ops_raw(),
            subtree_proof.to_index_value_raw(),
            &node_min.to_targets(),
            &node_max.to_targets(),
            subtree_proof.to_index_ids_raw(),
            &min_query.to_targets(),
            &max_query.to_targets(),
            &[*subtree_proof.to_overflow_raw()],
            subtree_proof.to_computational_hash_raw(),
            subtree_proof.to_placeholder_hash_raw(),
        )
        .register(b);

        SubtreeProvenSinglePathNodeWires {
            left_child_min,
            left_child_max,
            left_child_value,
            left_tree_hash,
            left_grand_children,
            right_child_min,
            right_child_max,
            right_child_value,
            right_tree_hash,
            right_grand_children,
            left_child_exists,
            right_child_exists,
            is_rows_tree_node,
            min_query,
            max_query,
        }
    }

    fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &SubtreeProvenSinglePathNodeWires<MAX_NUM_RESULTS>,
    ) {
        [
            (&wires.left_child_min, self.left_child_min),
            (&wires.left_child_max, self.left_child_max),
            (&wires.left_child_value, self.left_child_value),
            (&wires.right_child_min, self.right_child_min),
            (&wires.right_child_max, self.right_child_max),
            (&wires.right_child_value, self.right_child_value),
            (&wires.min_query, self.min_query),
            (&wires.max_query, self.max_query),
        ]
        .iter()
        .for_each(|(t, v)| pw.set_u256_target(t, *v));
        [
            (wires.left_tree_hash, self.left_tree_hash),
            (wires.right_tree_hash, self.right_tree_hash),
        ]
        .iter()
        .for_each(|(t, v)| pw.set_hash_target(*t, *v));
        wires
            .left_grand_children
            .iter()
            .zip(self.left_grand_children)
            .for_each(|(t, v)| pw.set_hash_target(*t, v));
        wires
            .right_grand_children
            .iter()
            .zip(self.right_grand_children)
            .for_each(|(t, v)| pw.set_hash_target(*t, v));
        [
            (wires.left_child_exists, self.left_child_exists),
            (wires.right_child_exists, self.right_child_exists),
            (wires.is_rows_tree_node, self.is_rows_tree_node),
        ]
        .iter()
        .for_each(|(t, v)| pw.set_bool_target(*t, *v));
    }
}

pub(crate) const NUM_VERIFIED_PROOFS: usize = 1;

impl<const MAX_NUM_RESULTS: usize> CircuitLogicWires<F, D, NUM_VERIFIED_PROOFS>
    for SubtreeProvenSinglePathNodeWires<MAX_NUM_RESULTS>
{
    type CircuitBuilderParams = ();
    type Inputs = SubtreeProvenSinglePathNodeCircuit<MAX_NUM_RESULTS>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F, MAX_NUM_RESULTS>::total_len();

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; NUM_VERIFIED_PROOFS],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let child_proof = PublicInputs::from_slice(&verified_proofs[0].public_inputs);

        Self::Inputs::build(builder, &child_proof)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mp2_common::{utils::ToFields, C};
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::gen_random_field_hash,
    };
    use plonky2::plonk::config::Hasher;
    use rand::{thread_rng, Rng};

    use crate::query::{
        aggregation::tests::{random_aggregation_operations, random_aggregation_public_inputs},
        PI_LEN,
    };

    const MAX_NUM_RESULTS: usize = 20;

    #[derive(Clone, Debug)]
    struct TestSubtreeProvenSinglePathNodeCircuit<'a> {
        c: SubtreeProvenSinglePathNodeCircuit<MAX_NUM_RESULTS>,
        subtree_proof: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestSubtreeProvenSinglePathNodeCircuit<'a> {
        type Wires = (
            SubtreeProvenSinglePathNodeWires<MAX_NUM_RESULTS>,
            Vec<Target>,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let subtree_proof = b
                .add_virtual_target_arr::<{ PI_LEN::<MAX_NUM_RESULTS> }>()
                .to_vec();
            let pi = PublicInputs::<Target, MAX_NUM_RESULTS>::from_slice(&subtree_proof);

            let wires = SubtreeProvenSinglePathNodeCircuit::build(b, &pi);

            (wires, subtree_proof)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);
            pw.set_target_arr(&wires.1, &self.subtree_proof);
        }
    }

    fn test_subtree_proven_single_path_node_circuit(
        is_rows_tree_node: bool,
        left_child_exists: bool,
        right_child_exists: bool,
    ) {
        // Generate the random operations.
        let ops: [_; MAX_NUM_RESULTS] = random_aggregation_operations();

        // Build the subtree proof.
        let [subtree_proof] = random_aggregation_public_inputs(&ops);
        let subtree_pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&subtree_proof);

        let index_ids = subtree_pi.index_ids();
        let index_value = subtree_pi.index_value();

        // Construct the witness.
        let mut rng = thread_rng();
        let [left_child_min, mut left_child_max, left_child_value, mut right_child_min, right_child_max, right_child_value] =
            array::from_fn(|_| U256::from_limbs(rng.gen::<[u64; 4]>()));
        let left_tree_hash = gen_random_field_hash();
        let left_grand_children: [HashOut<F>; 2] = array::from_fn(|_| gen_random_field_hash());
        let right_tree_hash = gen_random_field_hash();
        let right_grand_children: [HashOut<F>; 2] = array::from_fn(|_| gen_random_field_hash());
        let mut min_query = U256::from(100);
        let mut max_query = U256::from(200);

        if is_rows_tree_node {
            min_query = subtree_pi.min_query_value();
            max_query = subtree_pi.max_query_value();
        } else {
            if min_query > index_value {
                min_query = index_value - U256::from(1);
            }
            if max_query < index_value {
                max_query = index_value + U256::from(1);
            }
        }

        if left_child_exists {
            left_child_max = min_query - U256::from(1);
        }

        if right_child_exists {
            right_child_min = max_query + U256::from(1);
        }

        // Construct the test circuit.
        let test_circuit = TestSubtreeProvenSinglePathNodeCircuit {
            c: SubtreeProvenSinglePathNodeCircuit {
                left_child_min,
                left_child_max,
                left_child_value,
                left_tree_hash,
                left_grand_children,
                right_child_min,
                right_child_max,
                right_child_value,
                right_tree_hash,
                right_grand_children,
                left_child_exists,
                right_child_exists,
                is_rows_tree_node,
                min_query,
                max_query,
            },
            subtree_proof: &subtree_proof,
        };

        // Proof for the test circuit.
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&proof.public_inputs);

        let node_value = if is_rows_tree_node {
            subtree_pi.min_value()
        } else {
            index_value
        };
        let node_min = if left_child_exists {
            left_child_min
        } else {
            node_value
        };
        let node_max = if right_child_exists {
            right_child_max
        } else {
            node_value
        };
        // Check the public inputs.
        // Tree hash
        {
            let column_id = if is_rows_tree_node {
                index_ids[1]
            } else {
                index_ids[0]
            };

            let empty_hash = empty_poseidon_hash();
            // H(left_grandchild_1||left_grandchild_2||left_min||left_max||column_id||left_value||left_subtree_hash)
            let left_child_inputs: Vec<_> = left_grand_children[0]
                .to_fields()
                .into_iter()
                .chain(left_grand_children[1].to_fields())
                .chain(left_child_min.to_fields())
                .chain(left_child_max.to_fields())
                .chain(iter::once(column_id))
                .chain(left_child_value.to_fields())
                .chain(left_tree_hash.to_fields())
                .collect();
            let left_hash_exists = H::hash_no_pad(&left_child_inputs);
            let left_child_hash = if left_child_exists {
                left_hash_exists
            } else {
                *empty_hash
            };
            // H(right_grandchild_1||right_grandchild_2||right_min||right_max||column_id||right_value||right_subtree_hash)
            let right_child_inputs: Vec<_> = right_grand_children[0]
                .to_fields()
                .into_iter()
                .chain(right_grand_children[1].to_fields())
                .chain(right_child_min.to_fields())
                .chain(right_child_max.to_fields())
                .chain(iter::once(column_id))
                .chain(right_child_value.to_fields())
                .chain(right_tree_hash.to_fields())
                .collect();
            let right_hash_exists = H::hash_no_pad(&right_child_inputs);
            let right_child_hash = if right_child_exists {
                right_hash_exists
            } else {
                *empty_hash
            };

            let node_hash_input: Vec<_> = left_child_hash
                .to_fields()
                .into_iter()
                .chain(right_child_hash.to_fields())
                .chain(node_min.to_fields())
                .chain(node_max.to_fields())
                .chain(iter::once(column_id))
                .chain(node_value.to_fields())
                .chain(subtree_pi.tree_hash().to_fields())
                .collect();
            let exp_hash = H::hash_no_pad(&node_hash_input);

            assert_eq!(pi.tree_hash(), exp_hash);
        }
        // Output values
        assert_eq!(pi.to_values_raw(), subtree_pi.to_values_raw());
        // Count
        assert_eq!(pi.num_matching_rows(), subtree_pi.num_matching_rows());
        // Operation IDs
        assert_eq!(pi.operation_ids(), subtree_pi.operation_ids());
        // Index value
        assert_eq!(pi.index_value(), index_value);
        // Minimum value
        assert_eq!(pi.min_value(), node_min);
        // Maximum value
        assert_eq!(pi.max_value(), node_max);
        // Index IDs
        assert_eq!(pi.index_ids(), index_ids);
        // Minimum query
        assert_eq!(pi.min_query_value(), min_query);
        // Maximum query
        assert_eq!(pi.max_query_value(), max_query);
        // Overflow flag
        assert_eq!(pi.overflow_flag(), subtree_pi.overflow_flag());
        // Computational hash
        assert_eq!(pi.computational_hash(), subtree_pi.computational_hash());
        // Placeholder hash
        assert_eq!(pi.placeholder_hash(), subtree_pi.placeholder_hash());
    }

    #[test]
    fn test_subtree_proven_node_for_row_node_with_no_child() {
        test_subtree_proven_single_path_node_circuit(true, false, false);
    }
    #[test]
    fn test_subtree_proven_node_for_row_node_with_left_child() {
        test_subtree_proven_single_path_node_circuit(true, true, false);
    }
    #[test]
    fn test_subtree_proven_node_for_row_node_with_right_child() {
        test_subtree_proven_single_path_node_circuit(true, false, true);
    }
    #[test]
    fn test_subtree_proven_node_for_row_node_with_both_children() {
        test_subtree_proven_single_path_node_circuit(true, true, true);
    }
    #[test]
    fn test_subtree_proven_node_for_index_node_with_no_child() {
        test_subtree_proven_single_path_node_circuit(false, false, false);
    }
    #[test]
    fn test_subtree_proven_node_for_index_node_with_left_child() {
        test_subtree_proven_single_path_node_circuit(false, true, false);
    }
    #[test]
    fn test_subtree_proven_node_for_index_node_with_right_child() {
        test_subtree_proven_single_path_node_circuit(false, false, true);
    }
    #[test]
    fn test_subtree_proven_node_for_index_node_with_both_children() {
        test_subtree_proven_single_path_node_circuit(false, true, true);
    }
}
