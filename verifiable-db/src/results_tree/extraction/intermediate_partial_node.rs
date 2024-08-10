use crate::results_tree::extraction::PublicInputs;
use alloy::primitives::U256;
use anyhow::Result;
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    hash::hash_maybe_first,
    poseidon::{empty_poseidon_hash, H},
    public_inputs::PublicInputCommon,
    serialization::{deserialize, deserialize_long_array, serialize, serialize_long_array},
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{SelectAccumulator, SelectHashBuilder, ToTargets},
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
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::iter;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntermediatePartialNodeWires<const MAX_NUM_RESULTS: usize> {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_left_child_included: BoolTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_rows_tree: BoolTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntermediatePartialNodeCircuit<const MAX_NUM_RESULTS: usize> {
    /// Boolean flag specifying whether the included child is the left child or not
    pub(crate) is_left_child_included: bool,
    /// Boolean flag specifying whether the current node is a node
    /// of a rows tree or of the index tree
    pub(crate) is_rows_tree: bool,
}

impl<const MAX_NUM_RESULTS: usize> IntermediatePartialNodeCircuit<MAX_NUM_RESULTS> {
    pub fn build(
        b: &mut CBuilder,
        subtree_proof: &PublicInputs<Target, MAX_NUM_RESULTS>,
        included_chid_proof: &PublicInputs<Target, MAX_NUM_RESULTS>,
        excluded_child_proof: &PublicInputs<Target, MAX_NUM_RESULTS>,
    ) -> IntermediatePartialNodeWires<MAX_NUM_RESULTS> {
        let one = b.one();

        let [is_left_child_included, is_rows_tree] =
            [0; 2].map(|_| b.add_virtual_bool_target_safe());

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
            is_left_child_included,
            &included_chid_proof.min_value_target(),
            &excluded_child_proof.min_value_target(),
        );
        let node_max = b.select_u256(
            is_left_child_included,
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
            is_left_child_included,
            excluded_child_proof.tree_hash_target().elements,
            included_chid_proof.tree_hash_target().elements,
            &rest,
        );

        // Ensure the proofs in the same record subtree are employing the same value
        // of the indexed item
        // (is_rows_tree == is_rows_tree) AND (pR.I == pI.I)
        let is_equal = b.is_equal_u256(
            &subtree_proof.primary_index_value_target(),
            &included_chid_proof.primary_index_value_target(),
        );
        let condition = b.and(is_equal, is_rows_tree);
        b.connect(condition.target, is_rows_tree.target);

        // Enforce consistency of counters
        let max_left = b.select(
            is_left_child_included,
            included_chid_proof.max_counter_target(),
            excluded_child_proof.max_counter_target(),
        );
        let right_min = b.select(
            is_left_child_included,
            excluded_child_proof.min_counter_target(),
            included_chid_proof.min_counter_target(),
        );
        // Verifying proof guarantees:
        // If the excluded child has N rows in its subtree,
        // then pC.max_counter - pC.min_counter == N
        // assert max_left + 1 == pR.min_counter
        let left_plus_one = b.add(max_left, one);
        b.connect(left_plus_one, subtree_proof.min_counter_target());
        // assert pR.max_counter + 1 == right_min
        let max_cnt_plus_one = b.add(subtree_proof.max_counter_target(), one);
        b.connect(max_cnt_plus_one, right_min);

        // TODO(Insun35): maybe offset_range_(min/max) should be a Target (not UInt256Target)
        // Ensure that the subtree rooted in the sibling of the included child
        // contains only records outside of [query_min; query_max] range
        // (left == left) AND (pC.min_counter > offset_range_max)
        // TODO(Insun35): implement this constraint
        // (NOT(left) == NOT(left)) AND( pC.max_counter < offset_range_min)
        // TODO(Insun35): implement this constraint

        // Compute min_counter and max_counter for current node
        let min_counter = b.select(
            is_left_child_included,
            included_chid_proof.min_counter_target(),
            excluded_child_proof.min_counter_target(),
        );
        let max_counter = b.select(
            is_left_child_included,
            excluded_child_proof.max_counter_target(),
            included_chid_proof.max_counter_target(),
        );

        // TODO(Insun35): add constraints for the following
        // assert pR.index_ids == pI.index_ids
        // assert pI.offset_range_min == pR.offset_range_min
        // assert pI.offset_range_max == pR.offset_range_max

        // pR.D + pI.D
        let accumulator = b.add_curve_point(&[
            subtree_proof.accumulator_target(),
            included_chid_proof.accumulator_target(),
        ]);

        // Register the public inputs.
        PublicInputs::<_, MAX_NUM_RESULTS>::new(
            &node_hash.to_targets(),
            &node_min.to_targets(),
            &node_max.to_targets(),
            subtree_proof.to_primary_index_value_raw(),
            subtree_proof.to_index_ids_raw(),
            &[min_counter],
            &[max_counter],
            subtree_proof.to_offset_range_min_raw(),
            subtree_proof.to_offset_range_max_raw(),
            &accumulator.to_targets(),
        )
        .register(b);

        IntermediatePartialNodeWires {
            is_left_child_included,
            is_rows_tree,
        }
    }
}
