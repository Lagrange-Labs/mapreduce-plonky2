use crate::results_tree::extraction::PublicInputs;
use alloy::primitives::U256;
use anyhow::Result;
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
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
pub struct IntermediateFullNodeWires<const MAX_NUM_RESULTS: usize> {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    left_child_exists: BoolTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    right_child_exists: BoolTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_rows_tree: BoolTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntermediateFullNodeCircuit<const MAX_NUM_RESULTS: usize> {
    /// Boolean flag specifying whether the node has a left child
    pub(crate) left_child_exists: bool,
    /// Boolean flag specifying whether the node has a right child
    pub(crate) right_child_exists: bool,
    /// Boolean flag specifying whether  this node is a node of rows tree or of the index tree
    pub(crate) is_rows_tree: bool,
}

impl<const MAX_NUM_RESULTS: usize> IntermediateFullNodeCircuit<MAX_NUM_RESULTS> {
    pub fn build(
        b: &mut CBuilder,
        subtree_proof: &PublicInputs<Target, MAX_NUM_RESULTS>,
        child_proofs: &[PublicInputs<Target, MAX_NUM_RESULTS>; 2],
    ) -> IntermediateFullNodeWires<MAX_NUM_RESULTS> {
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
        // is_rows_tree == is_rows_tree AND p.I == p1.I AND p.I == p2.I
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
        let right_min = b.select(
            right_child_exists,
            child_proof2.min_counter_target(),
            max_plus_one,
        );
        // assert max_left + 1 == p.min_counter
        let left_plus_one = b.add(max_left, one);
        b.connect(left_plus_one, subtree_proof.min_counter_target());
        // assert p.max_counter + 1 == right_min
        let max_cnt_plus_one = b.add(subtree_proof.max_counter_target(), one);
        b.connect(max_cnt_plus_one, right_min);

        // aggregate accumulators
        let left_acc = b.select_accumulator(
            left_child_exists,
            &child_proof1.accumulator_target(),
            &curve_zero,
        );
        let right_acc = b.select_accumulator(
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

        // TODO(Insun35): add constraints for the following
        // assert p1.index_ids == p2.index_ids == p.index_ids
        // p1.offset_range_min == p2.offset_range_min == p.offset_range_min
        // p1.offset_range_max == p2.offset_range_max == p.offset_range_max

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

        IntermediateFullNodeWires {
            left_child_exists,
            right_child_exists,
            is_rows_tree,
        }
    }

    fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &IntermediateFullNodeWires<MAX_NUM_RESULTS>,
    ) {
        pw.set_bool_target(wires.left_child_exists, self.left_child_exists);
        pw.set_bool_target(wires.right_child_exists, self.right_child_exists);
        pw.set_bool_target(wires.is_rows_tree, self.is_rows_tree);
    }
}

/// Subtree proof number = 1, child proof number = 2
pub(crate) const NUM_VERIFIED_PROOFS: usize = 3;

impl<const MAX_NUM_RESULTS: usize> CircuitLogicWires<F, D, NUM_VERIFIED_PROOFS>
    for IntermediateFullNodeWires<MAX_NUM_RESULTS>
{
    type CircuitBuilderParams = ();
    type Inputs = IntermediateFullNodeCircuit<MAX_NUM_RESULTS>;

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

// TODO(Insun35): Add test
