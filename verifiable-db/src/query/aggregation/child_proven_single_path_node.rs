use std::iter;

use alloy::primitives::U256;
use anyhow::Result;
use mp2_common::{
    hash::hash_maybe_first,
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::ToTargets,
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

use crate::query::public_inputs::PublicInputs;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChildProvenSinglePathNodeWires<const MAX_NUM_RESULTS: usize> {
    value: UInt256Target,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    subtree_hash: HashOutTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    sibling_hash: HashOutTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_left_child: BoolTarget,
    unproven_min: UInt256Target,
    unproven_max: UInt256Target,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_rows_tree_node: BoolTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChildProvenSinglePathNodeCircuit<const MAX_NUM_RESULTS: usize> {
    /// Value stored in the current node
    pub(crate) value: U256,
    /// Hash of the row/rows tree stored in the current node
    pub(crate) subtree_hash: HashOut<F>,
    /// Hash of the sibling of the proven node child
    pub(crate) sibling_hash: HashOut<F>,
    /// Flag indicating whether the proven child is the left child or the right one
    pub(crate) is_left_child: bool,
    /// Minimum value of the indexed column to be employed to compute the hash of the current node
    pub(crate) unproven_min: U256,
    /// Maximum value of the indexed column to be employed to compute the hash of the current node
    pub(crate) unproven_max: U256,
    /// Boolean flag specifying whether the proof is being generated for a node
    /// in a rows tree of for a node in the index tree
    pub(crate) is_rows_tree_node: bool,
}

impl<const MAX_NUM_RESULTS: usize> ChildProvenSinglePathNodeCircuit<MAX_NUM_RESULTS> {
    pub fn build(
        b: &mut CBuilder,
        child_proof: &PublicInputs<Target, MAX_NUM_RESULTS>,
    ) -> ChildProvenSinglePathNodeWires<MAX_NUM_RESULTS> {
        let is_rows_tree_node = b.add_virtual_bool_target_safe();
        let is_left_child = b.add_virtual_bool_target_unsafe();
        let value = b.add_virtual_u256();
        let subtree_hash = b.add_virtual_hash();
        let sibling_hash = b.add_virtual_hash();
        let unproven_min = b.add_virtual_u256_unsafe();
        let unproven_max = b.add_virtual_u256_unsafe();

        let node_min = b.select_u256(
            is_left_child,
            &child_proof.min_value_target(),
            &unproven_min,
        );
        let node_max = b.select_u256(
            is_left_child,
            &unproven_max,
            &child_proof.max_value_target(),
        );
        let column_id = b.select(
            is_rows_tree_node,
            child_proof.index_ids_target()[1],
            child_proof.index_ids_target()[0],
        );
        // Compute the node hash:
        // node_hash = H(left_child_hash||right_child_hash||node_min||node_max||column_id||value||subtree_hash)
        let rest: Vec<_> = node_min
            .to_targets()
            .into_iter()
            .chain(node_max.to_targets())
            .chain(iter::once(column_id))
            .chain(value.to_targets())
            .chain(subtree_hash.elements)
            .collect();

        let node_hash = hash_maybe_first(
            b,
            is_left_child,
            sibling_hash.elements,
            child_proof.tree_hash_target().elements,
            &rest,
        );

        // if is_left_child:
        //   value > child_proof.max_query
        // else:
        //   value < child_proof.min_query
        let is_greater_than_max = b.is_greater_than_u256(&value, &child_proof.max_query_target());
        let is_less_than_min = b.is_less_than_u256(&value, &child_proof.min_query_target());
        let condition = b.select(
            is_left_child,
            is_greater_than_max.target,
            is_less_than_min.target,
        );
        let ttrue = b._true();
        b.connect(condition, ttrue.target);

        // Register the public inputs.
        PublicInputs::<_, MAX_NUM_RESULTS>::new(
            &node_hash.to_targets(),
            child_proof.to_values_raw(),
            &[child_proof.num_matching_rows_target()],
            child_proof.to_ops_raw(),
            child_proof.to_index_value_raw(),
            &node_min.to_targets(),
            &node_max.to_targets(),
            child_proof.to_index_ids_raw(),
            child_proof.to_min_query_raw(),
            child_proof.to_max_query_raw(),
            &[*child_proof.to_overflow_raw()],
            child_proof.to_computational_hash_raw(),
            child_proof.to_placeholder_hash_raw(),
        )
        .register(b);

        ChildProvenSinglePathNodeWires {
            value,
            subtree_hash,
            sibling_hash,
            is_left_child,
            unproven_min,
            unproven_max,
            is_rows_tree_node,
        }
    }

    fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &ChildProvenSinglePathNodeWires<MAX_NUM_RESULTS>,
    ) {
        pw.set_u256_target(&wires.value, self.value);
        pw.set_hash_target(wires.subtree_hash, self.subtree_hash);
        pw.set_hash_target(wires.sibling_hash, self.sibling_hash);
        pw.set_bool_target(wires.is_left_child, self.is_left_child);
        pw.set_u256_target(&wires.unproven_min, self.unproven_min);
        pw.set_u256_target(&wires.unproven_max, self.unproven_max);
        pw.set_bool_target(wires.is_rows_tree_node, self.is_rows_tree_node);
    }
}

pub(crate) const NUM_VERIFIED_PROOFS: usize = 1;

impl<const MAX_NUM_RESULTS: usize> CircuitLogicWires<F, D, NUM_VERIFIED_PROOFS>
    for ChildProvenSinglePathNodeWires<MAX_NUM_RESULTS>
{
    type CircuitBuilderParams = ();
    type Inputs = ChildProvenSinglePathNodeCircuit<MAX_NUM_RESULTS>;

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
    use crate::{
        query::pi_len,
        test_utils::{random_aggregation_operations, random_aggregation_public_inputs},
    };
    use mp2_common::{poseidon::H, utils::ToFields, C, D};
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::gen_random_field_hash,
    };
    use plonky2::{iop::witness::WitnessWrite, plonk::config::Hasher};
    use rand::{thread_rng, Rng};

    const MAX_NUM_RESULTS: usize = 20;

    #[derive(Clone, Debug)]
    struct TestChildProvenSinglePathNodeCircuit<'a> {
        c: ChildProvenSinglePathNodeCircuit<MAX_NUM_RESULTS>,
        child_proof: &'a [F],
    }

    impl UserCircuit<F, D> for TestChildProvenSinglePathNodeCircuit<'_> {
        type Wires = (ChildProvenSinglePathNodeWires<MAX_NUM_RESULTS>, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let child_proof = b
                .add_virtual_target_arr::<{ pi_len::<MAX_NUM_RESULTS>() }>()
                .to_vec();
            let pi = PublicInputs::<Target, MAX_NUM_RESULTS>::from_slice(&child_proof);

            let wires = ChildProvenSinglePathNodeCircuit::build(b, &pi);

            (wires, child_proof)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);
            pw.set_target_arr(&wires.1, self.child_proof);
        }
    }

    fn test_child_proven_single_path_node_circuit(is_rows_tree_node: bool, is_left_child: bool) {
        // Generate the random operations.
        let ops: [_; MAX_NUM_RESULTS] = random_aggregation_operations();

        // Build the child proof.
        let [child_proof] = random_aggregation_public_inputs(&ops);
        let child_pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&child_proof);

        let index_ids = child_pi.index_ids();
        let index_value = child_pi.index_value();
        let min_query = child_pi.min_query_value();
        let max_query = child_pi.max_query_value();

        // Construct the witness.
        let mut rng = thread_rng();
        let mut value = U256::from_limbs(rng.gen::<[u64; 4]>());
        let subtree_hash = gen_random_field_hash();
        let sibling_hash = gen_random_field_hash();
        let unproven_min = index_value
            .checked_sub(U256::from(100))
            .unwrap_or(index_value);
        let unproven_max = index_value
            .checked_add(U256::from(100))
            .unwrap_or(index_value);

        if is_left_child {
            while value <= max_query {
                value = U256::from_limbs(rng.gen::<[u64; 4]>());
            }
        } else {
            while value >= min_query {
                value = U256::from_limbs(rng.gen::<[u64; 4]>());
            }
        }

        // Construct the test circuit.
        let test_circuit = TestChildProvenSinglePathNodeCircuit {
            c: ChildProvenSinglePathNodeCircuit {
                value,
                subtree_hash,
                sibling_hash,
                is_left_child,
                unproven_min,
                unproven_max,
                is_rows_tree_node,
            },
            child_proof: &child_proof,
        };

        // Proof for the test circuit.
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&proof.public_inputs);

        let [node_min, node_max] = if is_left_child {
            [child_pi.min_value(), unproven_max]
        } else {
            [unproven_min, child_pi.max_value()]
        };
        // Check the public inputs.
        // Tree hash
        {
            let column_id = if is_rows_tree_node {
                index_ids[1]
            } else {
                index_ids[0]
            };

            let child_hash = child_pi.tree_hash();
            let [left_child_hash, right_child_hash] = if is_left_child {
                [child_hash, sibling_hash]
            } else {
                [sibling_hash, child_hash]
            };

            // H(left_child_hash||right_child_hash||node_min||node_max||column_id||value||subtree_hash)
            let input: Vec<_> = left_child_hash
                .to_fields()
                .into_iter()
                .chain(right_child_hash.to_fields())
                .chain(node_min.to_fields())
                .chain(node_max.to_fields())
                .chain(iter::once(column_id))
                .chain(value.to_fields())
                .chain(subtree_hash.to_fields())
                .collect();
            let exp_hash = H::hash_no_pad(&input);

            assert_eq!(pi.tree_hash(), exp_hash);
        }
        // Output values
        assert_eq!(pi.to_values_raw(), child_pi.to_values_raw());
        // Count
        assert_eq!(pi.num_matching_rows(), child_pi.num_matching_rows());
        // Operation IDs
        assert_eq!(pi.operation_ids(), child_pi.operation_ids());
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
        assert_eq!(pi.overflow_flag(), child_pi.overflow_flag());
        // Computational hash
        assert_eq!(pi.computational_hash(), child_pi.computational_hash());
        // Placeholder hash
        assert_eq!(pi.placeholder_hash(), child_pi.placeholder_hash());
    }

    #[test]
    fn test_child_proven_node_for_row_node_with_left_child() {
        test_child_proven_single_path_node_circuit(true, true);
    }
    #[test]
    fn test_child_proven_node_for_row_node_with_right_child() {
        test_child_proven_single_path_node_circuit(true, false);
    }
    #[test]
    fn test_child_proven_node_for_index_node_with_left_child() {
        test_child_proven_single_path_node_circuit(false, true);
    }
    #[test]
    fn test_child_proven_node_for_index_node_with_right_child() {
        test_child_proven_single_path_node_circuit(false, false);
    }
}
