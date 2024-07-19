//! Module handling the full node with one child for query aggregation circuits

use crate::simple_query_circuits::{
    aggregation::output_computation::compute_output_item, public_inputs::PublicInputs,
};
use alloy::primitives::U256;
use anyhow::Result;
use mp2_common::{
    array::Array,
    hash::hash_maybe_first,
    poseidon::empty_poseidon_hash,
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

/// Full node wires with one child
/// The constant generic parameter is only used for impl `CircuitLogicWires`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullNodeWithOneChildWires<const MAX_NUM_RESULTS: usize> {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_rows_tree_node: BoolTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_left_child: BoolTarget,
    min_query: UInt256Target,
    max_query: UInt256Target,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullNodeWithOneChildCircuit<const MAX_NUM_RESULTS: usize> {
    /// The flag specified if the proof is generated for a node in a rows tree or
    /// for a node in the index tree
    pub(crate) is_rows_tree_node: bool,
    /// The flag specified if the child node is the left or right child
    pub(crate) is_left_child: bool,
    /// Minimum range bound specified in the query for the indexed column
    /// It's a range bound for the primary indexed column for index tree,
    /// and secondary indexed column for rows tree.
    pub(crate) min_query: U256,
    /// Maximum range bound specified in the query for the indexed column
    pub(crate) max_query: U256,
}

impl<const MAX_NUM_RESULTS: usize> FullNodeWithOneChildCircuit<MAX_NUM_RESULTS> {
    pub fn build(
        b: &mut CBuilder,
        query_proof: &PublicInputs<Target, MAX_NUM_RESULTS>,
        child_proof: &PublicInputs<Target, MAX_NUM_RESULTS>,
    ) -> FullNodeWithOneChildWires<MAX_NUM_RESULTS>
    where
        [(); MAX_NUM_RESULTS - 1]:,
    {
        let zero = b.zero();
        let empty_hash = b.constant_hash(*empty_poseidon_hash());

        let [is_rows_tree_node, is_left_child] = [0; 2].map(|_| b.add_virtual_bool_target_safe());
        let [min_query, max_query] = [0; 2].map(|_| b.add_virtual_u256_unsafe());

        // Choose the column ID and node value to be hashed depending on which tree
        // the current node belongs to.
        let index_ids = query_proof.index_ids_target();
        let column_id = b.select(is_rows_tree_node, index_ids[1], index_ids[0]);
        let index_value = query_proof.index_value_target();
        let node_value = b.select_u256(
            is_rows_tree_node,
            &query_proof.min_value_target(),
            &index_value,
        );

        let node_min = b.select_u256(is_left_child, &child_proof.min_value_target(), &node_value);
        let node_max = b.select_u256(is_left_child, &node_value, &child_proof.max_value_target());

        // Compute the node hash:
        // H(left_child.H || right_child.H || node_min || node_max || column_id || node_value || p.H))
        let rest: Vec<_> = node_min
            .to_targets()
            .into_iter()
            .chain(node_max.to_targets())
            .chain(iter::once(column_id))
            .chain(node_value.to_targets())
            .chain(query_proof.tree_hash_target().to_targets())
            .collect();
        let node_hash = hash_maybe_first(
            b,
            is_left_child,
            empty_hash.elements,
            child_proof.tree_hash_target().elements,
            &rest,
        );

        // Ensure the proofs in the same subtree are employing the same value
        // of the indexed column:
        // is_rows_tree_node == is_rows_tree_node AND p.I == child.I
        let is_equal = b.is_equal_u256(&index_value, &child_proof.index_value_target());
        let is_equal = b.and(is_equal, is_rows_tree_node);
        b.connect(is_equal.target, is_rows_tree_node.target);

        // Ensure that the all proofs of the subtree rooted in this node has
        // employed the same value for the indexed column, and the value of the
        // indexed column for all the records stored in the rows tree found in
        // this node is within the range specified by the query:
        // NOT(is_rows_tree_node) ==
        //      NOT(is_row_tree_node) AND
        //      p.I >= MIN_query AND
        //      p.I <= MAX_query
        // => is_rows_tree_node ==
        //      is_row_tree_node OR
        //      p.I < MIN_query OR
        //      p.I > MAX_query
        let is_less_than_min = b.is_less_than_u256(&index_value, &min_query);
        let is_greater_than_max = b.is_less_than_u256(&max_query, &index_value);
        let is_diff = b.or(is_less_than_min, is_greater_than_max);
        let is_diff = b.or(is_diff, is_rows_tree_node);
        b.connect(is_diff.target, is_rows_tree_node.target);

        // Aggregate the output values of children and the overflow number.
        let mut num_overflows = zero;
        let mut aggregated_values = vec![];
        for i in 0..MAX_NUM_RESULTS {
            let (mut output, overflow) = compute_output_item(b, i, &[query_proof, child_proof]);

            aggregated_values.append(&mut output);
            num_overflows = b.add(num_overflows, overflow);
        }

        // p.index_ids == child.index_ids
        let index_ids = Array::from(index_ids);
        index_ids.enforce_equal(b, &Array::from(child_proof.index_ids_target()));

        // p.C == child.C
        b.connect_hashes(
            query_proof.computational_hash_target(),
            child_proof.computational_hash_target(),
        );

        // p.H_p == child.H_p
        b.connect_hashes(
            query_proof.placeholder_hash_target(),
            child_proof.placeholder_hash_target(),
        );

        // child.MIN_I = MIN_query
        b.enforce_equal_u256(&min_query, &child_proof.min_query_target());

        // child.MAX_I == MAX_query
        b.enforce_equal_u256(&max_query, &child_proof.max_query_target());

        // If the query proof is generated from a rows tree node, the query bounds must be same:
        // is_row_tree_node = is_row_tree_node AND MIN_query == p.MIN_I AND MAX_query == p.MAX_I
        let is_min_query_equal = b.is_equal_u256(&min_query, &query_proof.min_query_target());
        let is_max_query_equal = b.is_equal_u256(&max_query, &query_proof.max_query_target());
        let is_equal = b.and(is_min_query_equal, is_max_query_equal);
        let is_equal = b.and(is_equal, is_rows_tree_node);
        b.connect(is_equal.target, is_rows_tree_node.target);

        // count = current.count + child.count
        let count = b.add(
            query_proof.num_matching_rows_target(),
            child_proof.num_matching_rows_target(),
        );

        // overflow = (pC.overflow + pR.overflow + num_overflows) != 0
        let overflow = b.add_many([
            query_proof.to_overflow_raw(),
            child_proof.to_overflow_raw(),
            &num_overflows,
        ]);
        let overflow = b.is_not_equal(overflow, zero);

        // Register the public inputs.
        PublicInputs::<_, MAX_NUM_RESULTS>::new(
            &node_hash.to_targets(),
            &aggregated_values.as_slice(),
            &[count],
            query_proof.to_ops_raw(),
            query_proof.to_index_value_raw(),
            &node_min.to_targets(),
            &node_max.to_targets(),
            query_proof.to_index_ids_raw(),
            &min_query.to_targets(),
            &max_query.to_targets(),
            &[overflow.target],
            query_proof.to_computational_hash_raw(),
            query_proof.to_placeholder_hash_raw(),
        )
        .register(b);

        FullNodeWithOneChildWires {
            is_rows_tree_node,
            is_left_child,
            min_query,
            max_query,
        }
    }

    fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &FullNodeWithOneChildWires<MAX_NUM_RESULTS>,
    ) {
        pw.set_bool_target(wires.is_rows_tree_node, self.is_rows_tree_node);
        pw.set_bool_target(wires.is_left_child, self.is_left_child);
        pw.set_u256_target(&wires.min_query, self.min_query);
        pw.set_u256_target(&wires.max_query, self.max_query);
    }
}

/// Query proof number = 1, child proof number = 1
pub(crate) const NUM_VERIFIED_PROOFS: usize = 2;

impl<const MAX_NUM_RESULTS: usize> CircuitLogicWires<F, D, NUM_VERIFIED_PROOFS>
    for FullNodeWithOneChildWires<MAX_NUM_RESULTS>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    type CircuitBuilderParams = ();
    type Inputs = FullNodeWithOneChildCircuit<MAX_NUM_RESULTS>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F, MAX_NUM_RESULTS>::total_len();

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; NUM_VERIFIED_PROOFS],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        // The first one is the query proof, and the second is the child proof.
        let [query_proof, child_proof] =
            verified_proofs.map(|p| PublicInputs::from_slice(&p.public_inputs));

        Self::Inputs::build(builder, &query_proof, &child_proof)
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
        aggregation::tests::{
            compute_output_item_value, random_aggregation_operations,
            random_aggregation_public_inputs,
        },
        public_inputs::QueryPublicInputs,
        PI_LEN,
    };
    use mp2_common::{poseidon::H, utils::ToFields, C};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{iop::witness::WitnessWrite, plonk::config::Hasher};
    use std::array;

    const MAX_NUM_RESULTS: usize = 20;

    #[derive(Clone, Debug)]
    struct TestFullNodeWithOneChildCircuit<'a> {
        c: FullNodeWithOneChildCircuit<MAX_NUM_RESULTS>,
        query_proof: &'a [F],
        child_proof: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestFullNodeWithOneChildCircuit<'a> {
        // Circuit wires + query proof + child proof
        type Wires = (
            FullNodeWithOneChildWires<MAX_NUM_RESULTS>,
            Vec<Target>,
            Vec<Target>,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let proofs = array::from_fn(|_| {
                b.add_virtual_target_arr::<{ PI_LEN::<MAX_NUM_RESULTS> }>()
                    .to_vec()
            });
            let [query_pi, child_pi] =
                array::from_fn(|i| PublicInputs::<Target, MAX_NUM_RESULTS>::from_slice(&proofs[i]));

            let wires = FullNodeWithOneChildCircuit::build(b, &query_pi, &child_pi);

            let [query_proof, child_proof] = proofs;

            (wires, query_proof, child_proof)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);
            pw.set_target_arr(&wires.1, self.query_proof);
            pw.set_target_arr(&wires.2, self.child_proof);
        }
    }

    fn test_full_node_with_one_child_circuit(is_rows_tree_node: bool, is_left_child: bool) {
        // Construct the witness.
        let min_query = U256::from(100);
        let max_query = U256::from(200);

        // Generate the random operations.
        let ops: [_; MAX_NUM_RESULTS] = random_aggregation_operations();

        // Build the proofs.
        let [mut query_proof, mut child_proof] = random_aggregation_public_inputs(ops);
        let [index_value_range, index_ids_range, min_query_range, max_query_range, c_hash_range, p_hash_range] =
            [
                QueryPublicInputs::IndexValue,
                QueryPublicInputs::IndexIds,
                QueryPublicInputs::MinQuery,
                QueryPublicInputs::MaxQuery,
                QueryPublicInputs::ComputationalHash,
                QueryPublicInputs::PlaceholderHash,
            ]
            .map(|input| PublicInputs::<F, MAX_NUM_RESULTS>::to_range(input));

        // Build the query public inputs.
        if is_rows_tree_node {
            // p.MIN_I == MIN_query AND p.MAX_I == MAX_query
            query_proof[min_query_range.clone()].copy_from_slice(&min_query.to_fields());
            query_proof[max_query_range.clone()].copy_from_slice(&max_query.to_fields());
        } else {
            // p.I >= MIN_query AND p.I <= MAX_query
            let index_value: U256 = (min_query + max_query) >> 1;
            query_proof[index_value_range.clone()].copy_from_slice(&index_value.to_fields());
        }
        let query_pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&query_proof);

        // Build the child public inputs.
        // child.index_ids == p.index_ids
        child_proof[index_ids_range].copy_from_slice(query_pi.to_index_ids_raw());
        // child.C == p.C
        child_proof[c_hash_range].copy_from_slice(query_pi.to_computational_hash_raw());
        // child.H_p == p.H_p
        child_proof[p_hash_range].copy_from_slice(query_pi.to_placeholder_hash_raw());
        // child.MIN_I == MIN_query
        child_proof[min_query_range.clone()].copy_from_slice(&min_query.to_fields());
        // child.MAX_I == MAX_query
        child_proof[max_query_range.clone()].copy_from_slice(&max_query.to_fields());
        if is_rows_tree_node {
            // child.I == p.I
            child_proof[index_value_range.clone()].copy_from_slice(query_pi.to_index_value_raw());
            // child.MIN_I == p.MIN_I
            child_proof[min_query_range].copy_from_slice(query_pi.to_min_query_raw());
            // child.MAX_I == p.MAX_I.
            child_proof[max_query_range].copy_from_slice(query_pi.to_max_query_raw());
        }
        let child_pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&child_proof);

        // Construct the expected public input values.
        let index_ids = query_pi.index_ids();
        let index_value = query_pi.index_value();
        let node_value = if is_rows_tree_node {
            query_pi.min_value()
        } else {
            index_value
        };
        let [node_min, node_max] = if is_left_child {
            [child_pi.min_value(), node_value]
        } else {
            [node_value, child_pi.max_value()]
        };

        // Construct the test circuit.
        let test_circuit = TestFullNodeWithOneChildCircuit {
            c: FullNodeWithOneChildCircuit {
                is_rows_tree_node,
                is_left_child,
                min_query,
                max_query,
            },
            query_proof: &query_proof,
            child_proof: &child_proof,
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
                .chain(query_pi.tree_hash().to_fields())
                .collect();
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.tree_hash(), exp_hash);
        }
        // Output values and overflow flag
        {
            let mut num_overflows = 0;
            let mut aggregated_values = vec![];

            for i in 0..MAX_NUM_RESULTS {
                let (mut output, overflow) = compute_output_item_value(i, &[&query_pi, &child_pi]);

                aggregated_values.append(&mut output);
                num_overflows += overflow;
            }

            assert_eq!(pi.to_values_raw(), aggregated_values);
            assert_eq!(
                pi.overflow_flag(),
                query_pi.overflow_flag() || child_pi.overflow_flag() || num_overflows != 0
            );
        }
        // Count
        assert_eq!(
            pi.num_matching_rows(),
            query_pi.num_matching_rows() + child_pi.num_matching_rows(),
        );
        // Operation IDs
        assert_eq!(pi.operation_ids(), query_pi.operation_ids());
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
        // Computational hash
        assert_eq!(pi.computational_hash(), query_pi.computational_hash());
        // Placeholder hash
        assert_eq!(pi.placeholder_hash(), query_pi.placeholder_hash());
    }

    #[test]
    fn test_query_agg_full_node_with_one_child_for_row_node_with_left_child() {
        test_full_node_with_one_child_circuit(true, true);
    }

    #[test]
    fn test_query_agg_full_node_with_one_child_for_row_node_with_right_child() {
        test_full_node_with_one_child_circuit(true, false);
    }

    #[test]
    fn test_query_agg_full_node_with_one_child_for_index_node_with_left_child() {
        test_full_node_with_one_child_circuit(false, true);
    }

    #[test]
    fn test_query_agg_full_node_with_one_child_for_index_node_with_right_child() {
        test_full_node_with_one_child_circuit(false, false);
    }
}
