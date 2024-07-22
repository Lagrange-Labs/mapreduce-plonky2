//! Module handling the partial node for query aggregation circuits

use crate::simple_query_circuits::{
    aggregation::{output_computation::compute_output_item, utils::constrain_input_proofs},
    public_inputs::PublicInputs,
};
use alloy::primitives::U256;
use anyhow::Result;
use mp2_common::{
    hash::hash_maybe_first,
    poseidon::H,
    public_inputs::PublicInputCommon,
    serialization::{deserialize, deserialize_array, serialize, serialize_array},
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
use std::{array, iter, slice};

/// Partial node wires
/// The constant generic parameter is only used for impl `CircuitLogicWires`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialNodeWires<const MAX_NUM_RESULTS: usize> {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_rows_tree_node: BoolTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_left_child: BoolTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    sibling_tree_hash: HashOutTarget,
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    sibling_child_hashes: [HashOutTarget; 2],
    sibling_value: UInt256Target,
    sibling_min: UInt256Target,
    sibling_max: UInt256Target,
    min_query: UInt256Target,
    max_query: UInt256Target,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialNodeCircuit<const MAX_NUM_RESULTS: usize> {
    /// The flag specified if the proof is generated for a node in a rows tree or
    /// for a node in the index tree
    pub(crate) is_rows_tree_node: bool,
    /// The flag indicating if the proven child is the left child or right child
    pub(crate) is_left_child: bool,
    /// Hash of the rows tree stored in the sibling of the proven child
    pub(crate) sibling_tree_hash: HashOut<F>,
    /// The child hashes of the proven child's sibling
    pub(crate) sibling_child_hashes: [HashOut<F>; 2],
    /// Value of the indexed column for the rows tree stored in the sibling of
    /// the proven child
    pub(crate) sibling_value: U256,
    /// Minimum value of the indexed column for the subtree rooted in the sibling
    /// of the proven child
    pub(crate) sibling_min: U256,
    /// Maximum value of the indexed column for the subtree rooted in the sibling
    /// of the proven child
    pub(crate) sibling_max: U256,
    /// Minimum range bound specified in the query for the indexed column
    /// It's a range bound for the primary indexed column for index tree,
    /// and secondary indexed column for rows tree.
    pub(crate) min_query: U256,
    /// Maximum range bound specified in the query for the indexed column
    pub(crate) max_query: U256,
}

impl<const MAX_NUM_RESULTS: usize> PartialNodeCircuit<MAX_NUM_RESULTS> {
    pub fn build(
        b: &mut CBuilder,
        subtree_proof: &PublicInputs<Target, MAX_NUM_RESULTS>,
        child_proof: &PublicInputs<Target, MAX_NUM_RESULTS>,
    ) -> PartialNodeWires<MAX_NUM_RESULTS>
    where
        [(); MAX_NUM_RESULTS - 1]:,
    {
        let ttrue = b._true();
        let zero = b.zero();

        let is_rows_tree_node = b.add_virtual_bool_target_safe();
        let is_left_child = b.add_virtual_bool_target_unsafe();
        let [sibling_tree_hash, sibling_child_hash1, sibling_child_hash2] =
            array::from_fn(|_| b.add_virtual_hash());
        let [sibling_value, sibling_min, sibling_max, min_query, max_query] =
            array::from_fn(|_| b.add_virtual_u256_unsafe());

        // Check the consistency for the subtree proof and child proof.
        constrain_input_proofs(
            b,
            is_rows_tree_node,
            &min_query,
            &max_query,
            subtree_proof,
            slice::from_ref(child_proof),
        );

        // Check that the subtree rooted in sibling node contains only leaves with
        // indexed columns values outside the query range.
        // If the proved child is the left child, ensure sibling_min > MAX_query,
        // otherwise sibling_max < MIN_query.
        let is_greater_than_max = b.is_less_than_u256(&max_query, &sibling_min);
        let is_less_than_min = b.is_less_than_u256(&sibling_max, &min_query);
        let is_out_of_range = b.select(
            is_left_child,
            is_greater_than_max.target,
            is_less_than_min.target,
        );
        b.connect(is_out_of_range, ttrue.target);

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

        // Recompute the tree hash for the sibling node:
        // H(h1 || h2 || sibling_min || sibling_max || column_id || sibling_value || sibling_tree_hash)
        let inputs = sibling_child_hash1
            .to_targets()
            .into_iter()
            .chain(sibling_child_hash2.to_targets())
            .chain(sibling_min.to_targets())
            .chain(sibling_max.to_targets())
            .chain(iter::once(column_id))
            .chain(sibling_value.to_targets())
            .chain(sibling_tree_hash.to_targets())
            .collect();
        let sibling_hash = b.hash_n_to_hash_no_pad::<H>(inputs);

        // node_min = is_left_child ? child.min : sibling_min
        let node_min = b.select_u256(is_left_child, &child_proof.min_value_target(), &sibling_min);
        // node_max = is_left_child ? sibling_max : child.max
        let node_max = b.select_u256(is_left_child, &sibling_max, &child_proof.max_value_target());

        // Compute the node hash:
        // H(left_child_hash || right_child_hash || node_min || node_max || column_id || node_value || p.H)
        let rest: Vec<_> = node_min
            .to_targets()
            .into_iter()
            .chain(node_max.to_targets())
            .chain(iter::once(column_id))
            .chain(node_value.to_targets())
            .chain(subtree_proof.tree_hash_target().to_targets())
            .collect();
        let node_hash = hash_maybe_first(
            b,
            is_left_child,
            sibling_hash.elements,
            child_proof.tree_hash_target().elements,
            &rest,
        );

        // Aggregate the output values of children and the overflow number.
        let mut num_overflows = zero;
        let mut aggregated_values = vec![];
        for i in 0..MAX_NUM_RESULTS {
            let (mut output, overflow) = compute_output_item(b, i, &[subtree_proof, child_proof]);

            aggregated_values.append(&mut output);
            num_overflows = b.add(num_overflows, overflow);
        }

        // count = p.count + child.count
        let count = b.add(
            subtree_proof.num_matching_rows_target(),
            child_proof.num_matching_rows_target(),
        );

        // overflow = (pC.overflow + pR.overflow + num_overflows) != 0
        let overflow = b.add_many([
            subtree_proof.to_overflow_raw(),
            child_proof.to_overflow_raw(),
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
            &node_min.to_targets(),
            &node_max.to_targets(),
            subtree_proof.to_index_ids_raw(),
            &min_query.to_targets(),
            &max_query.to_targets(),
            &[overflow.target],
            subtree_proof.to_computational_hash_raw(),
            subtree_proof.to_placeholder_hash_raw(),
        )
        .register(b);

        let sibling_child_hashes = [sibling_child_hash1, sibling_child_hash2];

        PartialNodeWires {
            is_rows_tree_node,
            is_left_child,
            sibling_tree_hash,
            sibling_child_hashes,
            sibling_value,
            sibling_min,
            sibling_max,
            min_query,
            max_query,
        }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &PartialNodeWires<MAX_NUM_RESULTS>) {
        [
            (wires.is_rows_tree_node, self.is_rows_tree_node),
            (wires.is_left_child, self.is_left_child),
        ]
        .iter()
        .for_each(|(t, v)| pw.set_bool_target(*t, *v));
        [
            (&wires.sibling_value, self.sibling_value),
            (&wires.sibling_min, self.sibling_min),
            (&wires.sibling_max, self.sibling_max),
            (&wires.min_query, self.min_query),
            (&wires.max_query, self.max_query),
        ]
        .iter()
        .for_each(|(t, v)| pw.set_u256_target(t, *v));
        pw.set_hash_target(wires.sibling_tree_hash, self.sibling_tree_hash);
        wires
            .sibling_child_hashes
            .iter()
            .zip(self.sibling_child_hashes)
            .for_each(|(t, v)| pw.set_hash_target(*t, v));
    }
}

/// Subtree proof number = 1, child proof number = 1
pub(crate) const NUM_VERIFIED_PROOFS: usize = 2;

impl<const MAX_NUM_RESULTS: usize> CircuitLogicWires<F, D, NUM_VERIFIED_PROOFS>
    for PartialNodeWires<MAX_NUM_RESULTS>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    type CircuitBuilderParams = ();
    type Inputs = PartialNodeCircuit<MAX_NUM_RESULTS>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F, MAX_NUM_RESULTS>::total_len();

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
    use mp2_common::{poseidon::H, utils::ToFields, C};
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::{gen_random_field_hash, random_vector},
    };
    use plonky2::{iop::witness::WitnessWrite, plonk::config::Hasher};
    use rand::{thread_rng, Rng};
    use std::array;

    const MAX_NUM_RESULTS: usize = 20;

    #[derive(Clone, Debug)]
    struct TestPartialNodeCircuit<'a> {
        c: PartialNodeCircuit<MAX_NUM_RESULTS>,
        subtree_proof: &'a [F],
        child_proof: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestPartialNodeCircuit<'a> {
        // Circuit wires + query proof + child proof
        type Wires = (PartialNodeWires<MAX_NUM_RESULTS>, Vec<Target>, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let proofs = array::from_fn(|_| {
                b.add_virtual_target_arr::<{ PI_LEN::<MAX_NUM_RESULTS> }>()
                    .to_vec()
            });
            let [subtree_pi, child_pi] =
                array::from_fn(|i| PublicInputs::<Target, MAX_NUM_RESULTS>::from_slice(&proofs[i]));

            let wires = PartialNodeCircuit::build(b, &subtree_pi, &child_pi);

            let [subtree_proof, child_proof] = proofs;

            (wires, subtree_proof, child_proof)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);
            pw.set_target_arr(&wires.1, self.subtree_proof);
            pw.set_target_arr(&wires.2, self.child_proof);
        }
    }

    fn test_partial_node_circuit(is_rows_tree_node: bool, is_left_child: bool) {
        let min_query = U256::from(100);
        let max_query = U256::from(200);

        let [sibling_tree_hash, sibling_child_hash1, sibling_child_hash2] =
            array::from_fn(|_| gen_random_field_hash());

        let mut rng = thread_rng();
        let sibling_value = U256::from_limbs(rng.gen());
        let [sibling_min, sibling_max] = if is_left_child {
            // sibling_min > MAX_query
            [max_query + U256::from(1), U256::from_limbs(rng.gen())]
        } else {
            [U256::from_limbs(rng.gen()), min_query - U256::from(1)]
        };

        // Generate the input proofs.
        let ops: [_; MAX_NUM_RESULTS] = random_aggregation_operations();
        let [mut subtree_proof, mut child_proof] = random_aggregation_public_inputs(&ops);
        unify_subtree_proof::<MAX_NUM_RESULTS>(
            &mut subtree_proof,
            is_rows_tree_node,
            min_query,
            max_query,
        );
        let subtree_pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&subtree_proof);
        unify_child_proof::<MAX_NUM_RESULTS>(
            &mut child_proof,
            is_rows_tree_node,
            min_query,
            max_query,
            &subtree_pi,
        );
        let child_pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&child_proof);

        // Construct the expected public input values.
        let index_ids = subtree_pi.index_ids();
        let index_value = subtree_pi.index_value();
        let node_value = if is_rows_tree_node {
            subtree_pi.min_value()
        } else {
            index_value
        };
        let [node_min, node_max] = if is_left_child {
            [child_pi.min_value(), sibling_max]
        } else {
            [sibling_min, child_pi.max_value()]
        };

        // Construct the test circuit.
        let sibling_child_hashes = [sibling_child_hash1, sibling_child_hash2];
        let test_circuit = TestPartialNodeCircuit {
            c: PartialNodeCircuit {
                is_rows_tree_node,
                is_left_child,
                sibling_tree_hash,
                sibling_child_hashes,
                sibling_value,
                sibling_min,
                sibling_max,
                min_query,
                max_query,
            },
            subtree_proof: &subtree_proof,
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

            // H(h1 || h2 || sibling_min || sibling_max || column_id || sibling_value || sibling_tree_hash)
            let inputs: Vec<_> = sibling_child_hash1
                .to_fields()
                .into_iter()
                .chain(sibling_child_hash2.to_fields())
                .chain(sibling_min.to_fields())
                .chain(sibling_max.to_fields())
                .chain(iter::once(column_id))
                .chain(sibling_value.to_fields())
                .chain(sibling_tree_hash.to_fields())
                .collect();
            let sibling_hash = H::hash_no_pad(&inputs);

            let child_hash = child_pi.tree_hash();
            let [left_child_hash, right_child_hash] = if is_left_child {
                [child_hash, sibling_hash]
            } else {
                [sibling_hash, child_hash]
            };

            // H(left_child_hash || right_child_hash || node_min || node_max || column_id || node_value || p.H)
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
        // Output values and overflow flag
        {
            let mut num_overflows = 0;
            let mut aggregated_values = vec![];

            for i in 0..MAX_NUM_RESULTS {
                let (mut output, overflow) =
                    compute_output_item_value(i, &[&subtree_pi, &child_pi]);

                aggregated_values.append(&mut output);
                num_overflows += overflow;
            }

            assert_eq!(pi.to_values_raw(), aggregated_values);
            assert_eq!(
                pi.overflow_flag(),
                subtree_pi.overflow_flag() || child_pi.overflow_flag() || num_overflows != 0
            );
        }
        // Count
        assert_eq!(
            pi.num_matching_rows(),
            subtree_pi.num_matching_rows() + child_pi.num_matching_rows(),
        );
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
        // Computational hash
        assert_eq!(pi.computational_hash(), subtree_pi.computational_hash());
        // Placeholder hash
        assert_eq!(pi.placeholder_hash(), subtree_pi.placeholder_hash());
    }

    #[test]
    fn test_query_agg_partial_node_for_row_node_with_left_child() {
        test_partial_node_circuit(true, true);
    }

    #[test]
    fn test_query_agg_partial_node_for_row_node_with_right_child() {
        test_partial_node_circuit(true, false);
    }

    #[test]
    fn test_query_agg_partial_node_for_index_node_with_left_child() {
        test_partial_node_circuit(false, true);
    }

    #[test]
    fn test_query_agg_partial_node_for_index_node_with_right_child() {
        test_partial_node_circuit(false, false);
    }
}
