//! Module handling the non-existence intermediate node for query aggregation circuits

use crate::query::{
    aggregation::output_computation::compute_dummy_output_targets,
    public_inputs::PublicInputs,
    universal_circuit::universal_query_gadget::{
        QueryBound, QueryBoundTarget, QueryBoundTargetInputs,
    },
};
use alloy::primitives::U256;
use anyhow::Result;
use mp2_common::{
    array::ToField,
    hash::hash_maybe_first,
    poseidon::{empty_poseidon_hash, H},
    public_inputs::PublicInputCommon,
    serialization::{
        deserialize, deserialize_array, deserialize_long_array, serialize, serialize_array,
        serialize_long_array,
    },
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{HashBuilder, ToTargets},
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
use std::{array, iter};

/// Non-existence intermediate node wires
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonExistenceInterNodeWires<const MAX_NUM_RESULTS: usize> {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_rows_tree_node: BoolTarget,
    min_query: QueryBoundTargetInputs,
    max_query: QueryBoundTargetInputs,
    value: UInt256Target,
    index_value: UInt256Target,
    index_ids: [Target; 2],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    ops: [Target; MAX_NUM_RESULTS],
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    subtree_hash: HashOutTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    computational_hash: HashOutTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    placeholder_hash: HashOutTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonExistenceInterNodeCircuit<const MAX_NUM_RESULTS: usize> {
    /// The flag specified if the proof is generated for a node in a rows tree or
    /// for a node in the index tree
    pub(crate) is_rows_tree_node: bool,
    /// Minimum range bound specified in the query for the indexed column
    /// It's a range bound for the primary indexed column for index tree,
    /// and secondary indexed column for rows tree.
    pub(crate) min_query: QueryBound,
    /// Maximum range bound specified in the query for the indexed column
    pub(crate) max_query: QueryBound,
    pub(crate) value: U256,
    /// Value of the indexed column for the row stored in the current node
    /// (meaningful only if the current node belongs to a rows tree,
    /// can be equal to `value` if the current node belongs to the index tree)
    pub(crate) index_value: U256,
    /// Integer identifiers of the indexed columns
    pub(crate) index_ids: [F; 2],
    /// Set of identifiers of the aggregation operations for each of the `S` items found in `V`
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) ops: [F; MAX_NUM_RESULTS],
    /// Hash of the tree stored in the current node
    pub(crate) subtree_hash: HashOut<F>,
    /// Computational hash associated to the processing of single rows of the query
    /// (meaningless in this case, we just need to provide it for public input compliance)
    pub(crate) computational_hash: HashOut<F>,
    /// Placeholder hash associated to the processing of single rows of the query
    /// (meaningless in this case, we just need to provide it for public input compliance)
    pub(crate) placeholder_hash: HashOut<F>,
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
}

impl<const MAX_NUM_RESULTS: usize> NonExistenceInterNodeCircuit<MAX_NUM_RESULTS> {
    pub fn build(b: &mut CBuilder) -> NonExistenceInterNodeWires<MAX_NUM_RESULTS> {
        let ttrue = b._true();
        let ffalse = b._false();
        let zero = b.zero();
        let empty_hash = b.constant_hash(*empty_poseidon_hash());

        let is_rows_tree_node = b.add_virtual_bool_target_safe();
        let left_child_exists = b.add_virtual_bool_target_safe();
        let right_child_exists = b.add_virtual_bool_target_safe();
        // Initialize as unsafe, since all these Uint256s are either exposed as
        // public inputs or passed as inputs for hash computation.
        let [value, index_value, left_child_value, left_child_min, left_child_max, right_child_value, right_child_min, right_child_max] =
            b.add_virtual_u256_arr_unsafe();
        // compute min and max query bounds for secondary index

        let index_ids = b.add_virtual_target_arr();
        let ops = b.add_virtual_target_arr();
        let [subtree_hash, computational_hash, placeholder_hash, left_child_subtree_hash, left_grand_child_hash1, left_grand_child_hash2, right_child_subtree_hash, right_grand_child_hash1, right_grand_child_hash2] =
            array::from_fn(|_| b.add_virtual_hash());

        let min_query = QueryBoundTarget::new(b);
        let max_query = QueryBoundTarget::new(b);

        let min_query_value = min_query.get_bound_value();
        let max_query_value = max_query.get_bound_value();

        let [min_query_targets, max_query_targets] =
            [&min_query_value, &max_query_value].map(|v| v.to_targets());
        let column_id = b.select(is_rows_tree_node, index_ids[1], index_ids[0]);

        // Enforce that the value associated to the current node is out of the range
        // specified by the query:
        // value < MIN_query OR value > MAX_query
        let is_value_less_than_min = b.is_less_than_u256(&value, &min_query_value);
        let is_value_greater_than_max = b.is_less_than_u256(&max_query_value, &value);
        let is_out_of_range = b.or(is_value_less_than_min, is_value_greater_than_max);
        b.connect(is_out_of_range.target, ttrue.target);

        // Enforce that the records found in the subtree rooted in the child node
        // are all out of the range specified by the query. If left child exists,
        // ensure left_child_max < MIN_query; if right child exists, ensure right_child_min > MAX_query.
        let is_child_less_than_min = b.is_less_than_u256(&left_child_max, &min_query_value);
        let is_left_child_out_of_range = b.and(left_child_exists, is_child_less_than_min);
        b.connect(is_left_child_out_of_range.target, left_child_exists.target);
        let is_child_greater_than_max = b.is_less_than_u256(&max_query_value, &right_child_min);
        let is_right_child_out_of_range = b.and(right_child_exists, is_child_greater_than_max);
        b.connect(
            is_right_child_out_of_range.target,
            right_child_exists.target,
        );

        // Compute dummy values for each of the `S` values to be returned as output.
        let outputs = compute_dummy_output_targets(b, &ops);

        // Recompute hash of left child node to bind left_child_min and left_child_max inputs:
        // H(h1 || h2 || child_min || child_max || column_id || child_value || child_subtree_hash)
        let inputs = left_grand_child_hash1
            .to_targets()
            .into_iter()
            .chain(left_grand_child_hash2.to_targets())
            .chain(left_child_min.to_targets())
            .chain(left_child_max.to_targets())
            .chain(iter::once(column_id))
            .chain(left_child_value.to_targets())
            .chain(left_child_subtree_hash.to_targets())
            .collect();
        let left_child_hash = b.hash_n_to_hash_no_pad::<H>(inputs);

        let left_child_hash = b.select_hash(left_child_exists, &left_child_hash, &empty_hash);

        // Recompute hash of right child node to bind right_child_min and right_child_max inputs:
        // H(h1 || h2 || child_min || child_max || column_id || child_value || child_subtree_hash)
        let inputs = right_grand_child_hash1
            .to_targets()
            .into_iter()
            .chain(right_grand_child_hash2.to_targets())
            .chain(right_child_min.to_targets())
            .chain(right_child_max.to_targets())
            .chain(iter::once(column_id))
            .chain(right_child_value.to_targets())
            .chain(right_child_subtree_hash.to_targets())
            .collect();
        let right_child_hash = b.hash_n_to_hash_no_pad::<H>(inputs);

        let right_child_hash = b.select_hash(right_child_exists, &right_child_hash, &empty_hash);

        // node_min = left_child_exists ? left_child_min : value
        let node_min = b.select_u256(left_child_exists, &left_child_min, &value);
        // node_max = right_child_exists ? right_child_max : value
        let node_max = b.select_u256(right_child_exists, &right_child_max, &value);
        let [node_min_targets, node_max_targets] = [node_min, node_max].map(|u| u.to_targets());

        // Compute the node hash:
        // H(left_child_hash || right_child_hash || node_min || node_max || column_id || value || subtree_hash)
        let inputs = left_child_hash
            .to_targets()
            .into_iter()
            .chain(right_child_hash.to_targets())
            .chain(node_min_targets.clone())
            .chain(node_max_targets.clone())
            .chain(iter::once(column_id))
            .chain(value.to_targets())
            .chain(subtree_hash.to_targets())
            .collect();
        let node_hash = b.hash_n_to_hash_no_pad::<H>(inputs);

        // We add the query bounds to the placeholder hash only if the current node is in a rows tree.
        let placeholder_hash_with_query_bounds =
            QueryBoundTarget::add_query_bounds_to_placeholder_hash(
                b,
                &min_query,
                &max_query,
                &placeholder_hash,
            );
        let new_placeholder_hash = b.select_hash(
            is_rows_tree_node,
            &placeholder_hash_with_query_bounds,
            &placeholder_hash,
        );
        // We add the query bounds to the computational hash only if the current
        // node is in a rows tree.
        let computational_hash_with_query_bounds =
            QueryBoundTarget::add_query_bounds_to_computational_hash(
                b,
                &min_query,
                &max_query,
                &computational_hash,
            );
        let new_computational_hash = b.select_hash(
            is_rows_tree_node,
            &computational_hash_with_query_bounds,
            &computational_hash,
        );

        // Register the public inputs.
        PublicInputs::<_, MAX_NUM_RESULTS>::new(
            &node_hash.to_targets(),
            outputs.as_slice(),
            &[zero],
            &ops,
            &index_value.to_targets(),
            &node_min_targets,
            &node_max_targets,
            &index_ids,
            &min_query_targets,
            &max_query_targets,
            &[ffalse.target],
            &new_computational_hash.to_targets(),
            &new_placeholder_hash.to_targets(),
        )
        .register(b);

        let left_grand_children = [left_grand_child_hash1, left_grand_child_hash2];
        let right_grand_children = [right_grand_child_hash1, right_grand_child_hash2];

        NonExistenceInterNodeWires {
            is_rows_tree_node,
            left_child_exists,
            right_child_exists,
            min_query: min_query.into(),
            max_query: max_query.into(),
            value,
            index_value,
            left_child_value,
            left_child_min,
            left_child_max,
            right_child_value,
            right_child_min,
            right_child_max,
            index_ids,
            ops,
            subtree_hash,
            computational_hash,
            placeholder_hash,
            left_tree_hash: left_child_subtree_hash,
            left_grand_children,
            right_tree_hash: right_child_subtree_hash,
            right_grand_children,
        }
    }

    fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &NonExistenceInterNodeWires<MAX_NUM_RESULTS>,
    ) {
        [
            (wires.is_rows_tree_node, self.is_rows_tree_node),
            (wires.left_child_exists, self.left_child_exists),
            (wires.right_child_exists, self.right_child_exists),
        ]
        .iter()
        .for_each(|(t, v)| pw.set_bool_target(*t, *v));
        [
            (&wires.value, self.value),
            (&wires.index_value, self.index_value),
            (&wires.left_child_value, self.left_child_value),
            (&wires.left_child_min, self.left_child_min),
            (&wires.left_child_max, self.left_child_max),
            (&wires.right_child_value, self.right_child_value),
            (&wires.right_child_min, self.right_child_min),
            (&wires.right_child_max, self.right_child_max),
        ]
        .iter()
        .for_each(|(t, v)| pw.set_u256_target(t, *v));
        wires.min_query.assign(pw, &self.min_query);
        wires.max_query.assign(pw, &self.max_query);
        pw.set_target_arr(&wires.index_ids, &self.index_ids);
        pw.set_target_arr(&wires.ops, &self.ops);
        [
            (wires.subtree_hash, self.subtree_hash),
            (wires.computational_hash, self.computational_hash),
            (wires.placeholder_hash, self.placeholder_hash),
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
    }
}

/// Verified proof number = 0
pub(crate) const NUM_VERIFIED_PROOFS: usize = 0;

impl<const MAX_NUM_RESULTS: usize> CircuitLogicWires<F, D, NUM_VERIFIED_PROOFS>
    for NonExistenceInterNodeWires<MAX_NUM_RESULTS>
{
    type CircuitBuilderParams = ();
    type Inputs = NonExistenceInterNodeCircuit<MAX_NUM_RESULTS>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F, MAX_NUM_RESULTS>::total_len();

    fn circuit_logic(
        builder: &mut CBuilder,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; NUM_VERIFIED_PROOFS],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        Self::Inputs::build(builder)
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
        query::{
            aggregation::{
                output_computation::tests::compute_dummy_output_values, QueryBoundSource,
                QueryBounds,
            },
            computational_hash_ids::{AggregationOperation, Identifiers},
            universal_circuit::universal_circuit_inputs::{PlaceholderId, Placeholders},
        },
        test_utils::random_aggregation_operations,
    };
    use mp2_common::{array::ToField, poseidon::H, utils::ToFields, C};
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::gen_random_field_hash,
    };
    use plonky2::{
        field::types::{Field, Sample},
        plonk::config::Hasher,
    };

    use rand::{prelude::SliceRandom, thread_rng, Rng};

    const MAX_NUM_RESULTS: usize = 20;

    impl UserCircuit<F, D> for NonExistenceInterNodeCircuit<MAX_NUM_RESULTS> {
        type Wires = NonExistenceInterNodeWires<MAX_NUM_RESULTS>;

        fn build(b: &mut CBuilder) -> Self::Wires {
            NonExistenceInterNodeCircuit::build(b)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.assign(pw, wires);
        }
    }

    fn test_non_existence_inter_circuit(
        is_rows_tree_node: bool,
        left_child_exists: bool,
        right_child_exists: bool,
        ops: [F; MAX_NUM_RESULTS],
    ) {
        let min_query_value = U256::from(1000);
        let max_query_value = U256::from(3000);

        let mut rng = &mut thread_rng();
        // value < MIN_query OR value > MAX_query
        let value = *[
            min_query_value - U256::from(1),
            max_query_value + U256::from(1),
        ]
        .choose(&mut rng)
        .unwrap();
        let [left_child_min, left_child_max] = if left_child_exists {
            // left_child_max < MIN_query
            [U256::from_limbs(rng.gen()), min_query_value - U256::from(1)]
        } else {
            // no constraints otherwise
            [U256::from_limbs(rng.gen()), U256::from_limbs(rng.gen())]
        };
        let [right_child_min, right_child_max] = if right_child_exists {
            // right_child_min > MAX_query
            [max_query_value + U256::from(1), U256::from_limbs(rng.gen())]
        } else {
            // no constraints otherwise
            [U256::from_limbs(rng.gen()), U256::from_limbs(rng.gen())]
        };
        let [index_value, left_child_value, right_child_value] =
            array::from_fn(|_| U256::from_limbs(rng.gen()));
        let index_ids = F::rand_array();
        let [subtree_hash, computational_hash, placeholder_hash, left_child_subtree_hash, left_grand_child_hash1, left_grand_child_hash2, right_child_subtree_hash, right_grand_child_hash1, right_grand_child_hash2] =
            array::from_fn(|_| gen_random_field_hash());
        let left_grand_children = [left_grand_child_hash1, left_grand_child_hash2];
        let right_grand_children = [right_grand_child_hash1, right_grand_child_hash2];

        let first_placeholder_id = PlaceholderId::Generic(0);

        let (min_query, max_query, placeholders) = if is_rows_tree_node {
            let dummy_min_query_primary = U256::ZERO; //dummy value, circuit will employ only bounds for secondary index
            let dummy_max_query_primary = U256::MAX; //dummy value, circuit will employ only bounds for secondary index
            let placeholders = Placeholders::from((
                vec![(first_placeholder_id, max_query_value)],
                dummy_min_query_primary,
                dummy_max_query_primary,
            ));

            let query_bounds = QueryBounds::new(
                &&placeholders,
                Some(QueryBoundSource::Constant(min_query_value)),
                Some(QueryBoundSource::Placeholder(first_placeholder_id)),
            )
            .unwrap();
            (
                QueryBound::new_secondary_index_bound(
                    &placeholders,
                    &query_bounds.min_query_secondary,
                )
                .unwrap(),
                QueryBound::new_secondary_index_bound(
                    &placeholders,
                    &query_bounds.max_query_secondary,
                )
                .unwrap(),
                placeholders,
            )
        } else {
            // min_query and max_query should be primary index bounds
            let placeholders = Placeholders::new_empty(min_query_value, max_query_value);
            (
                QueryBound::new_primary_index_bound(&placeholders, true).unwrap(),
                QueryBound::new_primary_index_bound(&placeholders, false).unwrap(),
                placeholders,
            )
        };

        // Construct the test circuit.
        let test_circuit = NonExistenceInterNodeCircuit {
            is_rows_tree_node,
            left_child_exists,
            right_child_exists,
            min_query: min_query.clone(),
            max_query: max_query.clone(),
            value,
            index_value,
            left_child_value,
            left_child_min,
            left_child_max,
            index_ids,
            ops,
            subtree_hash,
            computational_hash,
            placeholder_hash,
            left_tree_hash: left_child_subtree_hash,
            left_grand_children,
            right_child_value,
            right_child_min,
            right_child_max,
            right_tree_hash: right_child_subtree_hash,
            right_grand_children,
        };

        // Prove for the test circuit.
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&proof.public_inputs);

        // node_min = is_left_child ? child_min : value
        // node_max = is_left_child ? value : child_max
        let node_min = if left_child_exists {
            left_child_min
        } else {
            value
        };
        let node_max = if right_child_exists {
            right_child_max
        } else {
            value
        };

        // Check the public inputs.
        // Tree hash
        {
            let empty_hash = empty_poseidon_hash();
            let column_id = if is_rows_tree_node {
                index_ids[1]
            } else {
                index_ids[0]
            };

            // H(h1 || h2 || child_min || child_max || column_id || child_value || child_subtree_hash)
            let inputs: Vec<_> = left_grand_child_hash1
                .to_fields()
                .into_iter()
                .chain(left_grand_child_hash2.to_fields())
                .chain(left_child_min.to_fields())
                .chain(left_child_max.to_fields())
                .chain(iter::once(column_id))
                .chain(left_child_value.to_fields())
                .chain(left_child_subtree_hash.to_fields())
                .collect();
            let left_child_hash = H::hash_no_pad(&inputs);

            let left_child_hash = if left_child_exists {
                left_child_hash
            } else {
                *empty_hash
            };

            // H(h1 || h2 || child_min || child_max || column_id || child_value || child_subtree_hash)
            let inputs: Vec<_> = right_grand_child_hash1
                .to_fields()
                .into_iter()
                .chain(right_grand_child_hash2.to_fields())
                .chain(right_child_min.to_fields())
                .chain(right_child_max.to_fields())
                .chain(iter::once(column_id))
                .chain(right_child_value.to_fields())
                .chain(right_child_subtree_hash.to_fields())
                .collect();
            let right_child_hash = H::hash_no_pad(&inputs);

            let right_child_hash = if right_child_exists {
                right_child_hash
            } else {
                *empty_hash
            };

            // H(left_child_hash || right_child_hash || node_min || node_max || column_id || value || subtree_hash)
            let inputs: Vec<_> = left_child_hash
                .to_fields()
                .into_iter()
                .chain(right_child_hash.to_fields())
                .chain(node_min.to_fields())
                .chain(node_max.to_fields())
                .chain(iter::once(column_id))
                .chain(value.to_fields())
                .chain(subtree_hash.to_fields())
                .collect();
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.tree_hash(), exp_hash);
        }
        // Output values
        {
            let outputs = compute_dummy_output_values(&ops);
            assert_eq!(pi.to_values_raw(), outputs);
        }
        // Count
        assert_eq!(pi.num_matching_rows(), F::ZERO);
        // Operation IDs
        assert_eq!(pi.operation_ids(), ops);
        // Index value
        assert_eq!(pi.index_value(), index_value);
        // Minimum value
        assert_eq!(pi.min_value(), node_min);
        // Maximum value
        assert_eq!(pi.max_value(), node_max);
        // Index IDs
        assert_eq!(pi.index_ids(), index_ids);
        // Minimum query
        assert_eq!(pi.min_query_value(), min_query_value);
        // Maximum query
        assert_eq!(pi.max_query_value(), max_query_value);
        // overflow_flag
        assert!(!pi.overflow_flag());
        // Computational hash
        {
            let exp_hash = if is_rows_tree_node {
                QueryBound::add_secondary_query_bounds_to_computational_hash(
                    &QueryBoundSource::Constant(min_query_value),
                    &QueryBoundSource::Placeholder(first_placeholder_id),
                    &computational_hash,
                )
                .unwrap()
            } else {
                computational_hash
            };
            assert_eq!(pi.computational_hash(), exp_hash);
        }
        // Placeholder hash
        {
            let exp_hash = if is_rows_tree_node {
                QueryBound::add_secondary_query_bounds_to_placeholder_hash(
                    &min_query,
                    &max_query,
                    &placeholder_hash,
                )
            } else {
                placeholder_hash
            };

            assert_eq!(pi.placeholder_hash(), exp_hash);
        }
    }

    #[test]
    fn test_query_agg_non_existence_inter_for_row_node_and_left_child() {
        // Generate the random operations.
        let mut ops: [_; MAX_NUM_RESULTS] = random_aggregation_operations();

        // Set the first operation to ID for testing the digest.
        // The condition of the first aggregation operation ID is not associated
        // with the `is_rows_tree_node` and `is_left_child` flag.
        ops[0] = Identifiers::AggregationOperations(AggregationOperation::IdOp).to_field();

        test_non_existence_inter_circuit(true, true, false, ops);
    }

    #[test]
    fn test_query_agg_non_existence_inter_for_row_node_and_right_child() {
        // Generate the random operations.
        let ops: [_; MAX_NUM_RESULTS] = random_aggregation_operations();

        test_non_existence_inter_circuit(true, false, true, ops);
    }

    #[test]
    fn test_query_agg_non_existence_inter_for_index_node_and_left_child() {
        // Generate the random operations.
        let ops: [_; MAX_NUM_RESULTS] = random_aggregation_operations();

        test_non_existence_inter_circuit(false, true, false, ops);
    }

    #[test]
    fn test_query_agg_non_existence_inter_for_index_node_and_right_child() {
        // Generate the random operations.
        let mut ops: [_; MAX_NUM_RESULTS] = random_aggregation_operations();

        // Set the first operation to ID for testing the digest.
        // The condition of the first aggregation operation ID is not associated
        // with the `is_rows_tree_node` and `is_left_child` flag.
        ops[0] = Identifiers::AggregationOperations(AggregationOperation::IdOp).to_field();

        test_non_existence_inter_circuit(false, false, true, ops);
    }

    #[test]
    fn test_query_agg_non_existence_for_row_tree_leaf_node() {
        // Generate the random operations.
        let mut ops: [_; MAX_NUM_RESULTS] = random_aggregation_operations();

        // Set the first operation to ID for testing the digest.
        // The condition of the first aggregation operation ID is not associated
        // with the `is_rows_tree_node` and `is_left_child` flag.
        ops[0] = Identifiers::AggregationOperations(AggregationOperation::IdOp).to_field();

        test_non_existence_inter_circuit(true, false, false, ops);
    }

    #[test]
    fn test_query_agg_non_existence_for_index_tree_leaf_node() {
        // Generate the random operations.
        let mut ops: [_; MAX_NUM_RESULTS] = random_aggregation_operations();

        test_non_existence_inter_circuit(false, false, false, ops);
    }

    #[test]
    fn test_query_agg_non_existence_for_row_tree_full_node() {
        // Generate the random operations.
        let mut ops: [_; MAX_NUM_RESULTS] = random_aggregation_operations();

        test_non_existence_inter_circuit(true, true, true, ops);
    }

    #[test]
    fn test_query_agg_non_existence_for_index_tree_full_node() {
        // Generate the random operations.
        let mut ops: [_; MAX_NUM_RESULTS] = random_aggregation_operations();

        // Set the first operation to ID for testing the digest.
        // The condition of the first aggregation operation ID is not associated
        // with the `is_rows_tree_node` and `is_left_child` flag.
        ops[0] = Identifiers::AggregationOperations(AggregationOperation::IdOp).to_field();

        test_non_existence_inter_circuit(false, true, true, ops);
    }
}
