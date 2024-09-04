//! Module handling the non-existence leaf node for query aggregation circuits

use crate::query::{
    aggregation::output_computation::compute_dummy_output_targets,
    computational_hash_ids::{AggregationOperation, Identifiers},
    public_inputs::PublicInputs,
    universal_circuit::universal_query_circuit::{
        QueryBound, QueryBoundTarget, QueryBoundTargetInputs,
    },
};
use alloy::primitives::U256;
use anyhow::Result;
use mp2_common::{
    array::ToField,
    poseidon::{empty_poseidon_hash, H},
    public_inputs::PublicInputCommon,
    serialization::{deserialize, deserialize_long_array, serialize, serialize_long_array},
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
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::{array, iter};

/// Non-existence leaf node wires
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonExistenceLeafWires<const MAX_NUM_RESULTS: usize> {
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonExistenceLeafCircuit<const MAX_NUM_RESULTS: usize> {
    /// The flag specified if the proof is generated for a node in a rows tree or
    /// for a node in the index tree
    pub(crate) is_rows_tree_node: bool,
    /// Minimum range bound specified in the query for the indexed column
    /// It's a range bound for the primary indexed column for index tree,
    /// and secondary indexed column for rows tree.
    pub(crate) min_query: QueryBound,
    /// Maximum range bound specified in the query for the indexed column
    pub(crate) max_query: QueryBound,
    /// Value stored in the current node
    pub(crate) value: U256,
    /// Value of the primary indexed column for the row stored in the current node
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
}

impl<const MAX_NUM_RESULTS: usize> NonExistenceLeafCircuit<MAX_NUM_RESULTS> {
    pub fn build(b: &mut CBuilder) -> NonExistenceLeafWires<MAX_NUM_RESULTS> {
        let ttrue = b._true();
        let ffalse = b._false();
        let zero = b.zero();
        let curve_zero = b.curve_zero();
        let u256_zero = b.zero_u256();
        let u256_max = b.constant_u256(U256::MAX);
        let empty_hash = b.constant_hash(*empty_poseidon_hash());
        let empty_hash_targets = empty_hash.to_targets();

        let is_rows_tree_node = b.add_virtual_bool_target_safe();
        let [value, index_value] = b.add_virtual_u256_arr_unsafe();
        let index_ids = b.add_virtual_target_arr();
        let ops = b.add_virtual_target_arr();
        let [subtree_hash, computational_hash, placeholder_hash] =
            array::from_fn(|_| b.add_virtual_hash());

        let min_query = QueryBoundTarget::new(b);
        let max_query = QueryBoundTarget::new(b);
        let min_query_value = min_query.get_bound_value();
        let max_query_value = max_query.get_bound_value();

        let [min_query_targets, max_query_targets, value_targets, index_value_targets] =
            [min_query_value, max_query_value, &value, &index_value].map(|v| v.to_targets());
        let column_id = b.select(is_rows_tree_node, index_ids[1], index_ids[0]);

        let [op_id, op_min] = [AggregationOperation::IdOp, AggregationOperation::MinOp]
            .map(|op| b.constant(Identifiers::AggregationOperations(op).to_field()));

        // Enforce that the value associated to the current node is out of range
        // specified by the query:
        // value < MIN_query OR value > MAX_query
        let is_less_than_min = b.is_less_than_u256(&value, &min_query_value);
        let is_greater_than_max = b.is_less_than_u256(&max_query_value, &value);
        let is_out_of_range = b.or(is_greater_than_max, is_less_than_min);
        b.connect(is_out_of_range.target, ttrue.target);

        // Compute dummy values for each of the `S` values to be returned as output.
        let outputs = compute_dummy_output_targets(b, &ops);

        // Compute the node hash:
        // H(H("") || H("") || value || value || column_id || value || subtree_hash)
        let inputs = empty_hash_targets
            .clone()
            .into_iter()
            .chain(empty_hash_targets)
            .chain(value_targets.clone())
            .chain(value_targets.clone())
            .chain(iter::once(column_id))
            .chain(value_targets.clone())
            .chain(subtree_hash.to_targets())
            .collect();
        let node_hash = b.hash_n_to_hash_no_pad::<H>(inputs);

        // We add the query bounds to the placeholder hash only if the current
        // node is in a rows tree.
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
            &index_value_targets,
            &value_targets,
            &value_targets,
            &index_ids,
            &min_query_targets,
            &max_query_targets,
            &[ffalse.target],
            &new_computational_hash.to_targets(),
            &new_placeholder_hash.to_targets(),
        )
        .register(b);

        NonExistenceLeafWires {
            is_rows_tree_node,
            min_query: min_query.into(),
            max_query: max_query.into(),
            value,
            index_value,
            index_ids,
            ops,
            subtree_hash,
            computational_hash,
            placeholder_hash,
        }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &NonExistenceLeafWires<MAX_NUM_RESULTS>) {
        pw.set_bool_target(wires.is_rows_tree_node, self.is_rows_tree_node);
        [
            (&wires.value, self.value),
            (&wires.index_value, self.index_value),
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
        ]
        .iter()
        .for_each(|(t, v)| pw.set_hash_target(*t, *v));
    }
}

/// Verified proof number = 0
pub(crate) const NUM_VERIFIED_PROOFS: usize = 0;

impl<const MAX_NUM_RESULTS: usize> CircuitLogicWires<F, D, NUM_VERIFIED_PROOFS>
    for NonExistenceLeafWires<MAX_NUM_RESULTS>
{
    type CircuitBuilderParams = ();
    type Inputs = NonExistenceLeafCircuit<MAX_NUM_RESULTS>;

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
            universal_circuit::universal_circuit_inputs::{PlaceholderId, Placeholders},
        },
        test_utils::random_aggregation_operations,
    };
    use mp2_common::{poseidon::H, utils::ToFields, C};
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

    impl UserCircuit<F, D> for NonExistenceLeafCircuit<MAX_NUM_RESULTS> {
        type Wires = NonExistenceLeafWires<MAX_NUM_RESULTS>;

        fn build(b: &mut CBuilder) -> Self::Wires {
            NonExistenceLeafCircuit::build(b)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.assign(pw, wires);
        }
    }

    fn test_non_existence_leaf_circuit(is_rows_tree_node: bool, ops: [F; MAX_NUM_RESULTS]) {
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
        let index_value = U256::from_limbs(rng.gen());
        let index_ids = F::rand_array();
        let [subtree_hash, computational_hash, placeholder_hash] =
            array::from_fn(|_| gen_random_field_hash());

        let first_placeholder_id = PlaceholderId::Generic(0);

        let (min_query, max_query, placeholders) = if is_rows_tree_node {
            let dummy_min_query_primary = U256::ZERO; //dummy value, circuit will employ only bounds for secondary index
            let dummy_max_query_primary = U256::MAX; //dummy value, circuit will employ only bounds for secondary index
            let placeholders = Placeholders::from((
                vec![(first_placeholder_id, min_query_value)],
                dummy_min_query_primary,
                dummy_max_query_primary,
            ));
            let query_bounds = QueryBounds::new(
                &placeholders,
                Some(QueryBoundSource::Placeholder(first_placeholder_id)),
                Some(QueryBoundSource::Constant(max_query_value)),
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
        let test_circuit = NonExistenceLeafCircuit {
            is_rows_tree_node,
            min_query: min_query.clone(),
            max_query: max_query.clone(),
            value,
            index_value,
            index_ids,
            ops,
            subtree_hash,
            computational_hash,
            placeholder_hash,
        };

        // Prove for the test circuit.
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&proof.public_inputs);

        let [min_query_fields, max_query_fields, value_fields] =
            [&min_query_value, &max_query_value, &value].map(|v| v.to_fields());

        // Check the public inputs.
        // Tree hash
        {
            let empty_hash = empty_poseidon_hash();
            let empty_hash_fields = empty_hash.to_fields();
            let column_id = if is_rows_tree_node {
                index_ids[1]
            } else {
                index_ids[0]
            };

            // H(H("") || H("") || value || value || column_id || value || subtree_hash)
            let inputs: Vec<_> = empty_hash_fields
                .clone()
                .into_iter()
                .chain(empty_hash_fields)
                .chain(value_fields.clone())
                .chain(value_fields.clone())
                .chain(iter::once(column_id))
                .chain(value_fields)
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
        assert_eq!(pi.min_value(), value);
        // Maximum value
        assert_eq!(pi.max_value(), value);
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
                    &QueryBoundSource::Placeholder(first_placeholder_id),
                    &QueryBoundSource::Constant(max_query_value),
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

    // The condition of the first aggregation operation ID is not associated
    // with the `is_rows_tree_node` flag.
    #[test]
    fn test_query_agg_non_existence_leaf_for_row_node_with_first_op_id() {
        // Generate the random operations.
        let mut ops: [_; MAX_NUM_RESULTS] = random_aggregation_operations();

        // Set the first operation to ID for testing the digest.
        ops[0] = Identifiers::AggregationOperations(AggregationOperation::IdOp).to_field();

        test_non_existence_leaf_circuit(true, ops);
    }

    #[test]
    fn test_query_agg_non_existence_leaf_for_index_node_with_random_ops() {
        // Generate the random operations.
        let ops: [_; MAX_NUM_RESULTS] = random_aggregation_operations();

        test_non_existence_leaf_circuit(false, ops);
    }
}
