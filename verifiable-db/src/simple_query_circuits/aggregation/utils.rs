//! Utility functions for query aggregation circuits

use crate::simple_query_circuits::public_inputs::PublicInputs;
use mp2_common::{
    array::Array,
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target},
    F,
};
use plonky2::{
    field::types::Field,
    iop::target::{BoolTarget, Target},
};

/// Check the consistency for the subtree proof and child proofs.
pub(crate) fn constrain_input_proofs<const S: usize>(
    b: &mut CBuilder,
    is_rows_tree_node: BoolTarget,
    min_query: &UInt256Target,
    max_query: &UInt256Target,
    subtree_proof: &PublicInputs<Target, S>,
    child_proofs: &[PublicInputs<Target, S>],
) {
    let ffalse = b._false();

    let index_ids = subtree_proof.index_ids_target();
    let index_value = subtree_proof.index_value_target();

    // Ensure the proofs in the same rows tree are employing the same value
    // of the primary indexed column:
    // is_rows_tree_node == is_rows_tree_node AND p.I == p1.I AND p.I == p2.I ...
    let is_equals: Vec<_> = child_proofs
        .iter()
        .map(|p| b.is_equal_u256(&index_value, &p.index_value_target()))
        .collect();
    let is_equal = is_equals
        .into_iter()
        .fold(is_rows_tree_node, |acc, is_equal| b.and(acc, is_equal));
    b.connect(is_equal.target, is_rows_tree_node.target);

    // Ensure the value of the indexed column for all the records stored in the
    // rows tree found in this node is within the range specified by the query:
    // NOT(is_rows_tree_node) == NOT(is_row_tree_node) AND p.I >= MIN_query AND p.I <= MAX_query
    // And assume: is_out_of_range = p.I < MIN_query OR p.I > MAX_query
    // => (1 - is_rows_tree_node) * is_out_of_range = 0
    // => is_out_of_range - is_out_of_range * is_rows_tree_node = 0
    let is_less_than_min = b.is_less_than_u256(&index_value, &min_query);
    let is_greater_than_max = b.is_less_than_u256(&max_query, &index_value);
    let is_out_of_range = b.or(is_less_than_min, is_greater_than_max);
    let is_out_of_range = b.or(is_out_of_range, is_rows_tree_node);
    let is_false = b.arithmetic(
        F::NEG_ONE,
        F::ONE,
        is_rows_tree_node.target,
        is_out_of_range.target,
        is_out_of_range.target,
    );
    b.connect(is_false, ffalse.target);

    // p.index_ids == p1.index_ids == p2.index_ids ...
    let index_ids = Array::from(index_ids);
    child_proofs
        .iter()
        .for_each(|p| index_ids.enforce_equal(b, &Array::from(p.index_ids_target())));

    // p.C == p1.C == p2.C ...
    let computational_hash = subtree_proof.computational_hash_target();
    child_proofs
        .iter()
        .for_each(|p| b.connect_hashes(computational_hash, p.computational_hash_target()));

    // p.H_p == p1.H_p == p2.H_p = ...
    let placeholder_hash = subtree_proof.placeholder_hash_target();
    child_proofs
        .iter()
        .for_each(|p| b.connect_hashes(placeholder_hash, p.placeholder_hash_target()));

    // MIN_query = p1.MIN_I == p2.MIN_I ...
    child_proofs
        .iter()
        .for_each(|p| b.enforce_equal_u256(&min_query, &p.min_query_target()));

    // MAX_query = p1.MAX_I == p2.MAX_I ...
    child_proofs
        .iter()
        .for_each(|p| b.enforce_equal_u256(&max_query, &p.max_query_target()));

    // if the subtree proof is generated for a rows tree node,
    // the query bounds must be same:
    // is_row_tree_node = is_row_tree_node AND MIN_query == p.MIN_I AND MAX_query == p.MAX_I
    let is_min_query_equal = b.is_equal_u256(&min_query, &subtree_proof.min_query_target());
    let is_max_query_equal = b.is_equal_u256(&max_query, &subtree_proof.max_query_target());
    let is_equal = b.and(is_min_query_equal, is_max_query_equal);
    let is_equal = b.and(is_equal, is_rows_tree_node);
    b.connect(is_equal.target, is_rows_tree_node.target);
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::simple_query_circuits::{
        aggregation::tests::random_aggregation_public_inputs, public_inputs::QueryPublicInputs,
    };
    use alloy::primitives::U256;
    use mp2_common::utils::ToFields;

    /// Assign the subtree proof to make it consistent.
    pub(crate) fn unify_subtree_proof<const S: usize>(
        proof: &mut [F],
        is_rows_tree_node: bool,
        min_query: U256,
        max_query: U256,
        ops: &[F; S],
    ) {
        let [index_value_range, min_query_range, max_query_range] = [
            QueryPublicInputs::IndexValue,
            QueryPublicInputs::MinQuery,
            QueryPublicInputs::MaxQuery,
        ]
        .map(|input| PublicInputs::<F, S>::to_range(input));

        if is_rows_tree_node {
            // p.MIN_I == MIN_query AND p.MAX_I == MAX_query
            proof[min_query_range].copy_from_slice(&min_query.to_fields());
            proof[max_query_range].copy_from_slice(&max_query.to_fields());
        } else {
            // p.I >= MIN_query AND p.I <= MAX_query
            let index_value: U256 = (min_query + max_query) >> 1;
            proof[index_value_range].copy_from_slice(&index_value.to_fields());
        }
    }

    /// Assign the child proof to make it consistent.
    pub(crate) fn unify_child_proof<const S: usize>(
        proof: &mut [F],
        is_rows_tree_node: bool,
        min_query: U256,
        max_query: U256,
        ops: &[F; S],
        subtree_pi: &PublicInputs<F, S>,
    ) {
        let [index_value_range, min_query_range, max_query_range] = [
            QueryPublicInputs::IndexValue,
            QueryPublicInputs::MinQuery,
            QueryPublicInputs::MaxQuery,
        ]
        .map(|input| PublicInputs::<F, S>::to_range(input));

        // child.MIN_I == MIN_query
        // child.MAX_I == MAX_query
        proof[min_query_range.clone()].copy_from_slice(&min_query.to_fields());
        proof[max_query_range.clone()].copy_from_slice(&max_query.to_fields());

        if is_rows_tree_node {
            // child.I == p.I
            proof[index_value_range.clone()].copy_from_slice(subtree_pi.to_index_value_raw());
        }
    }
}
