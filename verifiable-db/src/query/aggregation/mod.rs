use anyhow::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{
    array::ToField,
    poseidon::{empty_poseidon_hash, H},
    proof::ProofWithVK,
    serialization::{deserialize_long_array, serialize_long_array},
    types::HashOutput,
    utils::ToFields,
    F,
};
use plonky2::{
    field::types::PrimeField64,
    hash::hash_types::HashOut,
    plonk::config::{GenericHashOut, Hasher},
};

pub(crate) mod child_proven_single_path_node;
pub(crate) mod embedded_tree_proven_single_path_node;
pub(crate) mod full_node_index_leaf;
pub(crate) mod full_node_with_one_child;
pub(crate) mod full_node_with_two_children;
pub(crate) mod non_existence_inter;
pub(crate) mod non_existence_leaf;
mod output_computation;
pub(crate) mod partial_node;
mod utils;

use super::{
    api::CircuitInput,
    computational_hash_ids::{Identifiers, Output},
    universal_circuit::{
        output_no_aggregation::Circuit as NoAggOutputCircuit,
        output_with_aggregation::Circuit as AggOutputCircuit,
        universal_circuit_inputs::{
            BasicOperation, ColumnCell, PlaceholderId, Placeholders, ResultStructure,
        },
        universal_query_circuit::{
            dummy_placeholder, placeholder_hash, placeholder_hash_without_query_bounds, QueryBound,
            UniversalQueryCircuitInputs,
        },
        ComputationalHash, PlaceholderHash,
    },
};

#[derive(Clone, Debug)]
/// Data structure representing a query bound on secondary index
pub struct QueryBoundSecondary {
    /// value of the query bound. Could come either from a constant in the query or from a placeholder
    pub(crate) value: U256,
    /// Id of the placeholder from which the bound is taken; None if the bound comes from a constant
    pub(crate) id: Option<PlaceholderId>,
}

/// Enumeration employed to specify whether a query bound for secondary indexed is taken in the query from
/// a constant or from a placeholder
pub enum QueryBoundSource {
    // Query bound is a constant
    Constant(U256),
    /// Query bound taken from placeholder with id
    Placeholder(PlaceholderId),
}

impl QueryBoundSource {
    /// Get the payload corresponding to `self` query bound to be hashed in computational hash
    pub(crate) fn get_payload_for_computational_hash(&self) -> U256 {
        match self {
            QueryBoundSource::Constant(value) => *value,
            QueryBoundSource::Placeholder(id) => {
                U256::from(<PlaceholderId as ToField<F>>::to_field(&id).to_canonical_u64())
            }
        }
    }

    pub(crate) fn add_query_bounds_to_computational_hash(
        min_query: &Self,
        max_query: &Self,
        computational_hash: &ComputationalHash,
    ) -> ComputationalHash {
        let min_query = min_query.get_payload_for_computational_hash();
        let max_query = max_query.get_payload_for_computational_hash();
        let inputs = computational_hash
            .to_vec()
            .into_iter()
            .chain(min_query.to_fields())
            .chain(max_query.to_fields())
            .collect_vec();
        H::hash_no_pad(&inputs)
    }
}

impl From<&QueryBoundSecondary> for QueryBoundSource {
    fn from(value: &QueryBoundSecondary) -> Self {
        match value.id {
            Some(id) => QueryBoundSource::Placeholder(id),
            None => QueryBoundSource::Constant(value.value),
        }
    }
}

impl QueryBoundSecondary {
    pub fn new(placeholders: &Placeholders, source: QueryBoundSource) -> Result<Self> {
        Ok(match source {
            QueryBoundSource::Constant(value) => Self { value, id: None },
            QueryBoundSource::Placeholder(id) => Self {
                value: placeholders.get(&id)?,
                id: Some(id),
            },
        })
    }
}

#[derive(Clone, Debug)]
/// Data structure storing the query bounds specified in the query for primary and secondary index
pub struct QueryBounds {
    pub(crate) min_query_primary: U256,
    pub(crate) max_query_primary: U256,
    pub(crate) min_query_secondary: QueryBoundSecondary,
    pub(crate) max_query_secondary: QueryBoundSecondary,
}

impl QueryBounds {
    /// Initialize `QueryBounds`. Bounds for secondary indexes are optional as they might not have been specified
    /// in the query
    pub fn new(
        min_query_primary: U256,
        max_query_primary: U256,
        min_query_secondary: Option<QueryBoundSecondary>,
        max_query_secondary: Option<QueryBoundSecondary>,
    ) -> Self {
        Self {
            min_query_primary,
            max_query_primary,
            min_query_secondary: min_query_secondary.unwrap_or(QueryBoundSecondary {
                value: U256::ZERO,
                id: None,
            }),
            max_query_secondary: max_query_secondary.unwrap_or(QueryBoundSecondary {
                value: U256::MAX,
                id: None,
            }),
        }
    }
}

/// Data structure containing all the information needed as input by aggregation circuits for a single node of the tree
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NodeInfo {
    /// The hash of the embedded tree at this node. It can be the hash of the row tree if this node is a node in
    /// the index tree, or it can be a hash of the cells tree if this node is a node in a rows tree
    pub(crate) embedded_tree_hash: HashOut<F>,
    /// Hashes of the children of the current node, first left child and then right child hash. The hash of left/right child
    /// is the empty hash (i.e., H("")) if there is no corresponding left/right child for the current node
    pub(crate) child_hashes: [HashOut<F>; 2],
    /// value stored in the node. It can be a primary index value if the node is a node in the index tree,
    /// a secondary index value if the node is a node in a rows tree
    pub(crate) value: U256,
    /// minimum value associated to the current node. It can be a primary index value if the node is a node in the index tree,
    /// a secondary index value if the node is a node in a rows tree
    pub(crate) min: U256,
    /// minimum value associated to the current node. It can be a primary index value if the node is a node in the index tree,
    /// a secondary index value if the node is a node in a rows tree
    pub(crate) max: U256,
}

impl NodeInfo {
    /// Instantiate a new `NodeInfo` from the data stored in the node and the
    /// child hashes, if any
    pub fn new(
        embedded_tree_hash: &HashOutput,
        left_child_hash: Option<&HashOutput>,
        right_child_hash: Option<&HashOutput>,
        value: U256,
        min: U256,
        max: U256,
    ) -> Self {
        let child_hashes = [
            left_child_hash
                .map(|hash| HashOut::from_bytes(hash.into()))
                .unwrap_or(*empty_poseidon_hash()),
            right_child_hash
                .map(|hash| HashOut::from_bytes(hash.into()))
                .unwrap_or(*empty_poseidon_hash()),
        ];
        Self {
            embedded_tree_hash: HashOut::from_bytes(embedded_tree_hash.into()),
            child_hashes,
            value,
            min,
            max,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
/// enum to specify whether a node is the left or right child of another node
pub enum ChildPosition {
    Left,
    Right,
}

impl ChildPosition {
    // convert `self` to a flag specifying whether a node is the left child of another node or not
    pub(crate) fn to_flag(&self) -> bool {
        match self {
            ChildPosition::Left => true,
            ChildPosition::Right => false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CommonInputs {
    pub(crate) is_rows_tree_node: bool,
    pub(crate) min_query: U256,
    pub(crate) max_query: U256,
}

impl CommonInputs {
    pub(crate) fn new(is_rows_tree_node: bool, query_bounds: &QueryBounds) -> Self {
        Self {
            is_rows_tree_node,
            min_query: if is_rows_tree_node {
                query_bounds.min_query_secondary.value
            } else {
                query_bounds.min_query_primary
            },
            max_query: if is_rows_tree_node {
                query_bounds.max_query_secondary.value
            } else {
                query_bounds.max_query_primary
            },
        }
    }
}
/// Input data structure for circuits employed for nodes where both the children and the embedded tree are proven
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TwoProvenChildNodeInput {
    /// Proof for the left child of the node being proven
    pub(crate) left_child_proof: ProofWithVK,
    /// Proof for the right child of the node being proven
    pub(crate) right_child_proof: ProofWithVK,
    /// Proof for the embedded tree stored in the current node
    pub(crate) embedded_tree_proof: ProofWithVK,
    /// Common inputs shared across all the circuits
    pub(crate) common: CommonInputs,
}
/// Input data structure for circuits employed for nodes where one child and the embedded tree are proven
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OneProvenChildNodeInput {
    /// Data related to the child not associated with a proof, if any
    pub(crate) unproven_child: Option<NodeInfo>,
    /// Proof for the proven child
    pub(crate) proven_child_proof: ChildProof,
    /// Proof for the embedded tree stored in the current node
    pub(crate) embedded_tree_proof: ProofWithVK,
    /// Common inputs shared across all the circuits
    pub(crate) common: CommonInputs,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
/// Data structure representing a proof for a child node
pub struct ChildProof {
    /// Actual proof
    pub(crate) proof: ProofWithVK,
    /// Flag specifying whether the child associated with `proof` is the left or right child of its parent
    pub(crate) child_position: ChildPosition,
}

impl ChildProof {
    pub fn new(proof: Vec<u8>, child_position: ChildPosition) -> Result<ChildProof> {
        Ok(Self {
            proof: ProofWithVK::deserialize(&proof)?,
            child_position,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Enum employed to specify whether a proof refers to a child node or the embedded tree stored in a node
pub enum SubProof {
    /// Proof refer to a child
    Child(ChildProof),
    /// Proof refer to the embedded tree stored in the node: can be either the proof for a single row
    /// (if proving a rows tree node) of the proof for the root node of a rows tree (if proving an index tree node)
    Embedded(ProofWithVK),
}

impl SubProof {
    /// Initialize a new `SubProof::Child`
    pub fn new_child_proof(proof: Vec<u8>, child_position: ChildPosition) -> Result<Self> {
        Ok(SubProof::Child(ChildProof::new(proof, child_position)?))
    }

    /// Initialize a new `SubProof::Embedded`
    pub fn new_embedded_tree_proof(proof: Vec<u8>) -> Result<Self> {
        Ok(SubProof::Embedded(ProofWithVK::deserialize(&proof)?))
    }
}

/// Input data structure for circuits employed for nodes where only one among children node and embedded tree is proven
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SinglePathInput {
    /// Data about the left child of the node being proven, if any
    pub(crate) left_child: Option<NodeInfo>,
    /// Data about the right child of the node being proven, if any
    pub(crate) right_child: Option<NodeInfo>,
    /// Data about the node being proven
    pub(crate) node_info: NodeInfo,
    /// Proof of either a child node or of the embedded tree stored in the current node
    pub(crate) subtree_proof: SubProof,
    /// Common inputs shared across all the circuits
    pub(crate) common: CommonInputs,
}

/// Data structure containing the computational hash and placeholder hash to be provided as input to
/// non-existence circuits. These hashes are computed from the query specific data provided as input
/// to the initialization method of this data structure
pub struct QueryHashNonExistenceCircuits {
    pub(crate) computational_hash: ComputationalHash,
    pub(crate) placeholder_hash: PlaceholderHash,
}

impl QueryHashNonExistenceCircuits {
    pub fn new<
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_PREDICATE_OPS: usize,
        const MAX_NUM_RESULT_OPS: usize,
        const MAX_NUM_RESULTS: usize,
    >(
        column_cells: &[ColumnCell],
        predicate_operations: &[BasicOperation],
        results: &ResultStructure,
        placeholders: &Placeholders,
        query_bounds: &QueryBounds,
        is_rows_tree_node: bool,
    ) -> Result<Self>
    where
        [(); MAX_NUM_RESULTS - 1]:,
        [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
        [(); 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS)]:,
    {
        let column_ids = column_cells
            .iter()
            .map(|cell| cell.id.to_canonical_u64())
            .collect_vec();
        let computational_hash = if is_rows_tree_node {
            Identifiers::computational_hash_without_query_bounds(
                &column_ids,
                predicate_operations,
                results,
            )?
        } else {
            ComputationalHash::from_bytes(
                (&Identifiers::computational_hash_universal_circuit(
                    &column_ids,
                    predicate_operations,
                    results,
                    &(&query_bounds.min_query_secondary).into(),
                    &(&query_bounds.max_query_secondary).into(),
                )?)
                    .into(),
            )
        };
        let placeholder_hash_ids = CircuitInput::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
        >::ids_for_placeholder_hash(
            column_cells,
            predicate_operations,
            results,
            placeholders,
            query_bounds,
        )?;
        let placeholder_hash = if is_rows_tree_node {
            placeholder_hash_without_query_bounds(&placeholder_hash_ids, &placeholders)
        } else {
            placeholder_hash(&placeholder_hash_ids, &placeholders, query_bounds)
        }?;
        Ok(Self {
            computational_hash,
            placeholder_hash,
        })
    }
}

/// Input data structure for circuits employed to prove the non-existence of rows satisfying the query bounds
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonExistenceInput<const MAX_NUM_RESULTS: usize> {
    /// Data about the node being proven
    pub(crate) node_info: NodeInfo,
    /// Data about the child of the node, if any
    pub(crate) child_info: Option<NodeInfo>,
    /// Flag specifying whether the node hash a left or right child, if any
    pub(crate) is_child_left: Option<bool>,
    /// Value of the primary index associated to the current node
    pub(crate) primary_index_value: U256,
    /// Identifier of primary and secondary indexed columns
    pub(crate) index_ids: [F; 2],
    /// Computational hash associated to the query
    pub(crate) computational_hash: ComputationalHash,
    /// Placeholder hash associated to the query
    pub(crate) placeholder_hash: PlaceholderHash,
    /// Set of aggregation operations employed to aggregate results
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) aggregation_ops: [F; MAX_NUM_RESULTS],
    /// Flag specifying whether the node being proven belongs to the rows tree or not
    pub(crate) is_rows_tree_node: bool,
    /// Minimum query bound found in the query for primary or secondary index, depending on
    /// whether the node being proven belongs to the index tree or not
    pub(crate) min_query: QueryBound,
    /// Maximum query bound found in the query for primary or secondary index, depending on
    /// whether the node being proven belongs to the index tree or not
    pub(crate) max_query: QueryBound,
    /// Value of the dummy placeholder, employed in placeholder hash in case one of the min/max
    /// query index bounds are taken from a constant in the query
    pub(crate) dummy_placeholder_value: U256,
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::query::{
        computational_hash_ids::{AggregationOperation, Identifiers},
        public_inputs::{PublicInputs, QueryPublicInputs},
        PI_LEN,
    };
    use alloy::primitives::U256;
    use mp2_common::{
        array::ToField, group_hashing::add_curve_point, types::CURVE_TARGET_LEN, utils::ToFields, F,
    };
    use mp2_test::utils::random_vector;
    use plonky2::{
        field::types::{Field, Sample},
        hash::hash_types::NUM_HASH_OUT_ELTS,
    };
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{prelude::SliceRandom, thread_rng, Rng};
    use std::array;

    /// Generate a field array of S random aggregation operations.
    pub(crate) fn random_aggregation_operations<const S: usize>() -> [F; S] {
        let ops = [
            AggregationOperation::IdOp,
            AggregationOperation::SumOp,
            AggregationOperation::MinOp,
            AggregationOperation::MaxOp,
            AggregationOperation::AvgOp,
        ];

        let mut rng = thread_rng();
        array::from_fn(|_| {
            let op = *ops.choose(&mut rng).unwrap();
            Identifiers::AggregationOperations(op).to_field()
        })
    }

    /// Generate S number of proof public input slices by the specified operations.
    /// The each returned proof public inputs could be constructed by
    /// `PublicInputs::from_slice` function.
    pub(crate) fn random_aggregation_public_inputs<const N: usize, const S: usize>(
        ops: &[F; S],
    ) -> [Vec<F>; N] {
        let [ops_range, overflow_range, index_ids_range, c_hash_range, p_hash_range] = [
            QueryPublicInputs::OpIds,
            QueryPublicInputs::Overflow,
            QueryPublicInputs::IndexIds,
            QueryPublicInputs::ComputationalHash,
            QueryPublicInputs::PlaceholderHash,
        ]
        .map(PublicInputs::<F, S>::to_range);

        let first_value_start =
            PublicInputs::<F, S>::to_range(QueryPublicInputs::OutputValues).start;
        let is_first_op_id =
            ops[0] == Identifiers::AggregationOperations(AggregationOperation::IdOp).to_field();

        // Generate the index ids, computational hash and placeholder hash,
        // they should be same for a series of public inputs.
        let mut rng = thread_rng();
        let index_ids: Vec<_> = random_vector::<u32>(2).to_fields();
        let [computational_hash, placeholder_hash]: [Vec<_>; 2] =
            array::from_fn(|_| random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields());

        array::from_fn(|_| {
            let mut pi = random_vector::<u32>(PI_LEN::<S>).to_fields();

            // Copy the specified operations to the proofs.
            pi[ops_range.clone()].copy_from_slice(ops);

            // Set the overflow flag to a random boolean.
            let overflow = F::from_bool(rng.gen());
            pi[overflow_range.clone()].copy_from_slice(&[overflow]);

            // Set the index ids, computational hash and placeholder hash,
            pi[index_ids_range.clone()].copy_from_slice(&index_ids);
            pi[c_hash_range.clone()].copy_from_slice(&computational_hash);
            pi[p_hash_range.clone()].copy_from_slice(&placeholder_hash);

            // If the first operation is ID, set the value to a random point.
            if is_first_op_id {
                let first_value = Point::sample(&mut rng).to_weierstrass().to_fields();
                pi[first_value_start..first_value_start + CURVE_TARGET_LEN]
                    .copy_from_slice(&first_value);
            }

            pi
        })
    }

    /// Compute the output values and the overflow number at the specified index by
    /// the proofs. It's the test function corresponding to `compute_output_item`.
    pub(crate) fn compute_output_item_value<const S: usize>(
        i: usize,
        proofs: &[&PublicInputs<F, S>],
    ) -> (Vec<F>, u32)
    where
        [(); S - 1]:,
    {
        let proof0 = &proofs[0];
        let op = proof0.operation_ids()[i];

        let [op_id, op_min, op_max, op_sum, op_avg] = [
            AggregationOperation::IdOp,
            AggregationOperation::MinOp,
            AggregationOperation::MaxOp,
            AggregationOperation::SumOp,
            AggregationOperation::AvgOp,
        ]
        .map(|op| Identifiers::AggregationOperations(op).to_field());

        let is_op_id = op == op_id;
        let is_op_min = op == op_min;
        let is_op_max = op == op_max;
        let is_op_sum = op == op_sum;
        let is_op_avg = op == op_avg;

        // Check that the all proofs are employing the same aggregation operation.
        proofs[1..]
            .iter()
            .for_each(|p| assert_eq!(p.operation_ids()[i], op));

        // Compute the SUM, MIN or MAX value.
        let mut sum_overflow = 0;
        let mut output = proof0.value_at_index(i);
        if i == 0 && is_op_id {
            // If it's the first proof and the operation is ID,
            // the value is a curve point not a Uint256.
            output = U256::ZERO;
        }
        for p in proofs[1..].iter() {
            // Get the current proof value.
            let mut value = p.value_at_index(i);
            if i == 0 && is_op_id {
                // If it's the first proof and the operation is ID,
                // the value is a curve point not a Uint256.
                value = U256::ZERO;
            }

            // Compute the MIN or MAX value.
            if is_op_min {
                output = output.min(value);
            } else if is_op_max {
                output = output.max(value);
            } else {
                // Compute the SUM value and the overflow.
                let (addition, overflow) = output.overflowing_add(value);
                output = addition;
                if overflow {
                    sum_overflow += 1;
                }
            }
        }

        let mut output = output.to_fields();
        if i == 0 {
            // We always accumulate order-agnostic digest of the proofs for the first item.
            output = if is_op_id {
                let points: Vec<_> = proofs
                    .iter()
                    .map(|p| Point::decode(p.first_value_as_curve_point().encode()).unwrap())
                    .collect();
                add_curve_point(&points).to_fields()
            } else {
                // Pad the current output to ``CURVE_TARGET_LEN` for the first item.
                PublicInputs::<_, S>::pad_slice_to_curve_len(&output)
            };
        }

        // Set the overflow if the operation is SUM or AVG:
        // overflow = op == SUM OR op == AVG ? sum_overflow : 0
        let overflow = if is_op_sum || is_op_avg {
            sum_overflow
        } else {
            0
        };

        (output, overflow)
    }
}
