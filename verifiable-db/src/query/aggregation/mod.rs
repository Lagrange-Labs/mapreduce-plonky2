use std::{array, iter::once};

use alloy::primitives::U256;
use anyhow::Result;
use itertools::Itertools;
use mp2_common::{
    poseidon::{empty_poseidon_hash, HashPermutation},
    proof::ProofWithVK,
    serialization::{deserialize_long_array, serialize_long_array, serialize, deserialize, serialize_array, deserialize_array},
    types::{CBuilder, HashOutput},
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{Fieldable, ToFields, ToTargets},
    CHasher, F,
};
use plonky2::{
    field::types::Field,
    hash::{
        hash_types::{HashOut, HashOutTarget},
        hashing::hash_n_to_hash_no_pad,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::config::GenericHashOut,
};
use serde::{Deserialize, Serialize};

pub(crate) mod child_proven_single_path_node;
pub(crate) mod embedded_tree_proven_single_path_node;
pub(crate) mod full_node_index_leaf;
pub(crate) mod full_node_with_one_child;
pub(crate) mod full_node_with_two_children;
pub(crate) mod non_existence_inter;
mod output_computation;
pub(crate) mod partial_node;
mod utils;

use super::{
    api::CircuitInput,
    computational_hash_ids::{ColumnIDs, Identifiers, PlaceholderIdentifier},
    universal_circuit::{
        universal_circuit_inputs::{BasicOperation, PlaceholderId, Placeholders, ResultStructure},
        universal_query_circuit::{placeholder_hash, placeholder_hash_without_query_bounds},
        universal_query_gadget::QueryBound,
        ComputationalHash, PlaceholderHash,
    },
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Data structure representing a query bound on secondary index
pub struct QueryBoundSecondary {
    /// value of the query bound. Could come either from a constant in the query or from a placeholder
    pub(crate) value: U256,
    pub(crate) overflow: bool,
    pub(crate) source: QueryBoundSource,
}
impl QueryBoundSecondary {
    pub fn is_bounded_low(&self) -> bool {
        self.value != U256::ZERO
    }

    pub fn is_bounded_high(&self) -> bool {
        self.value != U256::MAX
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Enumeration employed to specify whether a query bound for secondary indexed is taken in the query from
/// a constant or from a placeholder
pub enum QueryBoundSource {
    // Query bound is a constant
    Constant(U256),
    /// Query bound taken from placeholder with id
    Placeholder(PlaceholderId),
    /// Query bound computed with a basic operation
    Operation(BasicOperation),
}

impl From<&QueryBoundSecondary> for QueryBoundSource {
    fn from(value: &QueryBoundSecondary) -> Self {
        value.source.clone()
    }
}

impl QueryBoundSecondary {
    pub fn new(placeholders: &Placeholders, source: QueryBoundSource) -> Result<Self> {
        let (value, overflow) = QueryBound::compute_bound_value(placeholders, &source)?;
        Ok(Self {
            value,
            overflow,
            source,
        })
    }

    pub fn new_constant_bound(value: U256) -> Self {
        Self {
            value,
            overflow: false,
            source: QueryBoundSource::Constant(value),
        }
    }

    pub fn value(&self) -> &U256 {
        &self.value
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Data structure storing the query bounds specified in the query for primary and secondary index
pub struct QueryBounds {
    min_query_primary: U256,
    max_query_primary: U256,
    min_query_secondary: QueryBoundSecondary,
    max_query_secondary: QueryBoundSecondary,
}

impl QueryBounds {
    /// Initialize `QueryBounds`. Bounds for secondary indexes are optional as they might not have been specified
    /// in the query
    pub fn new(
        placeholders: &Placeholders,
        min_query_secondary: Option<QueryBoundSource>,
        max_query_secondary: Option<QueryBoundSource>,
    ) -> Result<Self> {
        Ok(Self {
            min_query_primary: placeholders.get(&PlaceholderIdentifier::MinQueryOnIdx1)?,
            max_query_primary: placeholders.get(&PlaceholderIdentifier::MaxQueryOnIdx1)?,
            min_query_secondary: min_query_secondary
                .map(|source| QueryBoundSecondary::new(placeholders, source))
                .unwrap_or(Ok(QueryBoundSecondary::new_constant_bound(U256::ZERO)))?,
            max_query_secondary: max_query_secondary
                .map(|source| QueryBoundSecondary::new(placeholders, source))
                .unwrap_or(Ok(QueryBoundSecondary::new_constant_bound(U256::MAX)))?,
        })
    }

    pub fn is_primary_in_range(&self, v: &U256) -> bool {
        &self.min_query_primary <= v && v <= &self.max_query_primary
    }

    // Getter functions for the struct fields
    pub fn min_query_primary(&self) -> U256 {
        self.min_query_primary
    }
    pub fn max_query_primary(&self) -> U256 {
        self.max_query_primary
    }
    pub fn min_query_secondary(&self) -> &QueryBoundSecondary {
        &self.min_query_secondary
    }
    pub fn max_query_secondary(&self) -> &QueryBoundSecondary {
        &self.max_query_secondary
    }
}

/// Data structure containing all the information needed as input by aggregation circuits for a single node of the tree
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Flag specifying whether this is a leaf node or not
    pub(crate) is_leaf: bool,
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
            is_leaf: left_child_hash.is_none() && right_child_hash.is_none(),
        }
    }

    pub fn node_hash(&self, index_id: u64) -> HashOutput {
        HashOutput::try_from(self.compute_node_hash(index_id.to_field()).to_bytes()).unwrap()
    }

    pub(crate) fn compute_node_hash(&self, index_id: F) -> HashOut<F> {
        hash_n_to_hash_no_pad::<F, HashPermutation>(
            &self
                .child_hashes
                .into_iter()
                .flat_map(|h| h.to_vec())
                .chain(self.min.to_fields())
                .chain(self.max.to_fields())
                .chain(once(index_id))
                .chain(self.value.to_fields())
                .chain(self.embedded_tree_hash.to_vec())
                .collect_vec(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct NodeInfoTarget {
    /// The hash of the embedded tree at this node. It can be the hash of the row tree if this node is a node in
    /// the index tree, or it can be a hash of the cells tree if this node is a node in a rows tree
    #[serde(serialize_with="serialize", deserialize_with="deserialize")]
    pub(crate) embedded_tree_hash: HashOutTarget,
    /// Hashes of the children of the current node, first left child and then right child hash. The hash of left/right child
    /// is the empty hash (i.e., H("")) if there is no corresponding left/right child for the current node
    #[serde(serialize_with="serialize_array", deserialize_with="deserialize_array")]
    pub(crate) child_hashes: [HashOutTarget; 2],
    /// value stored in the node. It can be a primary index value if the node is a node in the index tree,
    /// a secondary index value if the node is a node in a rows tree
    pub(crate) value: UInt256Target,
    /// minimum value associated to the current node. It can be a primary index value if the node is a node in the index tree,
    /// a secondary index value if the node is a node in a rows tree
    pub(crate) min: UInt256Target,
    /// minimum value associated to the current node. It can be a primary index value if the node is a node in the index tree,
    /// a secondary index value if the node is a node in a rows tree
    pub(crate) max: UInt256Target,
}

impl NodeInfoTarget {
    pub(crate) fn build(b: &mut CBuilder) -> Self {
        let [value, min, max] = b.add_virtual_u256_arr();
        let [left_child_hash, right_child_hash, embedded_tree_hash] =
            array::from_fn(|_| b.add_virtual_hash());
        Self {
            embedded_tree_hash,
            child_hashes: [left_child_hash, right_child_hash],
            value,
            min,
            max,
        }
    }

    /// Build an instance of `Self` without range-check the `UInt256Target`s
    pub(crate) fn build_unsafe(b: &mut CBuilder) -> Self {
        let [value, min, max] = b.add_virtual_u256_arr_unsafe();
        let [left_child_hash, right_child_hash, embedded_tree_hash] =
            array::from_fn(|_| b.add_virtual_hash());
        Self {
            embedded_tree_hash,
            child_hashes: [left_child_hash, right_child_hash],
            value,
            min,
            max,
        }
    }

    pub(crate) fn compute_node_hash(&self, b: &mut CBuilder, index_id: Target) -> HashOutTarget {
        let inputs = self.child_hashes[0]
            .to_targets()
            .into_iter()
            .chain(self.child_hashes[1].to_targets())
            .chain(self.min.to_targets())
            .chain(self.max.to_targets())
            .chain(once(index_id))
            .chain(self.value.to_targets())
            .chain(self.embedded_tree_hash.to_targets())
            .collect_vec();
        b.hash_n_to_hash_no_pad::<CHasher>(inputs)
    }

    pub(crate) fn set_target(&self, pw: &mut PartialWitness<F>, inputs: &NodeInfo) {
        [
            (self.embedded_tree_hash, inputs.embedded_tree_hash),
            (self.child_hashes[0], inputs.child_hashes[0]),
            (self.child_hashes[1], inputs.child_hashes[1]),
        ]
        .into_iter()
        .for_each(|(target, value)| pw.set_hash_target(target, value));
        pw.set_u256_target_arr(
            &[self.min.clone(), self.max.clone(), self.value.clone()],
            &[inputs.min, inputs.max, inputs.value],
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    computational_hash: ComputationalHash,
    placeholder_hash: PlaceholderHash,
}

impl QueryHashNonExistenceCircuits {
    pub fn new<
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_PREDICATE_OPS: usize,
        const MAX_NUM_RESULT_OPS: usize,
        const MAX_NUM_RESULTS: usize,
    >(
        column_ids: &ColumnIDs,
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
                    Some((&query_bounds.min_query_secondary).into()),
                    Some((&query_bounds.max_query_secondary).into()),
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
            predicate_operations, results, placeholders, query_bounds
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

    // Getter functions for the struct fields
    pub fn computational_hash(&self) -> ComputationalHash {
        self.computational_hash
    }
    pub fn placeholder_hash(&self) -> PlaceholderHash {
        self.placeholder_hash
    }
}

/// Input data structure for circuits employed to prove the non-existence of rows satisfying the query bounds
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonExistenceInput<const MAX_NUM_RESULTS: usize> {
    /// Data about the node being proven
    pub(crate) node_info: NodeInfo,
    /// Data about the left child of the node, if any
    pub(crate) left_child_info: Option<NodeInfo>,
    /// Data about the left child of the node, if any
    pub(crate) right_child_info: Option<NodeInfo>,
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
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::query::{
        computational_hash_ids::{AggregationOperation, Identifiers},
        public_inputs::PublicInputs, universal_circuit::universal_query_gadget::{CurveOrU256, OutputValues},
    };
    use alloy::primitives::U256;
    use itertools::Itertools;
    use mp2_common::{array::ToField, group_hashing::add_curve_point, utils::{FromFields, ToFields}, F};
    use plonky2_ecgfp5::curve::curve::Point;

    /// Aggregate the i-th output values found in `outputs` according to the aggregation operation
    /// with identifier `op`. It's the test function corresponding to `OutputValuesTarget::aggregate_outputs`
    pub(crate) fn aggregate_output_values<const S: usize>(
        i: usize,
        outputs: &[OutputValues<S>],
        op: F,
    ) -> (Vec<F>, u32) 
    where [(); S-1]:,
    {   
        let out0 = &outputs[0];

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

        // Compute the SUM, MIN or MAX value.
        let mut sum_overflow = 0;
        let mut output = out0.value_at_index(i);
        if i == 0 && is_op_id {
            // If it's the first proof and the operation is ID,
            // the value is a curve point not a Uint256.
            output = U256::ZERO;
        }
        for out in outputs[1..].iter() {
            // Get the current proof value.
            let mut value = out.value_at_index(i);
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
                let points: Vec<_> = outputs
                    .iter()
                    .map(|out| Point::decode(out.first_value_as_curve_point().encode()).unwrap())
                    .collect();
                add_curve_point(&points).to_fields()
            } else {
                // Pad the current output to ``CURVE_TARGET_LEN` for the first item.
                CurveOrU256::from_slice(&output).to_vec()
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

        // Check that the all proofs are employing the same aggregation operation.
        proofs[1..]
            .iter()
            .for_each(|p| assert_eq!(p.operation_ids()[i], op));

        let outputs = proofs.iter().map(|p| 
            OutputValues::from_fields(p.to_values_raw())
        ).collect_vec();
        
        aggregate_output_values(i, &outputs, op)
    }
}
