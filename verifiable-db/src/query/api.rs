use std::{collections::HashMap, iter::repeat};

use crate::query::aggregation::full_node_index_leaf::FullNodeIndexLeafCircuit;

use super::{
    aggregation::{
        child_proven_single_path_node::{
            ChildProvenSinglePathNodeCircuit, ChildProvenSinglePathNodeWires,
            NUM_VERIFIED_PROOFS as NUM_PROOFS_CHILD,
        },
        embedded_tree_proven_single_path_node::{
            EmbeddedTreeProvenSinglePathNodeCircuit, EmbeddedTreeProvenSinglePathNodeWires,
            NUM_VERIFIED_PROOFS as NUM_PROOFS_EMBEDDED,
        },
        full_node_index_leaf::{FullNodeIndexLeafWires, NUM_VERIFIED_PROOFS as NUM_PROOFS_LEAF},
        full_node_with_one_child::{
            FullNodeWithOneChildCircuit, FullNodeWithOneChildWires,
            NUM_VERIFIED_PROOFS as NUM_PROOFS_FN1,
        },
        full_node_with_two_children::{
            FullNodeWithTwoChildrenCircuit, FullNodeWithTwoChildrenWires,
            NUM_VERIFIED_PROOFS as NUM_PROOFS_FN2,
        },
        non_existence_inter::{
            self, NonExistenceInterNodeCircuit, NonExistenceInterNodeWires,
            NUM_VERIFIED_PROOFS as NUM_PROOFS_NE_INTER,
        },
        non_existence_leaf::{
            self, NonExistenceLeafCircuit, NonExistenceLeafWires,
            NUM_VERIFIED_PROOFS as NUM_PROOFS_NE_LEAF,
        },
        partial_node::{
            self, PartialNodeCircuit, PartialNodeWires, NUM_VERIFIED_PROOFS as NUM_PROOFS_PN,
        },
        ChildPosition, ChildProof, CommonInputs, NodeInfo, NonExistenceInput,
        OneProvenChildNodeInput, QueryBounds, QueryHashNonExistenceCircuits, SinglePathInput,
        SubProof, TwoProvenChildNodeInput,
    },
    computational_hash_ids::{AggregationOperation, HashPermutation, Output},
    universal_circuit::{
        output_no_aggregation::Circuit as NoAggOutputCircuit,
        output_with_aggregation::Circuit as AggOutputCircuit,
        universal_circuit_inputs::{BasicOperation, ColumnCell, PlaceholderId, ResultStructure},
        universal_query_circuit::{
            placeholder_hash, UniversalCircuitInput, UniversalQueryCircuitInputs,
            UniversalQueryCircuitWires,
        },
        ComputationalHash, PlaceholderHash,
    },
    PI_LEN,
};
use alloy::primitives::U256;
use anyhow::{ensure, Result};
use itertools::Itertools;
use mp2_common::{
    array::ToField,
    default_config,
    proof::ProofWithVK,
    types::HashOutput,
    utils::{Fieldable, ToFields},
    C, D, F,
};
use plonky2::{
    hash::{hashing::hash_n_to_hash_no_pad, poseidon::PoseidonHash},
    plonk::config::{GenericHashOut, Hasher},
};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{
        prepare_recursive_circuit_for_circuit_set, RecursiveCircuitInfo, RecursiveCircuits,
    },
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)] // we need to clone data if we fix by put variants inside a `Box`
pub enum CircuitInput<
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
> {
    /// Inputs for the universal query circuit
    UniversalCircuit(
        UniversalCircuitInput<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
        >,
    ),
    /// Inputs for circuits with 2 proven children and a proven embedded tree
    TwoProvenChildNode(TwoProvenChildNodeInput),
    /// Inputs for circuits proving a node with one proven child and a proven embedded tree
    OneProvenChildNode(OneProvenChildNodeInput),
    /// Inputs for circuits proving a node with only one proven subtree (either a proven child or the embedded tree)
    SinglePath(SinglePathInput),
    /// Inputs for circuits to prove non-existence of results for the current query
    NonExistence(NonExistenceInput<MAX_NUM_RESULTS>),
}

impl<
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_PREDICATE_OPS: usize,
        const MAX_NUM_RESULT_OPS: usize,
        const MAX_NUM_RESULTS: usize,
    > CircuitInput<MAX_NUM_COLUMNS, MAX_NUM_PREDICATE_OPS, MAX_NUM_RESULT_OPS, MAX_NUM_RESULTS>
where
    [(); MAX_NUM_RESULTS - 1]:,
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
    [(); 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS)]:,
{
    /// Initialize input for universal circuit to prove the execution of a query over a
    /// single row, from the following inputs:
    /// - `column_cells`: set of columns (including primary and secondary indexes) of the row being proven
    /// - `predicate_operations`: Set of operations employed to compute the filtering predicate of the query for the
    ///     row being proven
    /// - `results`: Data structure specifying how the results for each row are computed according to the query
    /// - `placeholder_values`: Set of values employed for placeholder in the query
    /// - `is_leaf`: Flag specifying whether the row being proven is stored in a leaf node of the rows tree or not
    /// - `query_bounds`: bounds on primary and secondary indexes specified in the query
    /// Note that the following assumption is expected on the structure of the inputs:
    /// The output of the last operation in `predicate_operations` will be taken as the filtering predicate evaluation;
    /// this is an assumption exploited in the circuit for efficiency, and it is a simple assumption to be required for
    /// the caller of this method
    pub fn new_universal_circuit(
        column_cells: &[ColumnCell],
        predicate_operations: &[BasicOperation],
        results: &ResultStructure,
        placeholder_values: &HashMap<PlaceholderId, U256>,
        is_leaf: bool,
        query_bounds: &QueryBounds,
    ) -> Result<Self> {
        Ok(CircuitInput::UniversalCircuit(
            match results.output_variant {
                Output::Aggregation => UniversalCircuitInput::new_query_with_agg(
                    column_cells,
                    predicate_operations,
                    placeholder_values,
                    is_leaf,
                    query_bounds,
                    results,
                )?,
                Output::NoAggregation => UniversalCircuitInput::new_query_no_agg(
                    column_cells,
                    predicate_operations,
                    placeholder_values,
                    is_leaf,
                    query_bounds,
                    results,
                )?,
            },
        ))
    }

    /// Initialize input to prove a full node from the following inputs:
    /// - `left_child_proof`: proof for the left child of the node being proven
    /// - `right_child_proof`: proof for the right child of the node being proven
    /// - `embedded_tree_proof`: proof for the embedded tree stored in the full node: can be either the proof for a single
    ///     row (if proving a rows tree node) of the proof for the root node of a rows tree (if proving an index tree node)
    /// - `is_rows_tree_node`: flag specifying whether the full node belongs to the rows tree or to the index tree
    /// - `query_bounds`: bounds on primary and secondary indexes specified in the query
    pub fn new_full_node(
        left_child_proof: Vec<u8>,
        right_child_proof: Vec<u8>,
        embedded_tree_proof: Vec<u8>,
        is_rows_tree_node: bool,
        query_bounds: &QueryBounds,
    ) -> Result<Self> {
        Ok(CircuitInput::TwoProvenChildNode(TwoProvenChildNodeInput {
            left_child_proof: ProofWithVK::deserialize(&left_child_proof)?,
            right_child_proof: ProofWithVK::deserialize(&right_child_proof)?,
            embedded_tree_proof: ProofWithVK::deserialize(&embedded_tree_proof)?,
            common: CommonInputs::new(is_rows_tree_node, query_bounds),
        }))
    }

    /// Initialize input to prove a partial node from the following inputs:
    /// - `proven_child_proof`: Proof for the child being a proven node
    /// - `embedded_tree_proof`: Proof for the embedded tree stored in the partial node: can be either the proof
    ///     for a single row (if proving a rows tree node) of the proof for the root node of a rows
    ///     tree (if proving an index tree node)
    /// - `unproven_child`: Data about the child not being a proven node; if the node has only one child,
    ///     then, this parameter must be `None`
    /// - `proven_child_position`: Enum specifying whether the proven child is the left or right child
    ///     of the partial node being proven
    /// - `is_rows_tree_node`: flag specifying whether the full node belongs to the rows tree or to the index tree
    /// - `query_bounds`: bounds on primary and secondary indexes specified in the query
    pub fn new_partial_node(
        proven_child_proof: Vec<u8>,
        embedded_tree_proof: Vec<u8>,
        unproven_child: Option<NodeInfo>,
        proven_child_position: ChildPosition,
        is_rows_tree_node: bool,
        query_bounds: &QueryBounds,
    ) -> Result<Self> {
        Ok(CircuitInput::OneProvenChildNode(OneProvenChildNodeInput {
            unproven_child,
            proven_child_proof: ChildProof {
                proof: ProofWithVK::deserialize(&proven_child_proof)?,
                child_position: proven_child_position,
            },
            embedded_tree_proof: ProofWithVK::deserialize(&embedded_tree_proof)?,
            common: CommonInputs::new(is_rows_tree_node, query_bounds),
        }))
    }
    /// Initialize input to prove a single path node from the following inputs:
    /// - `subtree_proof`: Proof of either a child node or of the embedded tree stored in the current node
    /// - `left_child`: Data about the left child of the current node, if any; must be `None` if the node has
    ///     no left child
    /// - `right_child`: Data about the right child of the current node, if any; must be `None` if the node has
    ///     no right child
    /// - `node_info`: Data about the current node being proven
    /// - `is_rows_tree_node`: flag specifying whether the full node belongs to the rows tree or to the index tree
    /// - `query_bounds`: bounds on primary and secondary indexes specified in the query
    pub fn new_single_path(
        subtree_proof: SubProof,
        left_child: Option<NodeInfo>,
        right_child: Option<NodeInfo>,
        node_info: NodeInfo,
        is_rows_tree_node: bool,
        query_bounds: &QueryBounds,
    ) -> Result<Self> {
        Ok(CircuitInput::SinglePath(SinglePathInput {
            left_child,
            right_child,
            node_info,
            subtree_proof,
            common: CommonInputs::new(is_rows_tree_node, query_bounds),
        }))
    }
    /// Initialize input to prove a node storing a value of the primary or secondary index which
    /// is outside of the query bounds, from the following inputs:
    /// - `node_info`: Data about the node being proven
    /// - `child_info`: Data aboout the child of the node being proven, altogether with the child position;
    ///     must be `None` if the node being proven has no children
    /// - `primary_index_value`: Value of the primary index associated to the current node
    /// - `index_ids`: Identifiers of the primary and secondary index columns
    /// - `aggregation_ops`: Set of aggregation operations employed to aggregate the results of the query
    /// - `query_hashes`: Computational hash and placeholder hash associated to the query; can be computed with the `new`
    ///     method of `QueryHashNonExistenceCircuits` data structure
    /// - `is_rows_tree_node`: flag specifying whether the full node belongs to the rows tree or to the index tree
    /// - `query_bounds`: bounds on primary and secondary indexes specified in the query
    #[allow(clippy::too_many_arguments)] // doesn't make sense to aggregate arguments
    pub fn new_non_existence_input(
        node_info: NodeInfo,
        child_info: Option<(NodeInfo, ChildPosition)>,
        primary_index_value: U256,
        index_ids: &[u64; 2],
        aggregation_ops: &[AggregationOperation],
        query_hashes: QueryHashNonExistenceCircuits,
        is_rows_tree_node: bool,
        query_bounds: &QueryBounds,
    ) -> Result<Self> {
        let aggregation_ops = aggregation_ops
            .iter()
            .map(|op| op.to_field())
            .chain(repeat(AggregationOperation::default().to_field()))
            .take(MAX_NUM_RESULTS)
            .collect_vec();
        Ok(CircuitInput::NonExistence(NonExistenceInput {
            node_info,
            child_info: child_info.clone().map(|info| info.0),
            is_child_left: child_info.map(|info| info.1.to_flag()),
            primary_index_value,
            index_ids: index_ids
                .iter()
                .map(|id| id.to_field())
                .collect_vec()
                .try_into()
                .unwrap(),
            computational_hash: query_hashes.computational_hash,
            placeholder_hash: query_hashes.placeholder_hash,
            aggregation_ops: aggregation_ops.try_into().unwrap(),
            common: CommonInputs::new(is_rows_tree_node, query_bounds),
        }))
    }

    /// This method returns the ids of the placeholders employed to compute the placeholder hash,
    /// in the same order, so that those ids can be provided as input to other circuits that need
    /// to recompute this hash
    pub fn ids_for_placeholder_hash(
        column_cells: &[ColumnCell],
        predicate_operations: &[BasicOperation],
        results: &ResultStructure,
        placeholder_values: &HashMap<PlaceholderId, U256>,
        query_bounds: &QueryBounds,
    ) -> Result<[PlaceholderId; 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS)]> {
        Ok(match results.output_variant {
            Output::Aggregation => {
                let circuit = UniversalQueryCircuitInputs::<
                    MAX_NUM_COLUMNS,
                    MAX_NUM_PREDICATE_OPS,
                    MAX_NUM_RESULT_OPS,
                    MAX_NUM_RESULTS,
                    AggOutputCircuit<MAX_NUM_RESULTS>,
                >::new(
                    column_cells,
                    predicate_operations,
                    placeholder_values,
                    false, // doesn't matter for placeholder hash computation
                    query_bounds,
                    results,
                )?;
                circuit.ids_for_placeholder_hash()
            }
            Output::NoAggregation => {
                let circuit = UniversalQueryCircuitInputs::<
                    MAX_NUM_COLUMNS,
                    MAX_NUM_PREDICATE_OPS,
                    MAX_NUM_RESULT_OPS,
                    MAX_NUM_RESULTS,
                    NoAggOutputCircuit<MAX_NUM_RESULTS>,
                >::new(
                    column_cells,
                    predicate_operations,
                    placeholder_values,
                    false, // doesn't matter for placeholder hash computation
                    query_bounds,
                    results,
                )?;
                circuit.ids_for_placeholder_hash()
            }
        }
        .try_into()
        .unwrap())
    }

    /// Compute the `placeholder_hash` associated to a query
    pub fn placeholder_hash(
        column_cells: &[ColumnCell],
        predicate_operations: &[BasicOperation],
        results: &ResultStructure,
        placeholder_values: &HashMap<PlaceholderId, U256>,
        query_bounds: &QueryBounds,
    ) -> Result<HashOutput> {
        let placeholder_hash_ids = Self::ids_for_placeholder_hash(
            column_cells,
            predicate_operations,
            results,
            placeholder_values,
            query_bounds,
        )?;
        let hash = placeholder_hash(&placeholder_hash_ids, placeholder_values, query_bounds)?;
        // add primary query bounds to placeholder hash
        HashOutput::try_from(
            hash_n_to_hash_no_pad::<_, HashPermutation>(
                &hash
                    .to_vec()
                    .into_iter()
                    .chain(query_bounds.min_query_primary.to_fields())
                    .chain(query_bounds.max_query_primary.to_fields())
                    .collect_vec(),
            )
            .to_bytes(),
        )
    }
}
#[derive(Serialize, Deserialize)]
pub struct Parameters<
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
> where
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
    [(); MAX_NUM_RESULTS - 1]:,
{
    circuit_with_agg: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        0,
        UniversalQueryCircuitWires<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            AggOutputCircuit<MAX_NUM_RESULTS>,
        >,
    >,
    circuit_no_agg: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        0,
        UniversalQueryCircuitWires<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            NoAggOutputCircuit<MAX_NUM_RESULTS>,
        >,
    >,
    full_node_two_children: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        NUM_PROOFS_FN2,
        FullNodeWithTwoChildrenWires<MAX_NUM_RESULTS>,
    >,
    full_node_one_child: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        NUM_PROOFS_FN1,
        FullNodeWithOneChildWires<MAX_NUM_RESULTS>,
    >,
    full_node_leaf: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        NUM_PROOFS_LEAF,
        FullNodeIndexLeafWires<MAX_NUM_RESULTS>,
    >,
    partial_node:
        CircuitWithUniversalVerifier<F, C, D, NUM_PROOFS_PN, PartialNodeWires<MAX_NUM_RESULTS>>,
    single_path_proven_child: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        NUM_PROOFS_CHILD,
        ChildProvenSinglePathNodeWires<MAX_NUM_RESULTS>,
    >,
    single_path_embedded_tree: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        NUM_PROOFS_EMBEDDED,
        EmbeddedTreeProvenSinglePathNodeWires<MAX_NUM_RESULTS>,
    >,
    non_existence_leaf: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        NUM_PROOFS_NE_LEAF,
        NonExistenceLeafWires<MAX_NUM_RESULTS>,
    >,
    non_existence_intermediate: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        NUM_PROOFS_NE_INTER,
        NonExistenceInterNodeWires<MAX_NUM_RESULTS>,
    >,
    circuit_set: RecursiveCircuits<F, C, D>,
}

const QUERY_CIRCUIT_SET_SIZE: usize = 10;
impl<
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_PREDICATE_OPS: usize,
        const MAX_NUM_RESULT_OPS: usize,
        const MAX_NUM_RESULTS: usize,
    > Parameters<MAX_NUM_COLUMNS, MAX_NUM_PREDICATE_OPS, MAX_NUM_RESULT_OPS, MAX_NUM_RESULTS>
where
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
    [(); MAX_NUM_RESULTS - 1]:,
    [(); PI_LEN::<MAX_NUM_RESULTS>]:,
    [(); <PoseidonHash as Hasher<F>>::HASH_SIZE]:,
{
    /// Build `Parameters` for query circuits
    pub fn build() -> Self {
        let builder =
            CircuitWithUniversalVerifierBuilder::<F, D, { PI_LEN::<MAX_NUM_RESULTS> }>::new::<C>(
                default_config(),
                QUERY_CIRCUIT_SET_SIZE,
            );
        let circuit_with_agg = builder.build_circuit(());
        let circuit_no_agg = builder.build_circuit(());
        let full_node_two_children = builder.build_circuit(());
        let full_node_one_child = builder.build_circuit(());
        let full_node_leaf = builder.build_circuit(());
        let partial_node = builder.build_circuit(());
        let single_path_proven_child = builder.build_circuit(());
        let single_path_embedded_tree = builder.build_circuit(());
        let non_existence_leaf = builder.build_circuit(());
        let non_existence_intermediate = builder.build_circuit(());

        let circuits = vec![
            prepare_recursive_circuit_for_circuit_set(&circuit_with_agg),
            prepare_recursive_circuit_for_circuit_set(&circuit_no_agg),
            prepare_recursive_circuit_for_circuit_set(&full_node_two_children),
            prepare_recursive_circuit_for_circuit_set(&full_node_one_child),
            prepare_recursive_circuit_for_circuit_set(&full_node_leaf),
            prepare_recursive_circuit_for_circuit_set(&partial_node),
            prepare_recursive_circuit_for_circuit_set(&single_path_proven_child),
            prepare_recursive_circuit_for_circuit_set(&single_path_embedded_tree),
            prepare_recursive_circuit_for_circuit_set(&non_existence_leaf),
            prepare_recursive_circuit_for_circuit_set(&non_existence_intermediate),
        ];

        let circuit_set = RecursiveCircuits::new(circuits);

        Self {
            circuit_with_agg,
            circuit_no_agg,
            circuit_set,
            full_node_two_children,
            full_node_one_child,
            full_node_leaf,
            partial_node,
            single_path_proven_child,
            single_path_embedded_tree,
            non_existence_leaf,
            non_existence_intermediate,
        }
    }

    pub fn generate_proof(
        &self,
        input: CircuitInput<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
        >,
    ) -> Result<Vec<u8>> {
        let proof = ProofWithVK::from(match input {
            CircuitInput::UniversalCircuit(input) => match input {
                UniversalCircuitInput::QueryWithAgg(input) => (
                    self.circuit_set
                        .generate_proof(&self.circuit_with_agg, [], [], input)?,
                    self.circuit_with_agg.circuit_data().verifier_only.clone(),
                ),
                UniversalCircuitInput::QueryNoAgg(input) => (
                    self.circuit_set
                        .generate_proof(&self.circuit_no_agg, [], [], input)?,
                    self.circuit_no_agg.circuit_data().verifier_only.clone(),
                ),
            },
            CircuitInput::TwoProvenChildNode(TwoProvenChildNodeInput {
                left_child_proof,
                right_child_proof,
                embedded_tree_proof,
                common,
            }) => {
                let (left_proof, left_vk) = left_child_proof.into();
                let (right_proof, right_vk) = right_child_proof.into();
                let (embedded_proof, embedded_vk) = embedded_tree_proof.into();
                let input = FullNodeWithTwoChildrenCircuit {
                    is_rows_tree_node: common.is_rows_tree_node,
                    min_query: common.min_query,
                    max_query: common.max_query,
                };
                (
                    self.circuit_set.generate_proof(
                        &self.full_node_two_children,
                        [embedded_proof, left_proof, right_proof],
                        [&embedded_vk, &left_vk, &right_vk],
                        input,
                    )?,
                    self.full_node_two_children
                        .circuit_data()
                        .verifier_only
                        .clone(),
                )
            }
            CircuitInput::OneProvenChildNode(OneProvenChildNodeInput {
                unproven_child,
                proven_child_proof,
                embedded_tree_proof,
                common,
            }) => {
                let ChildProof {
                    proof,
                    child_position,
                } = proven_child_proof;
                let (child_proof, child_vk) = proof.into();
                let (embedded_proof, embedded_vk) = embedded_tree_proof.into();
                match unproven_child {
                    Some(child_node) => {
                        // the node has 2 children, so we use the partial node circuit
                        let input = PartialNodeCircuit {
                            is_rows_tree_node: common.is_rows_tree_node,
                            is_left_child: child_position.to_flag(),
                            sibling_tree_hash: child_node.embedded_tree_hash,
                            sibling_child_hashes: child_node.child_hashes,
                            sibling_value: child_node.value,
                            sibling_min: child_node.min,
                            sibling_max: child_node.max,
                            min_query: common.min_query,
                            max_query: common.max_query,
                        };
                        (
                            self.circuit_set.generate_proof(
                                &self.partial_node,
                                [embedded_proof, child_proof],
                                [&embedded_vk, &child_vk],
                                input,
                            )?,
                            self.partial_node.get_verifier_data().clone(),
                        )
                    }
                    None => {
                        // the node has 1 child, so use the circuit for full node with 1 child
                        let input = FullNodeWithOneChildCircuit {
                            is_rows_tree_node: common.is_rows_tree_node,
                            is_left_child: child_position.to_flag(),
                            min_query: common.min_query,
                            max_query: common.max_query,
                        };
                        (
                            self.circuit_set.generate_proof(
                                &self.full_node_one_child,
                                [embedded_proof, child_proof],
                                [&embedded_vk, &child_vk],
                                input,
                            )?,
                            self.full_node_one_child.get_verifier_data().clone(),
                        )
                    }
                }
            }
            CircuitInput::SinglePath(SinglePathInput {
                left_child,
                right_child,
                node_info,
                subtree_proof,
                common,
            }) => {
                let left_child_exists = left_child.is_some();
                let right_child_exists = right_child.is_some();
                let left_child_data = left_child.unwrap_or_default();
                let right_child_data = right_child.unwrap_or_default();

                match subtree_proof {
                    SubProof::Embedded(input_proof) => {
                        let (proof, vk) = input_proof.into();
                        if !(left_child_exists || right_child_exists) {
                            // leaf node, so call full node circuit for leaf node
                            ensure!(!common.is_rows_tree_node, "providing single-path input for a rows tree node leaf, call universal circuit instead");
                            let input = FullNodeIndexLeafCircuit {
                                min_query: common.min_query,
                                max_query: common.max_query,
                            };
                            (
                                self.circuit_set.generate_proof(
                                    &self.full_node_leaf,
                                    [proof],
                                    [&vk],
                                    input,
                                )?,
                                self.full_node_leaf.get_verifier_data().clone(),
                            )
                        } else {
                            // the input proof refers to the embedded tree stored in the node
                            let input = EmbeddedTreeProvenSinglePathNodeCircuit {
                                left_child_min: left_child_data.min,
                                left_child_max: left_child_data.max,
                                left_child_value: left_child_data.value,
                                left_tree_hash: left_child_data.embedded_tree_hash,
                                left_grand_children: left_child_data.child_hashes,
                                right_child_min: right_child_data.min,
                                right_child_max: right_child_data.max,
                                right_child_value: right_child_data.value,
                                right_tree_hash: right_child_data.embedded_tree_hash,
                                right_grand_children: right_child_data.child_hashes,
                                left_child_exists,
                                right_child_exists,
                                is_rows_tree_node: common.is_rows_tree_node,
                                min_query: common.min_query,
                                max_query: common.max_query,
                            };
                            (
                                self.circuit_set.generate_proof(
                                    &self.single_path_embedded_tree,
                                    [proof],
                                    [&vk],
                                    input,
                                )?,
                                self.single_path_embedded_tree.get_verifier_data().clone(),
                            )
                        }
                    }
                    SubProof::Child(ChildProof {
                        proof,
                        child_position,
                    }) => {
                        // the input proof refers to a child of the node
                        let (proof, vk) = proof.into();
                        let is_left_child = child_position.to_flag();
                        let input = ChildProvenSinglePathNodeCircuit {
                            value: node_info.value,
                            subtree_hash: node_info.embedded_tree_hash,
                            sibling_hash: if is_left_child {
                                node_info.child_hashes[1] // set the hash of the right child, since proven child is left
                            } else {
                                node_info.child_hashes[0] // set the hash of the left child, since proven child is right
                            },
                            is_left_child,
                            unproven_min: node_info.min,
                            unproven_max: node_info.max,
                            is_rows_tree_node: common.is_rows_tree_node,
                        };
                        (
                            self.circuit_set.generate_proof(
                                &self.single_path_proven_child,
                                [proof],
                                [&vk],
                                input,
                            )?,
                            self.single_path_proven_child.get_verifier_data().clone(),
                        )
                    }
                }
            }
            CircuitInput::NonExistence(NonExistenceInput {
                node_info,
                child_info,
                is_child_left,
                primary_index_value,
                index_ids,
                computational_hash,
                placeholder_hash,
                aggregation_ops,
                common,
            }) => {
                match child_info {
                    Some(child_data) => {
                        // intermediate node
                        let input = NonExistenceInterNodeCircuit {
                            is_rows_tree_node: common.is_rows_tree_node,
                            is_left_child: is_child_left.unwrap(),
                            min_query: common.min_query,
                            max_query: common.max_query,
                            value: node_info.value,
                            index_value: primary_index_value,
                            child_value: child_data.value,
                            child_min: child_data.min,
                            child_max: child_data.max,
                            index_ids,
                            ops: aggregation_ops,
                            subtree_hash: node_info.embedded_tree_hash,
                            computational_hash,
                            placeholder_hash,
                            child_subtree_hash: child_data.embedded_tree_hash,
                            grand_child_hashes: child_data.child_hashes,
                        };
                        (
                            self.circuit_set.generate_proof(
                                &self.non_existence_intermediate,
                                [],
                                [],
                                input,
                            )?,
                            self.non_existence_intermediate.get_verifier_data().clone(),
                        )
                    }
                    None => {
                        // leaf node
                        let input = NonExistenceLeafCircuit {
                            is_rows_tree_node: common.is_rows_tree_node,
                            min_query: common.min_query,
                            max_query: common.max_query,
                            value: node_info.value,
                            index_value: primary_index_value,
                            index_ids,
                            ops: aggregation_ops,
                            subtree_hash: node_info.embedded_tree_hash,
                            computational_hash,
                            placeholder_hash,
                        };
                        (
                            self.circuit_set.generate_proof(
                                &self.non_existence_leaf,
                                [],
                                [],
                                input,
                            )?,
                            self.non_existence_leaf.get_verifier_data().clone(),
                        )
                    }
                }
            }
        });

        proof.serialize()
    }

    pub(crate) fn get_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        &self.circuit_set
    }
}

#[cfg(test)]
mod tests {
    use std::{cmp::Ordering, collections::HashMap, iter::once};

    use alloy::{primitives::U256, signers::k256::elliptic_curve::consts::U2};
    use itertools::Itertools;
    use mp2_common::{
        poseidon::empty_poseidon_hash,
        proof::{self, ProofWithVK},
        types::HashOutput,
        utils::{Fieldable, ToFields},
        F,
    };
    use mp2_test::utils::{gen_random_field_hash, gen_random_u256};
    use plonky2::{
        hash::{hash_types::HashOut, hashing::hash_n_to_hash_no_pad},
        plonk::config::GenericHashOut,
    };
    use rand::{thread_rng, Rng};
    use ryhope::tree::scapegoat::Node;

    use crate::query::{
        aggregation::{
            ChildPosition, NodeInfo, QueryBounds, QueryHashNonExistenceCircuits, SubProof,
        },
        api::{CircuitInput, Parameters},
        computational_hash_ids::{AggregationOperation, HashPermutation, Operation},
        public_inputs::PublicInputs,
        universal_circuit::universal_circuit_inputs::{
            BasicOperation, ColumnCell, InputOperand, OutputItem, ResultStructure,
        },
    };

    impl NodeInfo {
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

    #[test]
    fn test_api() {
        // Simple query for testing SELECT SUM(C1 + C3) FROM T WHERE C3 >= 5 AND C1 > 56 AND C1 <= 67 AND C2 > 34 AND C2 <= 78
        let rng = &mut thread_rng();
        const NUM_COLUMNS: usize = 3;
        const MAX_NUM_COLUMNS: usize = 20;
        const MAX_NUM_PREDICATE_OPS: usize = 20;
        const MAX_NUM_RESULT_OPS: usize = 20;
        const MAX_NUM_RESULTS: usize = 10;
        let column_ids = (0..NUM_COLUMNS)
            .map(|_| {
                let id: u32 = rng.gen();
                id as u64
            })
            .collect_vec();

        let primary_index_id: F = column_ids[0].to_field();
        let secondary_index_id: F = column_ids[1].to_field();

        let min_query_primary = 57;
        let max_query_primary = 67;
        let min_query_secondary = 35;
        let max_query_secondary = 78;
        // define Enum to specify whether to generate index values in range or not
        enum IndexValueBounds {
            InRange, // generate index value within query bounds
            Smaller, // generate index value smaller than minimum query bound
            Bigger,  // generate inde value bigger than maximum query bound
        }
        // generate a new row with `NUM_COLUMNS` where value of secondary index is within the query bounds
        let mut gen_row = |primary_index: usize, secondary_index: IndexValueBounds| {
            (0..NUM_COLUMNS)
                .map(|i| match i {
                    0 => U256::from(primary_index),
                    1 => match secondary_index {
                        IndexValueBounds::InRange => {
                            U256::from(rng.gen_range(min_query_secondary..max_query_secondary))
                        }
                        IndexValueBounds::Smaller => {
                            U256::from(rng.gen_range(0..min_query_secondary))
                        }
                        IndexValueBounds::Bigger => {
                            U256::from(rng.gen_range(0..min_query_secondary))
                        }
                    },
                    _ => gen_random_u256(rng),
                })
                .collect_vec()
        };

        let predicate_operations = vec![BasicOperation {
            first_operand: InputOperand::Column(2),
            second_operand: Some(InputOperand::Constant(U256::from(5))),
            op: Operation::GreaterThanOrEqOp,
        }];
        let result_operations = vec![BasicOperation {
            first_operand: InputOperand::Column(0),
            second_operand: Some(InputOperand::Column(2)),
            op: Operation::AddOp,
        }];
        let aggregation_op_ids = vec![AggregationOperation::SumOp.to_id() as u64];
        let output_items = vec![OutputItem::ComputedValue(0)];
        let results = ResultStructure::new_for_query_with_aggregation(
            result_operations,
            output_items,
            aggregation_op_ids.clone(),
        );
        let query_bounds = QueryBounds::new(
            U256::from(min_query_primary),
            U256::from(max_query_primary),
            Some(U256::from(min_query_secondary)),
            Some(U256::from(max_query_secondary)),
        );

        let params = Parameters::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
        >::build();

        type Input = CircuitInput<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
        >;

        // test an index tree with all proven nodes: we assume to have index tree built as follows
        // (node identified according to their sorting order):
        //              4
        //          0
        //              2
        //          1       3

        // build a vector of 5 rows with values of index columns within the query bounds. The entries in the
        // vector are sorted according to primary index value
        let column_values = (min_query_primary..max_query_primary)
            .step_by((max_query_primary - min_query_primary) / 5)
            .take(5)
            .map(|index| gen_row(index, IndexValueBounds::InRange))
            .collect_vec();

        // generate proof with universal for a row with the `values` provided as input.
        // The flag `is_leaf` specifies whether the row is stored in a leaf node of a rows tree
        // or not
        let gen_universal_circuit_proofs = |values: &[U256], is_leaf: bool| {
            let column_cells = values
                .iter()
                .zip(column_ids.iter())
                .map(|(&value, &id)| ColumnCell::new(id, value))
                .collect_vec();
            let input = Input::new_universal_circuit(
                &column_cells,
                &predicate_operations,
                &results,
                &HashMap::new(),
                is_leaf,
                &query_bounds,
            )
            .unwrap();
            params.generate_proof(input).unwrap()
        };

        // generate base proofs with universal circuits for each node
        let base_proofs = column_values
            .iter()
            .map(|values| gen_universal_circuit_proofs(values, true))
            .collect_vec();

        // closure to extract the tree hash from a proof
        let get_tree_hash_from_proof = |proof: &[u8]| {
            let (proof, _) = ProofWithVK::deserialize(proof).unwrap().into();
            let pis = PublicInputs::<F, MAX_NUM_RESULTS>::from_slice(&proof.public_inputs);
            pis.tree_hash()
        };

        // closure to generate the proof for a leaf node of the index tree, corresponding to the node_index-th row
        let gen_leaf_proof_for_node = |node_index: usize| {
            let embedded_tree_hash = get_tree_hash_from_proof(&base_proofs[node_index]);
            let node_info = NodeInfo::new(
                &HashOutput::try_from(embedded_tree_hash.to_bytes()).unwrap(),
                None,
                None,
                column_values[node_index][0], // primary index value for this row
                column_values[node_index][0],
                column_values[node_index][0],
            );
            let tree_hash = node_info.compute_node_hash(primary_index_id);
            let subtree_proof =
                SubProof::new_embedded_tree_proof(base_proofs[node_index].clone()).unwrap();
            let input = Input::new_single_path(
                subtree_proof,
                None,
                None,
                node_info,
                false, // index tree node
                &query_bounds,
            )
            .unwrap();
            let proof = params.generate_proof(input).unwrap();
            // check tree hash is correct
            assert_eq!(tree_hash, get_tree_hash_from_proof(&proof));
            proof
        };

        // generate proof for node 1 of index tree above
        let leaf_proof_left = gen_leaf_proof_for_node(1);

        // generate proof for node 3 of index tree above
        let leaf_proof_right = gen_leaf_proof_for_node(3);

        // generate proof for node 2 of index tree above
        let left_child_hash = get_tree_hash_from_proof(&leaf_proof_left);
        let right_child_hash = get_tree_hash_from_proof(&leaf_proof_right);
        let input = Input::new_full_node(
            leaf_proof_left,
            leaf_proof_right,
            base_proofs[2].clone(),
            false,
            &query_bounds,
        )
        .unwrap();
        let full_node_proof = params.generate_proof(input).unwrap();

        // verify hash is correct
        let full_node_info = NodeInfo::new(
            &HashOutput::try_from(get_tree_hash_from_proof(&base_proofs[2]).to_bytes()).unwrap(),
            Some(&HashOutput::try_from(left_child_hash.to_bytes()).unwrap()),
            Some(&HashOutput::try_from(right_child_hash.to_bytes()).unwrap()),
            column_values[2][0], // primary index value for that row
            column_values[1][0], // primary index value for the min node in the left subtree
            column_values[3][0], // primary index value for the max node in the right subtree
        );
        let full_node_hash = get_tree_hash_from_proof(&full_node_proof);
        assert_eq!(
            full_node_hash,
            full_node_info.compute_node_hash(primary_index_id),
        );

        // generate proof for node 0 of the index tree above
        let input = Input::new_partial_node(
            full_node_proof,
            base_proofs[0].clone(),
            None,                 // there is no left child
            ChildPosition::Right, // proven child is the right child of node 0
            false,
            &query_bounds,
        )
        .unwrap();
        let one_child_node_proof = params.generate_proof(input).unwrap();
        // verify hash is correct
        let one_child_node_info = NodeInfo::new(
            &HashOutput::try_from(get_tree_hash_from_proof(&base_proofs[0]).to_bytes()).unwrap(),
            None,
            Some(&HashOutput::try_from(full_node_hash.to_bytes()).unwrap()),
            column_values[0][0],
            column_values[0][0],
            column_values[3][0],
        );
        let one_child_node_hash = get_tree_hash_from_proof(&one_child_node_proof);
        assert_eq!(
            one_child_node_hash,
            one_child_node_info.compute_node_hash(primary_index_id)
        );

        // generate proof for root node
        let input = Input::new_partial_node(
            one_child_node_proof,
            base_proofs[4].clone(),
            None,                // there is no right child
            ChildPosition::Left, // proven child is the left child of root node
            false,
            &query_bounds,
        )
        .unwrap();
        let (root_proof, _) = ProofWithVK::deserialize(&params.generate_proof(input).unwrap())
            .unwrap()
            .into();
        // check some public inputs for root proof
        let check_pis = |root_proof_pis: &[F], node_info: NodeInfo, column_values: &[Vec<U256>]| {
            let pis = PublicInputs::<F, MAX_NUM_RESULTS>::from_slice(&root_proof_pis);
            assert_eq!(
                pis.tree_hash(),
                node_info.compute_node_hash(primary_index_id),
            );
            assert_eq!(pis.min_value(), node_info.min,);
            assert_eq!(pis.max_value(), node_info.max,);
            assert_eq!(pis.min_query_value(), query_bounds.min_query_primary,);
            assert_eq!(pis.max_query_value(), query_bounds.max_query_primary,);
            assert_eq!(
                pis.index_ids().to_vec(),
                column_ids
                    .iter()
                    .take(2)
                    .map(|id| id.to_field())
                    .collect_vec(),
            );
            // compute output value: SUM(C1 + C3) for all the rows where C3 >= 5
            let (output, overflow, count) =
                column_values
                    .iter()
                    .fold((U256::ZERO, false, 0u64), |acc, value| {
                        if value[2] >= U256::from(5)
                            && value[0] >= query_bounds.min_query_primary
                            && value[0] <= query_bounds.max_query_primary
                            && value[1] >= query_bounds.min_query_secondary
                            && value[1] <= query_bounds.max_query_secondary
                        {
                            let (sum, overflow) = value[0].overflowing_add(value[2]);
                            let new_overflow = acc.1 || overflow;
                            let (new_sum, overflow) = sum.overflowing_add(acc.0);
                            (new_sum, new_overflow || overflow, acc.2 + 1)
                        } else {
                            acc
                        }
                    });
            assert_eq!(pis.first_value_as_u256(), output,);
            assert_eq!(pis.overflow_flag(), overflow,);
            assert_eq!(pis.num_matching_rows(), count.to_field(),);
        };

        let root_node_info = NodeInfo::new(
            &HashOutput::try_from(get_tree_hash_from_proof(&base_proofs[4]).to_bytes()).unwrap(),
            Some(&HashOutput::try_from(one_child_node_hash.to_bytes()).unwrap()),
            None,
            column_values[4][0],
            column_values[0][0],
            column_values[4][0],
        );

        check_pis(&root_proof.public_inputs, root_node_info, &column_values);

        // build an index tree with a mix of proven and unproven nodes. The tree is built as follows:
        //          0
        //              8
        //          3       9
        //      2       5
        //   1        4   6
        //                   7
        // nodes 3,4,5,6 are in the range specified by the query for the primary index, while the other nodes
        // are not
        let column_values = [0, min_query_primary / 3, min_query_primary * 2 / 3]
            .into_iter() // primary index values for nodes 0,1,2
            .chain(
                (min_query_primary..max_query_primary)
                    .step_by((max_query_primary - min_query_primary) / 4)
                    .take(4),
            ) // primary index values for nodes in the range
            .chain([
                max_query_primary * 2,
                max_query_primary * 3,
                max_query_primary * 4,
            ]) // primary index values for nodes 7,8, 9
            .map(|index| gen_row(index, IndexValueBounds::InRange))
            .collect_vec();

        // generate base proofs with universal circuits for each node in the range
        const START_NODE_IN_RANGE: usize = 3;
        const LAST_NODE_IN_RANGE: usize = 6;
        let base_proofs = column_values[START_NODE_IN_RANGE..=LAST_NODE_IN_RANGE]
            .iter()
            .map(|values| gen_universal_circuit_proofs(values, true))
            .collect_vec();

        // generate proof for node 4
        let embedded_tree_hash = get_tree_hash_from_proof(&base_proofs[4 - START_NODE_IN_RANGE]);
        let node_info = NodeInfo::new(
            &HashOutput::try_from(embedded_tree_hash.to_bytes()).unwrap(),
            None,
            None,
            column_values[4][0],
            column_values[4][0],
            column_values[4][0],
        );
        let subtree_proof =
            SubProof::new_embedded_tree_proof(base_proofs[4 - START_NODE_IN_RANGE].clone())
                .unwrap();
        let hash_4 = node_info.compute_node_hash(primary_index_id);
        let input =
            Input::new_single_path(subtree_proof, None, None, node_info, false, &query_bounds)
                .unwrap();
        let proof_4 = params.generate_proof(input).unwrap();
        // check hash
        assert_eq!(hash_4, get_tree_hash_from_proof(&proof_4),);

        // generate proof for node 6
        // compute node data for node 7, which is needed as input to generate the proof
        let node_info_7 = NodeInfo::new(
            // for the sake of this test, we can use random hash for the embedded tree stored in node 7, since it's not proven;
            // in a non-test scenario, we would need to get the actual embedded hash of the node, otherwise the root hash of the
            // tree computed in the proofs will be incorrect
            &HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap(),
            None,
            None,
            column_values[7][0],
            column_values[7][0],
            column_values[7][0],
        );
        let hash_7 = node_info_7.compute_node_hash(primary_index_id);
        let embedded_tree_hash = get_tree_hash_from_proof(&base_proofs[6 - START_NODE_IN_RANGE]);
        let node_info_6 = NodeInfo::new(
            &HashOutput::try_from(embedded_tree_hash.to_bytes()).unwrap(),
            None,
            Some(&HashOutput::try_from(hash_7.to_bytes()).unwrap()),
            column_values[6][0],
            column_values[6][0],
            column_values[7][0],
        );
        let subtree_proof =
            SubProof::new_embedded_tree_proof(base_proofs[6 - START_NODE_IN_RANGE].clone())
                .unwrap();
        let hash_6 = node_info_6.compute_node_hash(primary_index_id);
        let input = Input::new_single_path(
            subtree_proof,
            None,
            Some(node_info_7),
            node_info_6,
            false,
            &query_bounds,
        )
        .unwrap();
        let proof_6 = params.generate_proof(input).unwrap();
        // check hash
        assert_eq!(hash_6, get_tree_hash_from_proof(&proof_6));

        // generate proof for node 5
        let input = Input::new_full_node(
            proof_4,
            proof_6,
            base_proofs[5 - START_NODE_IN_RANGE].clone(),
            false,
            &query_bounds,
        )
        .unwrap();
        let proof_5 = params.generate_proof(input).unwrap();
        // check hash
        let embedded_tree_hash = get_tree_hash_from_proof(&base_proofs[5 - START_NODE_IN_RANGE]);
        let node_info_5 = NodeInfo::new(
            &HashOutput::try_from(embedded_tree_hash.to_bytes()).unwrap(),
            Some(&HashOutput::try_from(hash_4.to_bytes()).unwrap()),
            Some(&HashOutput::try_from(hash_6.to_bytes()).unwrap()),
            column_values[5][0],
            column_values[4][0],
            column_values[7][0],
        );
        let hash_5 = node_info_5.compute_node_hash(primary_index_id);
        assert_eq!(hash_5, get_tree_hash_from_proof(&proof_5),);

        // generate proof for node 3
        // compute node data for node 2, which is needed as input to generate the proof
        let node_info_2 = NodeInfo::new(
            // same as for node_info_7, we can use random hashes for the sake of this test
            &HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap(),
            Some(&HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap()),
            None,
            column_values[2][0],
            column_values[1][0],
            column_values[2][0],
        );
        let hash_2 = node_info_2.compute_node_hash(primary_index_id);
        let input = Input::new_partial_node(
            proof_5,
            base_proofs[3 - START_NODE_IN_RANGE].clone(),
            Some(node_info_2),
            ChildPosition::Right, // proven child is right child
            false,
            &query_bounds,
        )
        .unwrap();
        let proof_3 = params.generate_proof(input).unwrap();
        // check hash
        let embedded_tree_hash = get_tree_hash_from_proof(&base_proofs[3 - START_NODE_IN_RANGE]);
        let node_info_3 = NodeInfo::new(
            &HashOutput::try_from(embedded_tree_hash.to_bytes()).unwrap(),
            Some(&HashOutput::try_from(hash_2.to_bytes()).unwrap()),
            Some(&HashOutput::try_from(hash_5.to_bytes()).unwrap()),
            column_values[3][0],
            column_values[1][0],
            column_values[7][0],
        );
        let hash_3 = node_info_3.compute_node_hash(primary_index_id);
        assert_eq!(hash_3, get_tree_hash_from_proof(&proof_3),);

        // generate proof for node 8
        // compute node_info_9, which is needed as input for the proof
        let node_info_9 = NodeInfo::new(
            // same as for node_info_2, we can use random hashes for the sake of this test
            &HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap(),
            None,
            None,
            column_values[9][0],
            column_values[9][0],
            column_values[9][0],
        );
        let hash_9 = node_info_9.compute_node_hash(primary_index_id);
        let node_info_8 = NodeInfo::new(
            // same as for node_info_2, we can use random hashes for the sake of this test
            &HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap(),
            Some(&HashOutput::try_from(hash_3.to_bytes()).unwrap()),
            Some(&HashOutput::try_from(hash_9.to_bytes()).unwrap()),
            column_values[8][0],
            column_values[1][0],
            column_values[9][0],
        );
        let hash_8 = node_info_8.compute_node_hash(primary_index_id);
        let subtree_proof = SubProof::new_child_proof(
            proof_3,
            ChildPosition::Left, // subtree proof refers to the left child of the node
        )
        .unwrap();
        let input = Input::new_single_path(
            subtree_proof,
            Some(node_info_3),
            Some(node_info_9),
            node_info_8.clone(),
            false,
            &query_bounds,
        )
        .unwrap();
        let proof_8 = params.generate_proof(input).unwrap();
        // check hash
        assert_eq!(get_tree_hash_from_proof(&proof_8), hash_8);
        println!("generate proof for node 0");

        // generate proof for node 0 (root)
        let node_info_0 = NodeInfo::new(
            // same as for node_info_1, we can use random hashes for the sake of this test
            &HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap(),
            None,
            Some(&HashOutput::try_from(hash_8.to_bytes()).unwrap()),
            column_values[0][0],
            column_values[0][0],
            column_values[9][0],
        );
        let subtree_proof = SubProof::new_child_proof(
            proof_8,
            ChildPosition::Right, // subtree proof refers to the right child of the node
        )
        .unwrap();
        let input = Input::new_single_path(
            subtree_proof,
            None,
            Some(node_info_8),
            node_info_0.clone(),
            false,
            &query_bounds,
        )
        .unwrap();
        let (root_proof, _) = ProofWithVK::deserialize(&params.generate_proof(input).unwrap())
            .unwrap()
            .into();

        // check some public inputs
        check_pis(&root_proof.public_inputs, node_info_0, &column_values);

        // build an index tree with all nodes outside of the primary index range. The tree is built as follows:
        //          2
        //      1       3
        //  0
        // where nodes 0 stores an index value smaller than `min_query_primary`, while nodes 1, 2, 3 store index values
        // bigger than `max_query_primary`
        let column_values = [min_query_primary / 2]
            .into_iter()
            .chain(
                [
                    max_query_primary * 2,
                    max_query_primary * 3,
                    max_query_primary * 4,
                ]
                .into_iter(),
            )
            .map(|index| gen_row(index, IndexValueBounds::InRange))
            .collect_vec();

        // generate proof for node 0 with non-existence circuit, since it is outside of the query bounds
        let node_info_0 = NodeInfo::new(
            // we can use a randomly generated hash for the subtree, for the sake of the test
            &HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap(),
            None,
            None,
            column_values[0][0],
            column_values[0][0],
            column_values[0][0],
        );
        let hash_0 = node_info_0.compute_node_hash(primary_index_id);
        let column_cells = column_values[0]
            .iter()
            .zip(column_ids.iter())
            .map(|(&value, &id)| ColumnCell::new(id, value))
            .collect_vec();
        // compute hashes associated to query, which are needed as inputs
        let query_hashes = QueryHashNonExistenceCircuits::new::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
        >(
            &column_cells,
            &predicate_operations,
            &results,
            &HashMap::new(),
            &query_bounds,
            false,
        )
        .unwrap();
        let input = Input::new_non_existence_input(
            node_info_0.clone(),
            None,
            node_info_0.value,
            &column_ids[..2].try_into().unwrap(),
            &[AggregationOperation::SumOp],
            query_hashes,
            false,
            &query_bounds,
        )
        .unwrap();
        let proof_0 = params.generate_proof(input).unwrap();
        // check hash
        assert_eq!(hash_0, get_tree_hash_from_proof(&proof_0),);

        // get up to the root of the tree with proofs
        // generate proof for node 1
        let node_info_1 = NodeInfo::new(
            // we can use a random hash for the embedded tree
            &HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap(),
            Some(&HashOutput::try_from(hash_0.to_bytes()).unwrap()),
            None,
            column_values[1][0],
            column_values[0][0],
            column_values[1][0],
        );
        let hash_1 = node_info_1.compute_node_hash(primary_index_id);
        let subtree_proof = SubProof::new_child_proof(proof_0, ChildPosition::Left).unwrap();
        let input = Input::new_single_path(
            subtree_proof,
            Some(node_info_0.clone()),
            None,
            node_info_1.clone(),
            false,
            &query_bounds,
        )
        .unwrap();
        let proof_1 = params.generate_proof(input).unwrap();
        // check hash
        assert_eq!(hash_1, get_tree_hash_from_proof(&proof_1),);

        // generate proof for root node
        let node_info_2 = NodeInfo::new(
            // we can use a random hash for the embedded tree
            &HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap(),
            Some(&HashOutput::try_from(hash_1.to_bytes()).unwrap()),
            None,
            column_values[2][0],
            column_values[0][0],
            column_values[2][0],
        );
        let node_info_3 = NodeInfo::new(
            // we can use a random hash for the embedded tree
            &HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap(),
            None,
            None,
            column_values[3][0],
            column_values[3][0],
            column_values[3][0],
        );
        let subtree_proof = SubProof::new_child_proof(proof_1, ChildPosition::Left).unwrap();
        let input = Input::new_single_path(
            subtree_proof,
            Some(node_info_1.clone()),
            Some(node_info_3.clone()),
            node_info_2.clone(),
            false,
            &query_bounds,
        )
        .unwrap();
        let (root_proof, _) = ProofWithVK::deserialize(&params.generate_proof(input).unwrap())
            .unwrap()
            .into();

        check_pis(
            &root_proof.public_inputs,
            node_info_2.clone(),
            &column_values,
        );

        // generate non-existence proof starting from intermediate node (i.e., node 1) rather than a leaf node
        // generate proof with non-existence circuit for node 1
        let column_cells = column_values[1]
            .iter()
            .zip(column_ids.iter())
            .map(|(&value, &id)| ColumnCell::new(id, value))
            .collect_vec();
        // compute hashes associated to query, which are needed as inputs
        let query_hashes = QueryHashNonExistenceCircuits::new::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
        >(
            &column_cells,
            &predicate_operations,
            &results,
            &HashMap::new(),
            &query_bounds,
            false,
        )
        .unwrap();
        let input = Input::new_non_existence_input(
            node_info_1.clone(),
            Some((node_info_0, ChildPosition::Left)), // node 0 is the left child
            node_info_1.value,
            &column_ids[..2].try_into().unwrap(),
            &[AggregationOperation::SumOp],
            query_hashes,
            false,
            &query_bounds,
        )
        .unwrap();
        let proof_1 = params.generate_proof(input).unwrap();
        // check hash
        assert_eq!(hash_1, get_tree_hash_from_proof(&proof_1),);

        // generate proof for root node
        let subtree_proof = SubProof::new_child_proof(proof_1, ChildPosition::Left).unwrap();
        let input = Input::new_single_path(
            subtree_proof,
            Some(node_info_1.clone()),
            Some(node_info_3.clone()),
            node_info_2.clone(),
            false,
            &query_bounds,
        )
        .unwrap();
        let (root_proof, _) = ProofWithVK::deserialize(&params.generate_proof(input).unwrap())
            .unwrap()
            .into();

        check_pis(&root_proof.public_inputs, node_info_2, &column_values);

        // generate a tree with rows tree with more than one node. We generate an index tree with 2 nodes A and B,
        // both storing a primary index value within the query bounds.
        // Node A stores a rows tree with all entries outside of query bounds for secondary index, while
        // node B stores a rows tree with all entries within query bounds for secondary index.
        // The tree is structured as follows:
        //                      B
        //                      4
        //                  3       5
        //          A
        //          1
        //      0       2
        let mut column_values = vec![
            gen_row(min_query_primary, IndexValueBounds::Smaller),
            gen_row(min_query_primary, IndexValueBounds::Smaller),
            gen_row(min_query_primary, IndexValueBounds::Bigger),
            gen_row(max_query_primary, IndexValueBounds::InRange),
            gen_row(max_query_primary, IndexValueBounds::InRange),
            gen_row(max_query_primary, IndexValueBounds::InRange),
        ];
        // sort column values according to primary/secondary index values
        column_values.sort_by(|a, b| {
            if a[0] < b[0] {
                Ordering::Less
            } else if a[0] > b[0] {
                Ordering::Greater
            } else {
                a[1].cmp(&b[1])
            }
        });

        // generate proof for node A rows tree
        // generate non-existence proof for node 2, which is the smallest node higher than the maximum query bound, since
        // node 1, which is the highest node smaller than the minimum query bound, has 2 children
        // (see non-existence circuit docs to see why we don't generate non-existence proofs for nodes with 2 children)
        let node_info_2 = NodeInfo::new(
            // we can use a random hash for the embedded tree
            &HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap(),
            None,
            None,
            column_values[2][1],
            column_values[2][1],
            column_values[2][1],
        );
        let hash_2 = node_info_2.compute_node_hash(secondary_index_id);
        let column_cells = column_values[2]
            .iter()
            .zip(column_ids.iter())
            .map(|(&value, &id)| ColumnCell::new(id, value))
            .collect_vec();
        // compute hashes associated to query, which are needed as inputs
        let query_hashes = QueryHashNonExistenceCircuits::new::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
        >(
            &column_cells,
            &predicate_operations,
            &results,
            &HashMap::new(),
            &query_bounds,
            true,
        )
        .unwrap();
        let input = Input::new_non_existence_input(
            node_info_2.clone(),
            None,
            column_values[2][0], // we need to place the primary index value associated to this row
            &column_ids[..2].try_into().unwrap(),
            &[AggregationOperation::SumOp],
            query_hashes,
            true,
            &query_bounds,
        )
        .unwrap();
        let proof_2 = params.generate_proof(input).unwrap();
        // check hash
        assert_eq!(hash_2, get_tree_hash_from_proof(&proof_2),);

        // generate proof for node 1 (root of rows tree for node A)
        let node_info_1 = NodeInfo::new(
            &HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap(),
            None,
            Some(&HashOutput::try_from(hash_2.to_bytes()).unwrap()),
            column_values[1][1],
            column_values[0][1],
            column_values[2][1],
        );
        let node_info_0 = NodeInfo::new(
            &HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap(),
            None,
            None,
            column_values[0][1],
            column_values[0][1],
            column_values[0][1],
        );
        let hash_1 = node_info_1.compute_node_hash(secondary_index_id);
        let subtree_proof = SubProof::new_child_proof(proof_2, ChildPosition::Right).unwrap();
        let input = Input::new_single_path(
            subtree_proof,
            Some(node_info_0),
            Some(node_info_2),
            node_info_1,
            true,
            &query_bounds,
        )
        .unwrap();
        let proof_1 = params.generate_proof(input).unwrap();
        // check hash
        assert_eq!(hash_1, get_tree_hash_from_proof(&proof_1),);

        // generate proof for node A (leaf of index tree)
        let node_info_A = NodeInfo::new(
            &HashOutput::try_from(hash_1.to_bytes()).unwrap(),
            None,
            None,
            column_values[0][0],
            column_values[0][0],
            column_values[0][0],
        );
        let hash_A = node_info_A.compute_node_hash(primary_index_id);
        let subtree_proof = SubProof::new_embedded_tree_proof(proof_1).unwrap();
        let input = Input::new_single_path(
            subtree_proof,
            None,
            None,
            node_info_A.clone(),
            false,
            &query_bounds,
        )
        .unwrap();
        let proof_A = params.generate_proof(input).unwrap();
        // check hash
        assert_eq!(hash_A, get_tree_hash_from_proof(&proof_A),);

        // generate proof for node B rows tree
        // all the nodes are in the range, so we generate proofs for each of the nodes
        // generate proof for nodes 3 and 5: they are leaf nodes in the rows tree, so we directly use the universal circuit
        let [proof_3, proof_5] = [&column_values[3], &column_values[5]]
            .map(|values| gen_universal_circuit_proofs(values, true));
        // node 4 is not a leaf in the rows tree, so instead we need to first generate a proof for the row results using
        // the universal circuit, and then we generate the proof for the rows tree node
        let row_proof = gen_universal_circuit_proofs(&column_values[4], false);
        let hash_3 = get_tree_hash_from_proof(&proof_3);
        let hash_5 = get_tree_hash_from_proof(&proof_5);
        let embedded_tree_hash = get_tree_hash_from_proof(&row_proof);
        let input = Input::new_full_node(proof_3, proof_5, row_proof, true, &query_bounds).unwrap();
        let proof_4 = params.generate_proof(input).unwrap();
        // check hash
        let node_info_4 = NodeInfo::new(
            &HashOutput::try_from(embedded_tree_hash.to_bytes()).unwrap(),
            Some(&HashOutput::try_from(hash_3.to_bytes()).unwrap()),
            Some(&HashOutput::try_from(hash_5.to_bytes()).unwrap()),
            column_values[4][1],
            column_values[3][1],
            column_values[5][1],
        );
        let hash_4 = node_info_4.compute_node_hash(secondary_index_id);
        assert_eq!(hash_4, get_tree_hash_from_proof(&proof_4),);

        // generate proof for node B of the index tree (root node)
        let node_info_root = NodeInfo::new(
            &HashOutput::try_from(hash_4.to_bytes()).unwrap(),
            Some(&HashOutput::try_from(hash_A.to_bytes()).unwrap()),
            None,
            column_values[4][0],
            column_values[0][0],
            column_values[5][0],
        );
        let input = Input::new_partial_node(
            proof_A,
            proof_4,
            None,
            ChildPosition::Left,
            false,
            &query_bounds,
        )
        .unwrap();
        let (root_proof, _) = ProofWithVK::deserialize(&params.generate_proof(input).unwrap())
            .unwrap()
            .into();

        check_pis(&root_proof.public_inputs, node_info_root, &column_values);
    }
}
