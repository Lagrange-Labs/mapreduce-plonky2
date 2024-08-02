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
        ChildProof, CommonInputs, NodeInfo, NonExistenceInput, OneProvenChildNodeInput,
        QueryBounds, QueryHashNonExistenceCircuits, SinglePathInput, SubProof,
        TwoProvenChildNodeInput,
    },
    computational_hash_ids::{AggregationOperation, HashPermutation, Output},
    universal_circuit::{
        output_no_aggregation::Circuit as NoAggOutputCircuit,
        output_with_aggregation::Circuit as AggOutputCircuit,
        universal_circuit_inputs::{BasicOperation, ColumnCell, PlaceholderId, ResultStructure},
        universal_query_circuit::{
            UniversalCircuitInput, UniversalQueryCircuitInputs, UniversalQueryCircuitWires,
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
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULTS]:,
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
    /// Note that the following assumptions are expected on the structure of the inputs:
    /// - The output of the last operation in `predicate_operations` will be taken as the filtering predicate evaluation;
    ///   this is an assumption exploited in the circuit for efficiency, and it is a simple assumption to be required for
    ///   the caller of this method
    /// - The operations in `results.result_operations` that compute output values must be placed in the last `MAX_NUM_RESULTS`
    ///   entries of the `result_operations` found in `results` structure. This is again an assumption we require to
    ///   properly place the output values in the circuit. Note that this method returns an error if this assumption
    ///   is not met in the `results` structure provided as input
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
                    query_bounds.min_query_secondary,
                    query_bounds.max_query_secondary,
                    results,
                )?,
                Output::NoAggregation => UniversalCircuitInput::new_query_no_agg(
                    column_cells,
                    predicate_operations,
                    placeholder_values,
                    is_leaf,
                    query_bounds.min_query_secondary,
                    query_bounds.max_query_secondary,
                    results,
                )?,
            },
        ))
    }

    /// Initialize input to prove a full node from the following inputs:
    /// - `left_child_proof`: proof for the left child of the full node
    /// - `right_child_proof`: proof for the right child of the full node
    /// - `embedded_tree_proof`: proof for the embedded tree stored in the full node
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
    /// - `embedded_tree_proof`: Proof for the embedded tree stored in the partial node
    /// - `unproven_child`: Data about the child not being a proven node; if the node has only one child,
    ///     then, this parameter must be `None`
    /// - `is_proven_child_left`: Flag specifying whether the proven child is the left or right child
    ///     of the partial node being proven
    /// - `is_rows_tree_node`: flag specifying whether the full node belongs to the rows tree or to the index tree
    /// - `query_bounds`: bounds on primary and secondary indexes specified in the query
    pub fn new_partial_node(
        proven_child_proof: Vec<u8>,
        embedded_tree_proof: Vec<u8>,
        unproven_child: Option<NodeInfo>,
        proven_child_left: bool,
        is_rows_tree_node: bool,
        query_bounds: &QueryBounds,
    ) -> Result<Self> {
        Ok(CircuitInput::OneProvenChildNode(OneProvenChildNodeInput {
            unproven_child,
            proven_child_proof: ChildProof {
                proof: ProofWithVK::deserialize(&proven_child_proof)?,
                is_left_child: proven_child_left,
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
    /// - `child_info`: Data aboout the child of the node being proven, altogether with a flag specifying
    ///     whether this child is the left or right one; must be `None` if the node being proven has no children
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
        child_info: Option<(NodeInfo, bool)>,
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
            is_child_left: child_info.map(|info| info.1),
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

    /// Compute the `placeholder_hash` associated to a query
    pub fn placeholder_hash(
        column_cells: &[ColumnCell],
        predicate_operations: &[BasicOperation],
        results: &ResultStructure,
        placeholder_values: &HashMap<PlaceholderId, U256>,
        query_bounds: &QueryBounds,
    ) -> Result<HashOutput> {
        let hash = match results.output_variant {
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
                    query_bounds.min_query_secondary,
                    query_bounds.max_query_secondary,
                    results,
                )?;
                circuit.placeholder_hash()
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
                    query_bounds.min_query_secondary,
                    query_bounds.max_query_secondary,
                    results,
                )?;
                circuit.placeholder_hash()
            }
        };
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

pub struct Parameters<
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
> where
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULTS]:,
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
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULTS]:,
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
                    is_left_child,
                } = proven_child_proof;
                let (child_proof, child_vk) = proof.into();
                let (embedded_proof, embedded_vk) = embedded_tree_proof.into();
                match unproven_child {
                    Some(child_node) => {
                        // the node has 2 children, so we use the partial node circuit
                        let input = PartialNodeCircuit {
                            is_rows_tree_node: common.is_rows_tree_node,
                            is_left_child,
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
                            is_left_child,
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
                        is_left_child,
                    }) => {
                        // the input proof refers to a child of the node
                        let (proof, vk) = proof.into();
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
}
