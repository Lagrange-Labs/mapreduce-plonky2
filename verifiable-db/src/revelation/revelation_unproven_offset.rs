//! This module contains the final revelation circuit for SELECT queries without
//! aggregate function, where we just return at most `LIMIT` results, without
//! proving the `OFFSET` in the set of results. Note that this means that the
//! prover could censor some actual results of the query, but they cannot be
//! faked

use anyhow::{ensure, Result};
use std::{
    array,
    iter::{once, repeat},
};

use crate::{CBuilder, C, D, F, H};
use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{
    default_config,
    group_hashing::CircuitBuilderGroupHashing,
    poseidon::flatten_poseidon_hash_target,
    proof::verify_proof_fixed_circuit,
    public_inputs::PublicInputCommon,
    serialization::{
        deserialize, deserialize_array, deserialize_long_array, serialize, serialize_array,
        serialize_long_array,
    },
    types::HashOutput,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{Fieldable, HashBuilder, ToTargets},
};
use plonky2::{
    hash::hash_types::HashOutTarget,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_data::{VerifierCircuitData, VerifierOnlyCircuitData},
        config::Hasher,
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    framework::{RecursiveCircuits, RecursiveCircuitsVerifierGagdet},
};
use serde::{Deserialize, Serialize};

use crate::{
    ivc::PublicInputs as OriginalTreePublicInputs,
    query::{
        computational_hash_ids::{ColumnIDs, ResultIdentifier},
        merkle_path::{MerklePathGadget, MerklePathTargetInputs},
        public_inputs::PublicInputsUniversalCircuit as QueryProofPublicInputs,
        universal_circuit::{
            build_cells_tree,
            universal_circuit_inputs::{
                BasicOperation, ColumnCell, Placeholders, ResultStructure, RowCells,
            },
            universal_query_circuit::{UniversalCircuitInput, UniversalQueryCircuitInputs},
        },
        utils::{ChildPosition, NodeInfo, QueryBounds},
    },
};

use super::{
    pi_len as revelation_pi_len,
    placeholders_check::{CheckPlaceholderGadget, CheckPlaceholderInputWires},
    PublicInputs, NUM_PREPROCESSING_IO,
};

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
/// Data structure containing all the information needed to verify the membership of
/// a row in a tree representing a table
pub struct RowPath {
    /// Info about the node of the row tree storing the row
    pub(crate) row_node_info: NodeInfo,
    /// Info about the nodes in the path of the rows tree for the node storing the row; The `ChildPosition` refers to
    /// the position of the previous node in the path as a child of the current node
    pub(crate) row_tree_path: Vec<(NodeInfo, ChildPosition)>,
    /// Hash of the siblings of the node in the rows tree path (except for the root)
    pub(crate) row_path_siblings: Vec<Option<HashOutput>>,
    /// Info about the node of the index tree storing the rows tree containing the row
    pub(crate) index_node_info: NodeInfo,
    /// Info about the nodes in the path of the index tree for the index_node; The `ChildPosition` refers to
    /// the position of the previous node in the path as a child of the current node
    pub(crate) index_tree_path: Vec<(NodeInfo, ChildPosition)>,
    /// Hash of the siblings of the nodes in the index tree path (except for the root)
    pub(crate) index_path_siblings: Vec<Option<HashOutput>>,
}

impl RowPath {
    /// Instantiate a new instance of `RowPath` for a given proven row from the following input data:
    /// - `row_node_info`: data about the node of the row tree storing the row
    /// - `row_tree_path`: data about the nodes in the path of the rows tree for the node storing the row;
    ///   The `ChildPosition` refers to the position of the previous node in the path as a child of the current node
    /// - `row_path_siblings`: hash of the siblings of the node in the rows tree path (except for the root)
    /// - `index_node_info`: data about the node of the index tree storing the rows tree containing the row
    /// - `index_tree_path`: data about the nodes in the path of the index tree for the index_node;
    ///   The `ChildPosition` refers to the position of the previous node in the path as a child of the current node
    /// - `index_path_siblings`: hash of the siblings of the nodes in the index tree path (except for the root)
    pub fn new(
        row_node_info: NodeInfo,
        row_tree_path: Vec<(NodeInfo, ChildPosition)>,
        row_path_siblings: Vec<Option<HashOutput>>,
        index_node_info: NodeInfo,
        index_tree_path: Vec<(NodeInfo, ChildPosition)>,
        index_path_siblings: Vec<Option<HashOutput>>,
    ) -> Self {
        Self {
            row_node_info,
            row_tree_path,
            row_path_siblings,
            index_node_info,
            index_tree_path,
            index_path_siblings,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Target for all the information about nodes in the path needed by this revelation circuit
struct NodeInfoTarget {
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    child_hashes: [HashOutTarget; 2],
    node_min: UInt256Target,
    node_max: UInt256Target,
}

impl NodeInfoTarget {
    fn build(b: &mut CBuilder) -> Self {
        let child_hashes = b.add_virtual_hashes(2);
        let [node_min, node_max] = b.add_virtual_u256_arr_unsafe();

        Self {
            child_hashes: child_hashes.try_into().unwrap(),
            node_min,
            node_max,
        }
    }

    fn set_target(&self, pw: &mut PartialWitness<F>, inputs: &NodeInfo) {
        self.child_hashes
            .iter()
            .zip(inputs.child_hashes)
            .for_each(|(&target, value)| pw.set_hash_target(target, value));
        pw.set_u256_target(&self.node_min, inputs.min);
        pw.set_u256_target(&self.node_max, inputs.max);
    }
}

/// Data structure containing the parameters found in tabular
/// queries that specify which outputs should be returned
#[derive(Clone, Debug)]
pub(crate) struct TabularQueryOutputModifiers {
    limit: u32,
    offset: u32,
    /// Boolean flag specifying whether DISTINCT keyword must be applied to results
    distinct: bool,
}

impl TabularQueryOutputModifiers {
    pub(crate) fn new(limit: u32, offset: u32, distinct: bool) -> Self {
        Self {
            limit,
            offset,
            distinct,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RevelationWires<
    const ROW_TREE_MAX_DEPTH: usize,
    const INDEX_TREE_MAX_DEPTH: usize,
    const L: usize,
    const S: usize,
    const PH: usize,
    const PP: usize,
> where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); S * L]:,
{
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    row_tree_paths: [MerklePathTargetInputs<ROW_TREE_MAX_DEPTH>; L],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    index_tree_paths: [MerklePathTargetInputs<INDEX_TREE_MAX_DEPTH>; L],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    row_node_info: [NodeInfoTarget; L],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    index_node_info: [NodeInfoTarget; L],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    is_row_node_leaf: [BoolTarget; L],
    index_column_ids: [Target; 2],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    is_item_included: [BoolTarget; S],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    ids: [Target; S],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    results: [UInt256Target; S * L],
    limit: Target,
    offset: Target,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    distinct: BoolTarget,
    check_placeholder_wires: CheckPlaceholderInputWires<PH, PP>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevelationCircuit<
    const ROW_TREE_MAX_DEPTH: usize,
    const INDEX_TREE_MAX_DEPTH: usize,
    const L: usize,
    const S: usize,
    const PH: usize,
    const PP: usize,
> where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); S * L]:,
{
    /// Path to verify each of the L rows in the rows tree
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    row_tree_paths: [MerklePathGadget<ROW_TREE_MAX_DEPTH>; L],
    /// Path to verify each of the L rows in the index tree
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    index_tree_paths: [MerklePathGadget<INDEX_TREE_MAX_DEPTH>; L],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    /// Info about the nodes of the rows tree storing each of the L rows being proven
    row_node_info: [NodeInfo; L],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    /// Info about the nodes of the index tree that stores the rows trees where each of
    /// the L rows being proven are located
    index_node_info: [NodeInfo; L],
    /// Identifiers of the indexed columns
    index_column_ids: [F; 2],
    /// Actual number of items per-row included in the results.
    num_actual_items_per_row: usize,
    /// Ids of the output items included in the results for each row
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    ids: [F; S],
    /// Output results of the query. They must be provided as input as they are checked against the
    /// one accumulated by the query circuits
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    results: [U256; S * L],
    limit: u32,
    offset: u32,
    /// Boolean flag specifying whether DISTINCT keyword must be applied to results
    distinct: bool,
    /// Input values employed by the `CheckPlaceholderGadget`
    check_placeholder_inputs: CheckPlaceholderGadget<PH, PP>,
}

impl<
        const ROW_TREE_MAX_DEPTH: usize,
        const INDEX_TREE_MAX_DEPTH: usize,
        const L: usize,
        const S: usize,
        const PH: usize,
        const PP: usize,
    > RevelationCircuit<ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, L, S, PH, PP>
where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); S * L]:,
{
    pub(crate) fn new(
        row_paths: [RowPath; L],
        index_column_ids: [F; 2],
        item_ids: &[F],
        results: [Vec<U256>; L],
        query_modifiers: TabularQueryOutputModifiers,
        placeholder_inputs: CheckPlaceholderGadget<PH, PP>,
    ) -> Result<Self> {
        let mut row_tree_paths = [MerklePathGadget::<ROW_TREE_MAX_DEPTH>::default(); L];
        let mut index_tree_paths = [MerklePathGadget::<INDEX_TREE_MAX_DEPTH>::default(); L];
        let mut row_node_info = [NodeInfo::default(); L];
        let mut index_node_info = [NodeInfo::default(); L];
        for (i, row) in row_paths.into_iter().enumerate() {
            row_tree_paths[i] = MerklePathGadget::new(&row.row_tree_path, &row.row_path_siblings)?;
            index_tree_paths[i] =
                MerklePathGadget::new(&row.index_tree_path, &row.index_path_siblings)?;
            row_node_info[i] = row.row_node_info;
            index_node_info[i] = row.index_node_info;
        }

        let num_actual_items_per_row = item_ids.len();
        ensure!(
            num_actual_items_per_row <= S,
            format!("number of results per row is bigger than {}", S)
        );
        let padded_ids = item_ids
            .iter()
            .chain(repeat(&F::default()))
            .take(S)
            .cloned()
            .collect_vec();
        let results = results
            .iter()
            .flat_map(|res| {
                assert!(res.len() >= num_actual_items_per_row);
                res.iter()
                    .cloned()
                    .take(num_actual_items_per_row)
                    .chain(repeat(U256::default()))
                    .take(S)
                    .collect_vec()
            })
            .collect_vec();

        Ok(Self {
            row_tree_paths,
            index_tree_paths,
            row_node_info,
            index_node_info,
            index_column_ids,
            num_actual_items_per_row,
            ids: padded_ids.try_into().unwrap(),
            results: results.try_into().unwrap(),
            limit: query_modifiers.limit,
            offset: query_modifiers.offset,
            distinct: query_modifiers.distinct,
            check_placeholder_inputs: placeholder_inputs,
        })
    }

    pub(crate) fn build(
        b: &mut CBuilder,
        // Proofs of the L rows computed by the universal query circuit
        row_proofs: &[QueryProofPublicInputs<Target, S>; L],
        // proof of construction of the original tree in the pre-processing stage (IVC proof)
        original_tree_proof: &OriginalTreePublicInputs<Target>,
    ) -> RevelationWires<ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, L, S, PH, PP> {
        // allocate input values
        let [row_node_info, index_node_info] =
            array::from_fn(|_| array::from_fn(|_| NodeInfoTarget::build(b)));
        let is_row_node_leaf = array::from_fn(|_| b.add_virtual_bool_target_safe());
        let is_item_included = array::from_fn(|_| b.add_virtual_bool_target_safe());
        let distinct = b.add_virtual_bool_target_safe();
        let ids = b.add_virtual_target_arr();
        let results = b.add_virtual_u256_arr_unsafe(); // unsafe should be ok since they are matched against the order-agnostic digest
                                                       // computed by the universal query circuit
                                                       // closure to access the output items of the i-th result
        let get_result = |i| &results[S * i..S * (i + 1)];
        let (min_query_primary, max_query_primary) = (
            row_proofs[0].min_primary_target(),
            row_proofs[0].max_primary_target(),
        );
        let [limit, offset] = b.add_virtual_target_arr();
        let index_column_ids = b.add_virtual_target_arr();
        let tree_hash = original_tree_proof.merkle_hash();
        let zero = b.zero();
        let one = b.one();
        let zero_u256 = b.zero_u256();
        let _true = b._true();
        let _false = b._false();
        let mut num_results = zero;
        let placeholder_hash = row_proofs[0].placeholder_hash_target();
        let computational_hash = row_proofs[0].computational_hash_target();
        let mut overflow = _false;
        let mut row_paths = vec![];
        let mut index_paths = vec![];
        let mut max_result = None;
        // Flag employed to enforce that the matching rows are all placed in the initial slots;
        // this is a requirement to ensure that the check for DISTINCT is sound
        let mut only_matching_rows = _true;
        row_proofs.iter().enumerate().for_each(|(i, row_proof)| {
            let is_matching_row = b.is_equal(row_proof.num_matching_rows_target(), one);
            // ensure that once `is_matching_row = false`, then it will be false for all
            // subsequent iterations
            only_matching_rows = b.and(only_matching_rows, is_matching_row);
            b.connect(only_matching_rows.target, is_matching_row.target);
            let row_node_hash = {
                // if the node storing the current row is a leaf node in rows tree, then
                // the hash of such node is already computed by `row_proof`; otherwise,
                // we need to compute it
                let inputs = row_node_info[i]
                    .child_hashes
                    .into_iter()
                    .flat_map(|hash| hash.to_targets())
                    .chain(row_node_info[i].node_min.to_targets())
                    .chain(row_node_info[i].node_max.to_targets())
                    .chain(once(index_column_ids[1]))
                    .chain(row_proof.secondary_index_value_target().to_targets())
                    .chain(row_proof.tree_hash_target().to_targets())
                    .collect_vec();
                let row_node_hash = b.hash_n_to_hash_no_pad::<H>(inputs);
                b.select_hash(
                    is_row_node_leaf[i],
                    &row_proof.tree_hash_target(),
                    &row_node_hash,
                )
            };
            let row_path_wires = MerklePathGadget::build(b, row_node_hash, index_column_ids[1]);
            let row_tree_root = row_path_wires.root;
            // compute hash of the index node storing the rows tree containing the current row
            let index_node_hash = {
                let inputs = index_node_info[i]
                    .child_hashes
                    .into_iter()
                    .flat_map(|hash| hash.to_targets())
                    .chain(index_node_info[i].node_min.to_targets())
                    .chain(index_node_info[i].node_max.to_targets())
                    .chain(once(index_column_ids[0]))
                    .chain(row_proof.primary_index_value_target().to_targets())
                    .chain(row_tree_root.to_targets())
                    .collect_vec();
                b.hash_n_to_hash_no_pad::<H>(inputs)
            };
            let index_path_wires = MerklePathGadget::build(b, index_node_hash, index_column_ids[0]);
            // if the current row is valid, check that the root is the same of the original tree, completing
            // membership proof for the current row; otherwise, we don't care
            let root = b.select_hash(is_matching_row, &index_path_wires.root, &tree_hash);
            b.connect_hashes(tree_hash, root);

            row_paths.push(row_path_wires.inputs);
            index_paths.push(index_path_wires.inputs);

            // enforce DISTINCT only for actual results: we enforce the i-th actual result is strictly smaller
            // than the (i+1)-th actual result
            max_result = if let Some(res) = &max_result {
                let current_result: [UInt256Target; S] = get_result(i).to_vec().try_into().unwrap();
                let is_smaller = b.is_less_than_or_equal_to_u256_arr(res, &current_result).0;
                // flag specifying whether we must enforce DISTINCT for the current result or not
                let must_be_enforced = b.and(is_matching_row, distinct);
                let is_smaller = b.and(must_be_enforced, is_smaller);
                b.connect(is_smaller.target, must_be_enforced.target);
                Some(current_result)
            } else {
                Some(get_result(i).to_vec().try_into().unwrap())
            };

            // Expose results for this row.
            // First, we compute the digest of the results corresponding to this row, as computed in the universal
            // query circuit, to check that the results correspond to the one computed by that circuit.
            // To recompute the digest of the results, we first need to build the cells tree that is constructed
            // in the universal query circuit to store the results computed for each row. Note that the
            // universal query circuit stores results in a cells tree since to prove some queries a results tree
            // needs to be built
            let cells_tree_hash =
                build_cells_tree(b, &get_result(i)[2..], &ids[2..], &is_item_included[2..]);
            let second_item = b.select_u256(is_item_included[1], &get_result(i)[1], &zero_u256);
            // digest = D(ids[0]||result[0]||ids[1]||second_item||cells_tree_hash)
            let digest = {
                let inputs = once(ids[0])
                    .chain(get_result(i)[0].to_targets())
                    .chain(once(ids[1]))
                    .chain(second_item.to_targets())
                    .chain(cells_tree_hash.to_targets())
                    .collect_vec();
                b.map_to_curve_point(&inputs)
            };
            // we need to check that the digests are equal only if the current row is valid
            let digest_equal = b.curve_eq(digest, row_proof.first_value_as_curve_target());
            let digest_equal = b.and(digest_equal, is_matching_row);
            b.connect(is_matching_row.target, digest_equal.target);
            num_results = b.add(num_results, is_matching_row.target);

            // check that placeholder hash and computational hash are the same for all
            // the proofs
            b.connect_hashes(row_proof.computational_hash_target(), computational_hash);
            b.connect_hashes(row_proof.placeholder_hash_target(), placeholder_hash);
            // check that query bounds on primary index are the same for all the proofs
            b.enforce_equal_u256(&row_proof.min_primary_target(), &min_query_primary);
            b.enforce_equal_u256(&row_proof.max_primary_target(), &max_query_primary);

            overflow = b.or(overflow, row_proof.overflow_flag_target());
        });

        // finally, check placeholders
        // First, compute the final placeholder hash, adding the primary index query bounds
        let final_placeholder_hash = {
            let inputs = placeholder_hash
                .to_targets()
                .into_iter()
                .chain(min_query_primary.to_targets())
                .chain(max_query_primary.to_targets())
                .collect_vec();
            b.hash_n_to_hash_no_pad::<H>(inputs)
        };
        let check_placeholder_wires = CheckPlaceholderGadget::build(b, &final_placeholder_hash);

        b.enforce_equal_u256(
            &min_query_primary,
            &check_placeholder_wires.input_wires.placeholder_values[0],
        );
        b.enforce_equal_u256(
            &max_query_primary,
            &check_placeholder_wires.input_wires.placeholder_values[1],
        );

        // Add the information about DISTINCT keyword being used or not to the computational hash
        let computational_hash =
            ResultIdentifier::result_id_hash_circuit(b, computational_hash, &distinct);

        // Add the hash of placeholder identifiers and pre-processing metadata
        // hash to the computational hash:
        // H(pQ.C || placeholder_ids_hash || pQ.M)
        let inputs = computational_hash
            .to_targets()
            .iter()
            .chain(&check_placeholder_wires.placeholder_id_hash.to_targets())
            .chain(original_tree_proof.metadata_hash())
            .cloned()
            .collect();
        let computational_hash = b.hash_n_to_hash_no_pad::<H>(inputs);

        let flat_computational_hash = flatten_poseidon_hash_target(b, computational_hash);

        let placeholder_values_slice = check_placeholder_wires
            .input_wires
            .placeholder_values
            .iter()
            .flat_map(ToTargets::to_targets)
            .collect_vec();

        let results_slice = results.iter().flat_map(ToTargets::to_targets).collect_vec();

        // Register the public innputs.
        PublicInputs::<_, L, S, PH>::new(
            &original_tree_proof.block_hash(),
            &flat_computational_hash,
            &placeholder_values_slice,
            &results_slice,
            &[check_placeholder_wires.num_placeholders],
            // The aggregation query proof only has one result.
            &[num_results],
            &[num_results],
            &[overflow.target],
            // Query limit
            &[zero],
            // Query offset
            &[zero],
        )
        .register(b);

        RevelationWires {
            row_tree_paths: row_paths.try_into().unwrap(),
            index_tree_paths: index_paths.try_into().unwrap(),
            row_node_info,
            index_node_info,
            is_row_node_leaf,
            index_column_ids,
            is_item_included,
            ids,
            results,
            limit,
            offset,
            distinct,
            check_placeholder_wires: check_placeholder_wires.input_wires,
        }
    }

    pub(crate) fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &RevelationWires<ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, L, S, PH, PP>,
    ) {
        self.row_tree_paths
            .iter()
            .zip(wires.row_tree_paths.iter())
            .for_each(|(value, target)| value.assign(pw, target));
        self.index_tree_paths
            .iter()
            .zip(wires.index_tree_paths.iter())
            .for_each(|(value, target)| value.assign(pw, target));
        [
            (self.row_node_info, &wires.row_node_info),
            (self.index_node_info, &wires.index_node_info),
        ]
        .into_iter()
        .for_each(|(nodes, target_nodes)| {
            nodes
                .iter()
                .zip(target_nodes)
                .for_each(|(&value, target)| target.set_target(pw, &value))
        });
        wires
            .is_item_included
            .iter()
            .enumerate()
            .for_each(|(i, &target)| pw.set_bool_target(target, i < self.num_actual_items_per_row));
        self.row_node_info
            .iter()
            .zip(wires.is_row_node_leaf)
            .for_each(|(&node_info, target)| pw.set_bool_target(target, node_info.is_leaf));
        self.results
            .iter()
            .zip(wires.results.iter())
            .for_each(|(&value, target)| pw.set_u256_target(target, value));
        pw.set_target_arr(&wires.ids, &self.ids);
        pw.set_target_arr(&wires.index_column_ids, &self.index_column_ids);
        pw.set_target(wires.limit, self.limit.to_field());
        pw.set_target(wires.offset, self.offset.to_field());
        pw.set_bool_target(wires.distinct, self.distinct);
        self.check_placeholder_inputs
            .assign(pw, &wires.check_placeholder_wires);
    }
}

/// Compute the inputs for the dummy proof to be employed to pad up to L the number of
/// proofs provided as input to the revelation circuit. The proof is generated by
/// running the non-existence circuit over a fake index-tree node
pub(crate) fn generate_dummy_row_proof_inputs<
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_ITEMS_PER_OUTPUT: usize,
>(
    column_ids: &ColumnIDs,
    predicate_operations: &[BasicOperation],
    results: &ResultStructure,
    placeholders: &Placeholders,
    query_bounds: &QueryBounds,
) -> Result<
    UniversalCircuitInput<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_ITEMS_PER_OUTPUT,
    >,
>
where
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
    [(); 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS)]:,
    [(); MAX_NUM_ITEMS_PER_OUTPUT - 1]:,
    [(); <H as Hasher<F>>::HASH_SIZE]:,
{
    // we generate dummy column cells; we can use all dummy values, except for the
    // primary index value which must be in the query range
    let primary_index_value = query_bounds.min_query_primary();
    let primary_index_column = ColumnCell {
        value: primary_index_value,
        id: column_ids.primary,
    };
    let secondary_index_column = ColumnCell {
        value: U256::default(),
        id: column_ids.secondary,
    };
    let non_indexed_columns = column_ids
        .non_indexed_columns()
        .iter()
        .map(|id| ColumnCell::new(*id, U256::default()))
        .collect_vec();
    let cells = RowCells::new(
        primary_index_column,
        secondary_index_column,
        non_indexed_columns,
    );
    let universal_query_circuit = UniversalQueryCircuitInputs::new(
        &cells,
        predicate_operations,
        placeholders,
        false,
        query_bounds,
        results,
        true, // we generate proof for a dummy row
    )?;
    Ok(UniversalCircuitInput::QueryNoAgg(universal_query_circuit))
}

pub struct CircuitBuilderParams {
    pub(crate) universal_query_vk: VerifierCircuitData<F, C, D>,
    pub(crate) preprocessing_circuit_set: RecursiveCircuits<F, C, D>,
    pub(crate) preprocessing_vk: VerifierOnlyCircuitData<C, D>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecursiveCircuitWires<
    const ROW_TREE_MAX_DEPTH: usize,
    const INDEX_TREE_MAX_DEPTH: usize,
    const L: usize,
    const S: usize,
    const PH: usize,
    const PP: usize,
> where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); S * L]:,
{
    revelation_circuit: RevelationWires<ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, L, S, PH, PP>,
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    row_verifiers: [ProofWithPublicInputsTarget<D>; L],
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    preprocessing_proof: ProofWithPublicInputsTarget<D>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecursiveCircuitInputs<
    const ROW_TREE_MAX_DEPTH: usize,
    const INDEX_TREE_MAX_DEPTH: usize,
    const L: usize,
    const S: usize,
    const PH: usize,
    const PP: usize,
> where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); S * L]:,
{
    pub(crate) inputs: RevelationCircuit<ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, L, S, PH, PP>,
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) row_proofs: [ProofWithPublicInputs<F, C, D>; L],
    pub(crate) preprocessing_proof: ProofWithPublicInputs<F, C, D>,
    pub(crate) query_circuit_set: RecursiveCircuits<F, C, D>,
}

impl<
        const ROW_TREE_MAX_DEPTH: usize,
        const INDEX_TREE_MAX_DEPTH: usize,
        const L: usize,
        const S: usize,
        const PH: usize,
        const PP: usize,
    > CircuitLogicWires<F, D, 0>
    for RecursiveCircuitWires<ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, L, S, PH, PP>
where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); S * L]:,
    [(); <H as Hasher<F>>::HASH_SIZE]:,
{
    type CircuitBuilderParams = CircuitBuilderParams;

    type Inputs = RecursiveCircuitInputs<ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, L, S, PH, PP>;

    const NUM_PUBLIC_INPUTS: usize = revelation_pi_len::<L, S, PH>();

    fn circuit_logic(
        builder: &mut CBuilder,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let row_verifiers = [0; L]
            .map(|_| verify_proof_fixed_circuit(builder, &builder_parameters.universal_query_vk));
        let preprocessing_verifier =
            RecursiveCircuitsVerifierGagdet::<F, C, D, NUM_PREPROCESSING_IO>::new(
                default_config(),
                &builder_parameters.preprocessing_circuit_set,
            );
        let preprocessing_proof = preprocessing_verifier.verify_proof_fixed_circuit_in_circuit_set(
            builder,
            &builder_parameters.preprocessing_vk,
        );
        let row_pis = row_verifiers
            .iter()
            .map(|verifier| QueryProofPublicInputs::from_slice(&verifier.public_inputs))
            .collect_vec();
        let preprocessing_pi =
            OriginalTreePublicInputs::from_slice(&preprocessing_proof.public_inputs);
        let revelation_circuit =
            RevelationCircuit::build(builder, &row_pis.try_into().unwrap(), &preprocessing_pi);

        Self {
            revelation_circuit,
            row_verifiers,
            preprocessing_proof,
        }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        for (verifier_target, row_proof) in self.row_verifiers.iter().zip(inputs.row_proofs) {
            pw.set_proof_with_pis_target(verifier_target, &row_proof);
        }
        pw.set_proof_with_pis_target(&self.preprocessing_proof, &inputs.preprocessing_proof);
        inputs.inputs.assign(pw, &self.revelation_circuit);
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::{array, cmp::Ordering, iter::once};

    use crate::{C, D, F};
    use alloy::primitives::U256;
    use futures::{stream, StreamExt};
    use itertools::Itertools;
    use mp2_common::{
        group_hashing::map_to_curve_point,
        types::{HashOutput, CURVE_TARGET_LEN},
        u256::is_less_than_or_equal_to_u256_arr,
        utils::ToFields,
    };
    use mp2_test::{
        cells_tree::{compute_cells_tree_hash, TestCell},
        circuit::{run_circuit, UserCircuit},
        utils::{gen_random_field_hash, gen_random_u256},
    };
    use plonky2::{
        field::types::{Field, Sample},
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{circuit_builder::CircuitBuilder, config::GenericHashOut},
    };
    use rand::{thread_rng, Rng};

    use crate::{
        ivc::{
            public_inputs::H_RANGE as ORIGINAL_TREE_H_RANGE,
            PublicInputs as OriginalTreePublicInputs,
        },
        query::{
            pi_len as query_pi_len,
            public_inputs::{
                PublicInputsUniversalCircuit as QueryProofPublicInputs,
                QueryPublicInputsUniversalCircuit,
            },
            utils::{ChildPosition, NodeInfo},
        },
        revelation::{
            revelation_unproven_offset::{RowPath, TabularQueryOutputModifiers},
            tests::TestPlaceholders,
            NUM_PREPROCESSING_IO,
        },
        test_utils::random_aggregation_operations,
    };

    use super::{RevelationCircuit, RevelationWires};

    #[derive(Clone, Debug)]
    struct TestRevelationCircuit<
        'a,
        const ROW_TREE_MAX_DEPTH: usize,
        const INDEX_TREE_MAX_DEPTH: usize,
        const L: usize,
        const S: usize,
        const PH: usize,
        const PP: usize,
    >
    where
        [(); ROW_TREE_MAX_DEPTH - 1]:,
        [(); INDEX_TREE_MAX_DEPTH - 1]:,
        [(); S * L]:,
    {
        circuit: RevelationCircuit<ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, L, S, PH, PP>,
        row_pis: &'a [Vec<F>; L],
        original_tree_pis: &'a [F],
    }

    impl<
            const ROW_TREE_MAX_DEPTH: usize,
            const INDEX_TREE_MAX_DEPTH: usize,
            const L: usize,
            const S: usize,
            const PH: usize,
            const PP: usize,
        > UserCircuit<F, D>
        for TestRevelationCircuit<'_, ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, L, S, PH, PP>
    where
        [(); ROW_TREE_MAX_DEPTH - 1]:,
        [(); INDEX_TREE_MAX_DEPTH - 1]:,
        [(); S * L]:,
    {
        type Wires = (
            RevelationWires<ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, L, S, PH, PP>,
            [Vec<Target>; L],
            Vec<Target>,
        );

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let row_pis_raw: [Vec<Target>; L] = (0..L)
                .map(|_| c.add_virtual_targets(query_pi_len::<S>()))
                .collect_vec()
                .try_into()
                .unwrap();
            let original_pis_raw = c.add_virtual_targets(NUM_PREPROCESSING_IO);
            let row_pis = row_pis_raw
                .iter()
                .map(|pis| QueryProofPublicInputs::from_slice(pis))
                .collect_vec()
                .try_into()
                .unwrap();
            let original_pis = OriginalTreePublicInputs::from_slice(&original_pis_raw);
            let revelation_wires = RevelationCircuit::build(c, &row_pis, &original_pis);
            (revelation_wires, row_pis_raw, original_pis_raw)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.circuit.assign(pw, &wires.0);
            self.row_pis
                .iter()
                .zip(&wires.1)
                .for_each(|(pis, pis_target)| pw.set_target_arr(pis_target, pis));
            pw.set_target_arr(&wires.2, self.original_tree_pis);
        }
    }

    // test function for this revelation circuit. If `distinct` is true, then the
    // results are enforced to be distinct
    async fn test_revelation_unproven_offset_circuit(distinct: bool) {
        const ROW_TREE_MAX_DEPTH: usize = 10;
        const INDEX_TREE_MAX_DEPTH: usize = 10;
        const L: usize = 5;
        const S: usize = 7;
        const PH: usize = 10;
        const PP: usize = 30;
        let ops = random_aggregation_operations::<S>();
        let mut row_pis = QueryProofPublicInputs::sample_from_ops(&ops);
        let rng = &mut thread_rng();
        let mut original_tree_pis = (0..NUM_PREPROCESSING_IO)
            .map(|_| rng.gen())
            .collect::<Vec<u32>>()
            .to_fields();
        let index_ids = F::rand_array();
        const NUM_PLACEHOLDERS: usize = 5;
        let test_placeholders = TestPlaceholders::sample(NUM_PLACEHOLDERS);
        let computational_hash = {
            let row_pi_0 = QueryProofPublicInputs::<_, S>::from_slice(&row_pis[0]);
            row_pi_0.computational_hash()
        };
        let placeholder_hash = test_placeholders.query_placeholder_hash;
        let min_query_primary = test_placeholders.min_query;
        let max_query_primary = test_placeholders.max_query;
        // set same primary index query bounds, computational hash and placeholder hash for all proofs;
        // set also num matching rows to 1 for all proofs
        row_pis.iter_mut().for_each(|pis| {
            let [min_primary_range, max_primary_range, ch_range, ph_range, count_range] = [
                QueryPublicInputsUniversalCircuit::MinPrimary,
                QueryPublicInputsUniversalCircuit::MaxPrimary,
                QueryPublicInputsUniversalCircuit::ComputationalHash,
                QueryPublicInputsUniversalCircuit::PlaceholderHash,
                QueryPublicInputsUniversalCircuit::NumMatching,
            ]
            .map(QueryProofPublicInputs::<F, S>::to_range);
            pis[min_primary_range].copy_from_slice(&min_query_primary.to_fields());
            pis[max_primary_range].copy_from_slice(&max_query_primary.to_fields());
            pis[ch_range].copy_from_slice(&computational_hash.to_fields());
            pis[ph_range].copy_from_slice(&placeholder_hash.to_fields());
            pis[count_range].copy_from_slice(&[F::ONE]);
        });
        let hash_range =
            QueryProofPublicInputs::<F, S>::to_range(QueryPublicInputsUniversalCircuit::TreeHash);
        let index_value_range = QueryProofPublicInputs::<F, S>::to_range(
            QueryPublicInputsUniversalCircuit::PrimaryIndexValue,
        );
        // build a test tree containing the rows 0..5 found in row_pis
        // Index tree:
        //          A
        //      B       C
        // Rows tree A:
        //          0
        //      1
        // Rows tree B:
        //          2
        // Rows tree C:
        //          3
        //      4       5
        let node_1 = {
            let row_pi = QueryProofPublicInputs::<_, S>::from_slice(&row_pis[1]);
            let embedded_tree_hash =
                HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap();
            let node_value = row_pi.secondary_index_value();
            NodeInfo::new(
                &embedded_tree_hash,
                None,
                None,
                node_value,
                node_value,
                node_value,
            )
        };
        // set hash in row 1 proof to node 1 hash, given that node 1 is a leaf node
        let node_1_hash = node_1.compute_node_hash(index_ids[1]);
        row_pis[1][hash_range.clone()].copy_from_slice(&node_1_hash.to_fields());
        let node_0 = {
            let row_pi = QueryProofPublicInputs::<_, S>::from_slice(&row_pis[0]);
            let embedded_tree_hash = HashOutput::from(row_pi.tree_hash());
            let node_value = row_pi.secondary_index_value();
            // left child is node 1
            let left_child_hash = HashOutput::from(node_1_hash);
            NodeInfo::new(
                &embedded_tree_hash,
                Some(&left_child_hash),
                None,
                node_value,
                node_1.min,
                node_value,
            )
        };
        let node_2 = {
            let row_pi = QueryProofPublicInputs::<_, S>::from_slice(&row_pis[2]);
            let embedded_tree_hash = HashOutput::from(gen_random_field_hash::<F>());
            let node_value = row_pi.secondary_index_value();
            NodeInfo::new(
                &embedded_tree_hash,
                None,
                None,
                node_value,
                node_value,
                node_value,
            )
        };
        // set hash in row 2 proof to node 2 hash, given that node 2 is a leaf node
        let node_2_hash = node_2.compute_node_hash(index_ids[1]);
        row_pis[2][hash_range.clone()].copy_from_slice(&node_2_hash.to_fields());
        let node_4 = {
            let row_pi = QueryProofPublicInputs::<_, S>::from_slice(&row_pis[4]);
            let embedded_tree_hash = HashOutput::from(gen_random_field_hash::<F>());
            let node_value = row_pi.secondary_index_value();
            NodeInfo::new(
                &embedded_tree_hash,
                None,
                None,
                node_value,
                node_value,
                node_value,
            )
        };
        // set hash in row 4 proof to node 4 hash, given that node 4 is a leaf node
        let node_4_hash = node_4.compute_node_hash(index_ids[1]);
        row_pis[4][hash_range.clone()].copy_from_slice(&node_4_hash.to_fields());
        let node_5 = {
            // can use all dummy values for this node, since there is no proof associated to it
            let embedded_tree_hash = HashOutput::from(gen_random_field_hash::<F>());
            let [node_value, node_min, node_max] = array::from_fn(|_| gen_random_u256(rng));
            NodeInfo::new(
                &embedded_tree_hash,
                None,
                None,
                node_value,
                node_min,
                node_max,
            )
        };
        let node_4_hash = HashOutput::from(node_4_hash);
        let node_5_hash = HashOutput::from(node_5.compute_node_hash(index_ids[1]));
        let node_3 = {
            let row_pi = QueryProofPublicInputs::<_, S>::from_slice(&row_pis[3]);
            let embedded_tree_hash = HashOutput::from(row_pi.tree_hash());
            let node_value = row_pi.secondary_index_value();
            NodeInfo::new(
                &embedded_tree_hash,
                Some(&node_4_hash), // left child is node 4
                Some(&node_5_hash), // right child is node 5
                node_value,
                node_4.min,
                node_5.max,
            )
        };
        let node_b = {
            let row_pi = QueryProofPublicInputs::<_, S>::from_slice(&row_pis[2]);
            let embedded_tree_hash = HashOutput::from(node_2.compute_node_hash(index_ids[1]));
            let node_value = row_pi.primary_index_value();
            NodeInfo::new(
                &embedded_tree_hash,
                None,
                None,
                node_value,
                node_value,
                node_value,
            )
        };
        let node_c = {
            let row_pi = QueryProofPublicInputs::<_, S>::from_slice(&row_pis[3]);
            let embedded_tree_hash = HashOutput::from(node_3.compute_node_hash(index_ids[1]));
            let node_value = row_pi.primary_index_value();
            // we need to set index value in `row_pis[4]` to the same value of `row_pis[3]`, as
            // they are in the same index tree
            row_pis[4][index_value_range.clone()].copy_from_slice(&node_value.to_fields());
            NodeInfo::new(
                &embedded_tree_hash,
                None,
                None,
                node_value,
                node_value,
                node_value,
            )
        };
        let node_b_hash = HashOutput::from(node_b.compute_node_hash(index_ids[0]));
        let node_c_hash = HashOutput::from(node_c.compute_node_hash(index_ids[0]));
        let node_a = {
            let row_pi = QueryProofPublicInputs::<_, S>::from_slice(&row_pis[0]);
            let embedded_tree_hash = HashOutput::from(node_0.compute_node_hash(index_ids[1]));
            let node_value = row_pi.primary_index_value();
            // we need to set index value in `row_pis[1]` to the same value of `row_pis[0]`, as
            // they are in the same index tree
            row_pis[1][index_value_range].copy_from_slice(&node_value.to_fields());
            NodeInfo::new(
                &embedded_tree_hash,
                Some(&node_b_hash), // left child is node B
                Some(&node_c_hash), // right child is node C
                node_value,
                node_b.min,
                node_c.max,
            )
        };
        // set original tree PI to the root of the tree
        let root = node_a.compute_node_hash(index_ids[0]);
        original_tree_pis[ORIGINAL_TREE_H_RANGE].copy_from_slice(&root.to_fields());

        // sample final results and set order-agnostic digests in row_pis proofs accordingly
        const NUM_ACTUAL_ITEMS_PER_OUTPUT: usize = 4;
        let mut results: [[U256; NUM_ACTUAL_ITEMS_PER_OUTPUT]; L] = if distinct {
            // generate all the output values distinct from each other; generating at
            // random will make them distinct with overwhelming probability
            array::from_fn(|_| array::from_fn(|_| gen_random_u256(rng)))
        } else {
            // generate some values which are the same
            let mut res = array::from_fn(|_| array::from_fn(|_| gen_random_u256(rng)));
            res[L - 1] = res[0];
            res
        };

        // sort them to ensure that DISTINCT constraints are satisfied
        results.sort_by(|a, b| {
            let (is_smaller, is_eq) = is_less_than_or_equal_to_u256_arr(a, b);
            if is_smaller {
                return Ordering::Less;
            }
            if is_eq {
                return Ordering::Equal;
            }
            Ordering::Greater
        });
        // random ids of output items
        let ids: [F; NUM_ACTUAL_ITEMS_PER_OUTPUT] = F::rand_array();

        let digests = stream::iter(results.iter())
            .then(|res| async {
                // build set of cells for the cells tree
                let cells = res
                    .iter()
                    .zip(ids.iter())
                    .map(|(value, id)| TestCell::new(*value, *id))
                    .collect_vec();
                map_to_curve_point(
                    &once(cells[0].id)
                        .chain(cells[0].value.to_fields())
                        .chain(once(cells.get(1).map(|cell| cell.id).unwrap_or_default()))
                        .chain(
                            cells
                                .get(1)
                                .map(|cell| cell.value)
                                .unwrap_or_default()
                                .to_fields(),
                        )
                        .chain(
                            compute_cells_tree_hash(cells.get(2..).unwrap_or_default().to_vec())
                                .await
                                .to_vec(),
                        )
                        .collect_vec(),
                )
            })
            .collect::<Vec<_>>()
            .await;

        row_pis.iter_mut().zip(digests).for_each(|(pis, digest)| {
            let values_range = QueryProofPublicInputs::<F, S>::to_range(
                QueryPublicInputsUniversalCircuit::OutputValues,
            );
            pis[values_range.start..values_range.start + CURVE_TARGET_LEN]
                .copy_from_slice(&digest.to_fields())
        });

        // prepare RowPath inputs for each row
        let row_path_1 = RowPath {
            row_node_info: node_1,
            row_tree_path: vec![(node_0, ChildPosition::Left)],
            row_path_siblings: vec![None],
            index_node_info: node_a,
            index_tree_path: vec![],
            index_path_siblings: vec![],
        };
        let row_path_0 = RowPath {
            row_node_info: node_0,
            row_tree_path: vec![],
            row_path_siblings: vec![],
            index_node_info: node_a,
            index_tree_path: vec![],
            index_path_siblings: vec![],
        };
        let row_path_2 = RowPath {
            row_node_info: node_2,
            row_tree_path: vec![],
            row_path_siblings: vec![],
            index_node_info: node_b,
            index_tree_path: vec![(node_a, ChildPosition::Left)],
            index_path_siblings: vec![Some(node_c_hash)],
        };
        let row_path_4 = RowPath {
            row_node_info: node_4,
            row_tree_path: vec![(node_3, ChildPosition::Left)],
            row_path_siblings: vec![Some(node_5_hash)],
            index_node_info: node_c,
            index_tree_path: vec![(node_a, ChildPosition::Right)],
            index_path_siblings: vec![Some(node_b_hash)],
        };
        let row_path_3 = RowPath {
            row_node_info: node_3,
            row_tree_path: vec![],
            row_path_siblings: vec![],
            index_node_info: node_c,
            index_tree_path: vec![(node_a, ChildPosition::Right)],
            index_path_siblings: vec![Some(node_b_hash)],
        };

        let circuit =
            TestRevelationCircuit::<ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, L, S, PH, PP> {
                circuit: RevelationCircuit::new(
                    [row_path_0, row_path_1, row_path_2, row_path_3, row_path_4],
                    index_ids,
                    &ids,
                    results.map(|res| res.to_vec()),
                    TabularQueryOutputModifiers::new(0, 0, false),
                    test_placeholders.check_placeholder_inputs,
                )
                .unwrap(),
                row_pis: &row_pis,
                original_tree_pis: &original_tree_pis,
            };

        let _ = run_circuit::<F, D, C, _>(circuit);
    }

    #[tokio::test]
    async fn test_revelation_unproven_offset_circuit_no_distinct() {
        test_revelation_unproven_offset_circuit(false).await
    }

    #[tokio::test]
    async fn test_revelation_unproven_offset_circuit_distinct() {
        test_revelation_unproven_offset_circuit(true).await
    }
}
