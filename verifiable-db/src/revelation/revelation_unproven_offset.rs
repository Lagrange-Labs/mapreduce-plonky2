//! This module contains the final revelation circuit for SELECT queries without
//! aggregate function, where we just return at most `LIMIT` results, without
//! proving the `OFFSET` in the set of results. Note that this means that the
//! prover could censor some actual results of the query, but they cannot be
//! faked

use std::{array, iter::{once, repeat}};
use anyhow::Result;

use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{group_hashing::CircuitBuilderGroupHashing, poseidon::{flatten_poseidon_hash_target, H}, public_inputs::PublicInputCommon, serialization::{deserialize_array, deserialize_long_array, serialize_array, serialize_long_array}, types::CBuilder, u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256}, utils::{Fieldable, SelectHashBuilder, ToTargets}, F};
use plonky2::{hash::hash_types::{HashOut, HashOutTarget}, iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}}};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use serde::{Deserialize, Serialize};

use crate::{ivc::PublicInputs as OriginalTreePublicInputs, query::{aggregation::{ChildPosition, NodeInfo}, merkle_path::{MerklePathGadget, MerklePathTargetInputs}, public_inputs::PublicInputs as QueryProofPublicInputs, universal_circuit::build_cells_tree}
};

use super::{placeholders_check::{CheckPlaceholderGadget, CheckPlaceholderInputWires}, PublicInputs};

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
        self.child_hashes.iter().zip(inputs.child_hashes).for_each(|(&target, value)|
            pw.set_hash_target(target, value)
        );
        pw.set_u256_target(&self.node_min, inputs.min);
        pw.set_u256_target(&self.node_max, inputs.max);
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
> 
where 
    [(); ROW_TREE_MAX_DEPTH -1]:,
    [(); INDEX_TREE_MAX_DEPTH -1]:,
    [(); S*L]:,
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
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    is_row_valid: [BoolTarget; L],
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
    results: [UInt256Target; S*L],
    limit: Target,
    offset: Target,
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
> 
where 
    [(); ROW_TREE_MAX_DEPTH -1]:,
    [(); INDEX_TREE_MAX_DEPTH -1]:, 
    [(); S*L]:,
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
    /// How many rows among the L ones being proven have to be included in the output results
    num_valid_rows: usize,
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
    results: [U256; S*L],
    limit: u64,
    offset: u64,
    /// Input values employed by the `CheckPlaceholderGadget`
    check_placeholder_inputs: CheckPlaceholderGadget<PH, PP>,
}

pub struct RowPath {
    /// Info about the node of the row tree storing the row
    row_node_info: NodeInfo,
    /// Info about the nodes in the path of the rows tree for the node storing the row; The `ChildPosition` refers to 
    /// the position of the previous node in the path as a child of the current node
    row_tree_path: Vec<(NodeInfo, ChildPosition)>,
    /// Info about the siblings of the node in the rows tree path (except for the root)
    row_path_siblings: Vec<Option<NodeInfo>>,
    /// Info about the node of the index tree storing the rows tree containing the row
    index_node_info: NodeInfo,
    /// Info about the nodes in the path of the index tree for the index_node; The `ChildPosition` refers to 
    /// the position of the previous node in the path as a child of the current node
    index_tree_path: Vec<(NodeInfo, ChildPosition)>,
    /// Info about the siblings of the nodes in the index tree path (except for the root)
    index_path_siblings: Vec<Option<NodeInfo>>,
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
    [(); ROW_TREE_MAX_DEPTH -1]:,
    [(); INDEX_TREE_MAX_DEPTH -1]:,
    [(); S*L]:,
{
    pub(crate) fn new(
        row_paths: [RowPath; L],
        num_valid_rows: usize,
        num_actual_items_per_row: usize,
        index_ids: [u64; 2],
        item_ids: &[u64],
        results: [Vec<U256>; L],
        limit: u64,
        offset: u64,
        placeholder_inputs: CheckPlaceholderGadget<PH, PP>,
    ) -> Result<Self> {
        let mut row_tree_paths = [MerklePathGadget::<ROW_TREE_MAX_DEPTH>::default(); L];
        let mut index_tree_paths = [MerklePathGadget::<INDEX_TREE_MAX_DEPTH>::default(); L];
        let mut row_node_info = [NodeInfo::default(); L];
        let mut index_node_info = [NodeInfo::default(); L];
        for (i, row)  in  row_paths.into_iter().enumerate() {
            row_tree_paths[i] = MerklePathGadget::new(
                &row.row_tree_path, 
                &row.row_path_siblings, 
                index_ids[1],
            )?;
            index_tree_paths[i] = MerklePathGadget::new(
                &row.index_tree_path, 
                &row.index_path_siblings, 
                index_ids[0],
            )?;
            row_node_info[i] = row.row_node_info;
            index_node_info[i] = row.index_node_info;
        }

        let padded_ids = item_ids.into_iter()
            .chain(repeat(&u64::default()))
            .take(S)
            .map(|id| id.to_field())
            .collect_vec();

        let results = results.iter().flat_map(|res|
            res.into_iter()
                .cloned()
                .chain(repeat(U256::default()))
                .take(S)
                .collect_vec()
        ).collect_vec();

        Ok(Self {
            row_tree_paths,
            index_tree_paths,
            row_node_info,
            index_node_info,
            num_valid_rows,
            num_actual_items_per_row,
            ids: padded_ids.try_into().unwrap(),
            results: results.try_into().unwrap(),
            limit,
            offset,
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
        let [row_node_info, index_node_info] = array::from_fn(|_|
            array::from_fn(|_| NodeInfoTarget::build(b))
        );
        let [is_row_node_leaf, is_row_valid] = array::from_fn(|_| 
            array::from_fn(|_|
                b.add_virtual_bool_target_safe()
            )
        );
        let is_item_included = array::from_fn(|_|
            b.add_virtual_bool_target_safe()
        );
        let ids = b.add_virtual_target_arr();
        let results = b.add_virtual_u256_arr_unsafe(); // unsafe should be ok since they are matched against the order-agnostic digest
                // computed by the universal query circuit
        // closure to access the output items of the i-th result
        let get_result = |i| {
            &results[S*i..S*(i+1)]
        }; 
        let [min_query, max_query] = b.add_virtual_u256_arr_unsafe(); // unsafe should be ok since they are later included in placeholder hash
        let [limit, offset] = b.add_virtual_target_arr();
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
        row_proofs.into_iter().enumerate().for_each(|(i, row_proof)| {
            let index_ids = row_proof.index_ids_target();
            let row_node_hash = {
                // if the node storing the current row is a leaf node in rows tree, then
                // the hash of such node is already computed by `row_proof`; otherwise,
                // we need to compute it
                let inputs = row_node_info[i].child_hashes.into_iter().flat_map(|hash| hash.to_targets())
                    .chain(row_node_info[i].node_min.to_targets())
                    .chain(row_node_info[i].node_max.to_targets())
                    .chain(once(index_ids[1]))
                    .chain(row_proof.min_value_target().to_targets())
                    .chain(row_proof.tree_hash_target().to_targets())
                    .collect_vec();
                let row_node_hash = b.hash_n_to_hash_no_pad::<H>(inputs);
                b.select_hash(
                    is_row_node_leaf[i], 
                    &row_proof.tree_hash_target(), 
                    &row_node_hash,
                )
            };
            let row_path_wires = MerklePathGadget::build(
                b, 
                row_node_hash, 
                index_ids[1]
            );
            let row_tree_root = row_path_wires.root;
            // compute hash of the index node storing the rows tree containing the current row
            let index_node_hash = {
                let inputs = index_node_info[i].child_hashes.into_iter().flat_map(|hash| hash.to_targets())
                .chain(index_node_info[i].node_min.to_targets())
                .chain(index_node_info[i].node_max.to_targets())
                    .chain(once(index_ids[0]))
                    .chain(row_proof.index_value_target().to_targets())
                    .chain(row_tree_root.to_targets())
                    .collect_vec();
                b.hash_n_to_hash_no_pad::<H>(inputs)
            };
            let index_path_wires = MerklePathGadget::build(
                b, 
                index_node_hash, 
                index_ids[0]
            );
            // check that the root is the same of the original tree, completing membership
	        // proof for the current row
            b.connect_hashes(tree_hash, index_path_wires.root);
            
            row_paths.push(row_path_wires.inputs);
            index_paths.push(index_path_wires.inputs);
            // check that the primary index value for the current row is within the query
	        // bounds
            let index_value = row_proof.index_value_target();
            let greater_than_min = b.is_less_or_equal_than_u256(&min_query, &index_value);
            let smaller_than_max = b.is_less_or_equal_than_u256(&index_value, &max_query);
            let in_range = b.and(greater_than_min, smaller_than_max);
            b.connect(in_range.target, _true.target);

            // Expose results for this row. 
	        // First, we compute the digest of the results corresponding to this row, as computed in the universal
            // query circuit, to check that the results correspond to the one computed by that circuit
            let cells_tree_hash = build_cells_tree(b, &get_result(i)[2..], &ids[2..], &is_item_included[2..]);
            let second_item  = b.select_u256(
                is_item_included[1], 
                &get_result(i)[1], 
                &zero_u256,
            );
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
            // also, we enforce that the current row is a matching row only if the current row is valid
            let is_matching_row = b.is_equal(row_proof.num_matching_rows_target(), one);
            let equal_and_matching_row = b.and(digest_equal, is_matching_row);
            let equal_and_matching_row = b.and(equal_and_matching_row, is_row_valid[i]);
            b.connect(is_row_valid[i].target, equal_and_matching_row.target);
            num_results = b.add(num_results, is_row_valid[i].target);
            
            // check that placeholder hash and computational hash are the same for all
            // the proofs
            b.connect_hashes(row_proof.computational_hash_target(), computational_hash);
            b.connect_hashes(row_proof.placeholder_hash_target(), placeholder_hash);

            overflow = b.or(overflow, row_proof.overflow_flag_target());
        });

    // finally, check placeholders
    // First, compute the final placeholder hash, adding the primary index query bounds
    let final_placeholder_hash = {
        let inputs = placeholder_hash.to_targets().into_iter()
            .chain(min_query.to_targets())
            .chain(max_query.to_targets())
            .collect_vec();
        b.hash_n_to_hash_no_pad::<H>(inputs)
    };
    let check_placeholder_wires = CheckPlaceholderGadget::build(
        b,
        &final_placeholder_hash,
    );

    b.enforce_equal_u256(&min_query, &check_placeholder_wires.input_wires.placeholder_values[0]);
    b.enforce_equal_u256(&max_query, &check_placeholder_wires.input_wires.placeholder_values[1]);
    

    // Add the hash of placeholder identifiers and pre-processing metadata
    // hash to the computational hash:
    // H(pQ.C || placeholder_ids_hash || pQ.M)
    let inputs = computational_hash.to_targets()
        .iter()
        .chain(&check_placeholder_wires.placeholder_id_hash.to_targets())
        .chain(original_tree_proof.metadata_hash())
        .cloned()
        .collect();
    let computational_hash = b.hash_n_to_hash_no_pad::<H>(inputs);

    let flat_computational_hash = flatten_poseidon_hash_target(b, computational_hash);

    let placeholder_values_slice = check_placeholder_wires.input_wires.placeholder_values
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
        is_row_valid,
        is_item_included,
        ids,
        results,
        limit,
        offset,
        check_placeholder_wires: check_placeholder_wires.input_wires,
    }

    }

    pub(crate) fn assign(
        &self, 
        pw: &mut PartialWitness<F>, 
        wires: &RevelationWires<ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, L, S, PH, PP>
    ) {
        self.row_tree_paths.iter().zip(wires.row_tree_paths.iter()).for_each(|(value, target)|
                value.assign(pw, target)
        );
        self.index_tree_paths.iter().zip(wires.index_tree_paths.iter()).for_each(|(value, target)|
                value.assign(pw, target)
        );
        [
            (self.row_node_info, &wires.row_node_info),
            (self.index_node_info, &wires.index_node_info),
        ].into_iter().for_each(|(nodes, target_nodes)|
            nodes.iter().zip(target_nodes).for_each(|(&value, target)|
                target.set_target(pw, &value)
            )
        );
        wires.is_row_valid.iter().enumerate().for_each(|(i, &target)| 
            pw.set_bool_target(target, i < self.num_valid_rows)
        );
        wires.is_item_included.iter().enumerate().for_each(|(i, &target)| 
            pw.set_bool_target(target, i < self.num_actual_items_per_row)
        );
        self.row_node_info.iter().zip(wires.is_row_node_leaf).for_each(|(&node_info, target)| 
            pw.set_bool_target(target, node_info.is_leaf)
        );
        self.results.iter().zip(wires.results.iter()).for_each(|(&value, target)|
            pw.set_u256_target(target, value)
        );
        pw.set_target_arr(&wires.ids, &self.ids);
        pw.set_target(wires.limit, self.limit.to_field());
        pw.set_target(wires.offset, self.offset.to_field());
        self.check_placeholder_inputs.assign(pw, &wires.check_placeholder_wires);  
    }
}


#[cfg(test)]
mod tests {

    use std::{array, iter::once};

    use alloy::primitives::U256;
    use futures::{stream, StreamExt};
    use itertools::Itertools;
    use mp2_common::{group_hashing::map_to_curve_point, types::{HashOutput, CURVE_TARGET_LEN}, utils::{Fieldable, ToFields}, C, D, F};
    use mp2_test::{cells_tree::{compute_cells_tree_hash, TestCell}, circuit::{run_circuit, UserCircuit}, utils::{gen_random_field_hash, gen_random_u256}};
    use plonky2::{field::types::{Field, PrimeField64, Sample}, iop::{target::Target, witness::{PartialWitness, WitnessWrite}}, plonk::{circuit_builder::CircuitBuilder, config::GenericHashOut}};
    use rand::{thread_rng, Rng};

    use crate::{ivc::{public_inputs::H_RANGE as ORIGINAL_TREE_H_RANGE, PublicInputs as OriginalTreePublicInputs}, query::{aggregation::{ChildPosition, NodeInfo}, public_inputs::{PublicInputs as QueryProofPublicInputs, QueryPublicInputs}}, revelation::{revelation_unproven_offset::RowPath, tests::TestPlaceholders, NUM_PREPROCESSING_IO, NUM_QUERY_IO}, test_utils::{random_aggregation_operations, random_aggregation_public_inputs}};

    use super::{RevelationCircuit, RevelationWires};

    #[derive(Clone, Debug)]
    struct TestRevelationCircuit<'a,
        const ROW_TREE_MAX_DEPTH: usize,
        const INDEX_TREE_MAX_DEPTH: usize,
        const L: usize,
        const S: usize,
        const PH: usize,
        const PP: usize,
    > 
    where 
        [(); ROW_TREE_MAX_DEPTH -1]:,
        [(); INDEX_TREE_MAX_DEPTH -1]:,
        [(); S*L]:,
    {
        circuit: RevelationCircuit<ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, L, S, PH, PP>,
        row_pis: &'a[Vec<F>; L],
        original_tree_pis: &'a[F],
    }

    impl<'a,
        const ROW_TREE_MAX_DEPTH: usize,
        const INDEX_TREE_MAX_DEPTH: usize,
        const L: usize,
        const S: usize,
        const PH: usize,
        const PP: usize,
    > UserCircuit<F, D> for TestRevelationCircuit<'a, ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, L, S, PH, PP> 
    where 
        [(); ROW_TREE_MAX_DEPTH -1]:,
        [(); INDEX_TREE_MAX_DEPTH -1]:,
        [(); S*L]:,
    {
        type Wires = (
            RevelationWires<ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, L, S, PH, PP>,
            [Vec<Target>; L],
            Vec<Target>,
        );
    
        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let row_pis_raw: [Vec<Target>; L] = (0..L).map(|_| 
                c.add_virtual_targets(NUM_QUERY_IO::<S>)
            ).collect_vec().try_into().unwrap();
            let original_pis_raw = c.add_virtual_targets(NUM_PREPROCESSING_IO);
            let row_pis = row_pis_raw.iter().map(|pis| 
                QueryProofPublicInputs::from_slice(&pis)
            ).collect_vec().try_into().unwrap();
            let original_pis = OriginalTreePublicInputs::from_slice(&original_pis_raw);
            let revelation_wires = RevelationCircuit::build(
                c, 
                &row_pis, 
                &original_pis
            );
            (
                revelation_wires,
                row_pis_raw,
                original_pis_raw,
            )
        }
    
        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.circuit.assign(pw, &wires.0);
            self.row_pis.iter().zip(&wires.1).for_each(|(pis, pis_target)|
                pw.set_target_arr(pis_target, pis)
            );
            pw.set_target_arr(&wires.2, self.original_tree_pis);
        }
    }

    #[tokio::test]
    async fn test_revelation_unproven_offset_circuit() {
        const ROW_TREE_MAX_DEPTH: usize = 10;
        const INDEX_TREE_MAX_DEPTH: usize = 10;
        const L: usize = 5;
        const S: usize = 7;
        const PH: usize = 10;
        const PP: usize = 30;
        let ops = random_aggregation_operations::<S>(); 
        let mut row_pis = random_aggregation_public_inputs(&ops);
        let mut rng = &mut thread_rng();
        let mut original_tree_pis = (0..NUM_PREPROCESSING_IO)
            .map(|_| rng.gen())
            .collect::<Vec<u32>>()
            .to_fields();
        const NUM_PLACEHOLDERS: usize = 5;
        let test_placeholders = TestPlaceholders::sample(NUM_PLACEHOLDERS);
        let (index_ids, computational_hash) = {
            let row_pi_0 = QueryProofPublicInputs::<_, S>::from_slice(&row_pis[0]);
            let index_ids = row_pi_0.index_ids();
            let computational_hash = row_pi_0.computational_hash();

            (index_ids, computational_hash)
        };
        let placeholder_hash = test_placeholders.query_placeholder_hash;
        // set same index_ids, computational hash and placeholder hash for all proofs; set also num matching rows to 1
        // for all proofs
        row_pis.iter_mut().for_each(|pis| {
            let [
                index_id_range,
                ch_range,
                ph_range,
                count_range,
             ] = [
                QueryPublicInputs::IndexIds,
                QueryPublicInputs::ComputationalHash,
                QueryPublicInputs::PlaceholderHash,
                QueryPublicInputs::NumMatching,
            ].map(QueryProofPublicInputs::<F, S>::to_range);
            pis[index_id_range].copy_from_slice(&index_ids);
            pis[ch_range].copy_from_slice(&computational_hash.to_fields());
            pis[ph_range].copy_from_slice(&placeholder_hash.to_fields());
            pis[count_range].copy_from_slice(&[F::ONE]);
        });
        let index_value_range = QueryProofPublicInputs::<F,S>::to_range(QueryPublicInputs::IndexValue);
        let hash_range = QueryProofPublicInputs::<F,S>::to_range(QueryPublicInputs::TreeHash);
        let min_query = test_placeholders.min_query;
        let max_query = test_placeholders.max_query;
        // closure that modifies a set of row public inputs to ensure that the index value lies
        // within the query bounds; the new index value set in the public inputs is returned by the closure
        let enforce_index_value_in_query_range = |pis: &mut[F], index_value: U256| {
            let query_range_size = max_query - min_query + U256::from(1);
            let new_index_value = min_query + index_value % query_range_size;
            pis[index_value_range.clone()].copy_from_slice(&new_index_value.to_fields());
            assert!(new_index_value >= min_query && new_index_value <= max_query);
            new_index_value
        };
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
            let node_value = row_pi.min_value();
            NodeInfo::new(
                &embedded_tree_hash,
                None,
                None,
                node_value,
                node_value,
                node_value
            )
        };
        // set hash in row 1 proof to node 1 hash, given that node 1 is a leaf node
        let node_1_hash = node_1.compute_node_hash(index_ids[1]);
        row_pis[1][hash_range.clone()].copy_from_slice(&node_1_hash.to_fields()); 
        let node_0 = {
            let row_pi = QueryProofPublicInputs::<_, S>::from_slice(&row_pis[0]);
            let embedded_tree_hash = 
                HashOutput::try_from(row_pi.tree_hash().to_bytes()).unwrap();
            let node_value = row_pi.min_value();
            // left child is node 1
            let left_child_hash = HashOutput::try_from(
                node_1_hash.to_bytes()
            ).unwrap();
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
            let embedded_tree_hash =
                    HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap();
            let node_value = row_pi.min_value();
            NodeInfo::new(
                &embedded_tree_hash, 
                None, 
                None, 
                node_value, 
                node_value, 
                node_value
            )
        };
        // set hash in row 2 proof to node 2 hash, given that node 2 is a leaf node
        let node_2_hash = node_2.compute_node_hash(index_ids[1]);
        row_pis[2][hash_range.clone()].copy_from_slice(&node_2_hash.to_fields()); 
        let node_4 = {
            let row_pi = QueryProofPublicInputs::<_, S>::from_slice(&row_pis[4]);
            let embedded_tree_hash =
                    HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap();
            let node_value = row_pi.min_value();
            NodeInfo::new(
                &embedded_tree_hash, 
                None, 
                None, 
                node_value, 
                node_value, 
                node_value
            )
        };
        // set hash in row 4 proof to node 4 hash, given that node 4 is a leaf node
        let node_4_hash = node_4.compute_node_hash(index_ids[1]);
        row_pis[4][hash_range.clone()].copy_from_slice(&node_4_hash.to_fields()); 
        let node_5 = {
            // can use all dummy values for this node, since there is no proof associated to it
            let embedded_tree_hash =
                    HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap();
            let [node_value, node_min, node_max] = array::from_fn(|_| gen_random_u256(rng));
            NodeInfo::new(
                &embedded_tree_hash,
                None,
                None,
                node_value,
                node_min,
                node_max
            )
        };
        let node_3 = {
            let row_pi = QueryProofPublicInputs::<_, S>::from_slice(&row_pis[3]);
            let embedded_tree_hash = 
                HashOutput::try_from(row_pi.tree_hash().to_bytes()).unwrap();
            let node_value = row_pi.min_value();
            // left child is node 4
            let left_child_hash = HashOutput::try_from(
                node_4_hash.to_bytes()
            ).unwrap();
            // right child is node 5
            let right_child_hash = HashOutput::try_from(
                node_5.compute_node_hash(index_ids[1]).to_bytes()
            ).unwrap();
            NodeInfo::new(
                &embedded_tree_hash, 
                Some(&left_child_hash), 
                Some(&right_child_hash), 
                node_value, 
                node_4.min, 
                node_5.max,
            )
        };
        let node_B = {
            let row_pi = QueryProofPublicInputs::<_, S>::from_slice(&row_pis[2]);
            let embedded_tree_hash = HashOutput::try_from(
                node_2.compute_node_hash(index_ids[1]).to_bytes()
            ).unwrap();
            let index_value = row_pi.index_value();
            let node_value = enforce_index_value_in_query_range(&mut row_pis[2], index_value);
            NodeInfo::new(
                &embedded_tree_hash, 
                None, 
                None, 
                node_value, 
                node_value, 
                node_value
            )
        };
        let node_C = {
            let row_pi = QueryProofPublicInputs::<_, S>::from_slice(&row_pis[4]);
            let embedded_tree_hash = HashOutput::try_from(
                node_3.compute_node_hash(index_ids[1]).to_bytes()
            ).unwrap();
            let index_value = row_pi.index_value();
            let node_value = enforce_index_value_in_query_range(&mut row_pis[4], index_value);
            // we need also to set index value PI in row_pis[3] to the same value of row_pis[4], as they are in the same index tree
            row_pis[3][index_value_range.clone()].copy_from_slice(&node_value.to_fields());
            NodeInfo::new(
                &embedded_tree_hash, 
                None, 
                None, 
                node_value, 
                node_value, 
                node_value
            )
        };
        let node_A = {
            let row_pi = QueryProofPublicInputs::<_, S>::from_slice(&row_pis[0]);
            let embedded_tree_hash = HashOutput::try_from(
                node_0.compute_node_hash(index_ids[1]).to_bytes()
            ).unwrap();
            let index_value = row_pi.index_value();
            let node_value = enforce_index_value_in_query_range(&mut row_pis[0], index_value);
            // we need also to set index value PI in row_pis[1] to the same value of row_pis[0], as they are in the same index tree
            row_pis[1][index_value_range].copy_from_slice(&node_value.to_fields());
            // left child is node B
            let left_child_hash = HashOutput::try_from(
                node_B.compute_node_hash(index_ids[0]).to_bytes()
            ).unwrap();
            // right child is node C
            let right_child_hash = HashOutput::try_from(
                node_C.compute_node_hash(index_ids[0]).to_bytes()
            ).unwrap();
            NodeInfo::new(
                &embedded_tree_hash, 
                Some(&left_child_hash), 
                Some(&right_child_hash), 
                node_value, 
                node_B.min, 
                node_C.max
            )
        };
        // set original tree PI to the root of the tree
        let root = node_A.compute_node_hash(index_ids[0]);
        original_tree_pis[ORIGINAL_TREE_H_RANGE].copy_from_slice(&root.to_fields());

        // sample final results and set order-agnostic digests in row_pis proofs accordingly
        const NUM_ACTUAL_ITEMS_PER_OUTPUT: usize = 4;
        let results: [[U256; NUM_ACTUAL_ITEMS_PER_OUTPUT]; L] = array::from_fn(|_|
            array::from_fn(|_| gen_random_u256(rng))
        );
        // random ids of output items
        let ids: [u64; NUM_ACTUAL_ITEMS_PER_OUTPUT] = F::rand_array().map(|id| id.to_canonical_u64()); 

        
        let digests = stream::iter(results.iter()).then(|res| async {
            // build set of cells for the cells tree
            let cells = res.iter().zip(ids.iter()).map(|(value, id)|
                TestCell::new(*value, id.to_field())
            ).collect_vec();
            map_to_curve_point(
                &once(cells[0].id)
                    .chain(cells[0].value.to_fields())
                    .chain(once(
                        cells.get(1).map(|cell| cell.id).unwrap_or_default(),
                    ))
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
        }).collect::<Vec<_>>().await;

        row_pis.iter_mut().zip(digests).for_each(|(pis, digest)| {
            let values_range = QueryProofPublicInputs::<F,S>::to_range(QueryPublicInputs::OutputValues);
            pis[values_range.start..values_range.start+CURVE_TARGET_LEN].copy_from_slice(&digest.to_fields())
        });

        // prepare RowPath inputs for each row
        let row_path_1 = RowPath { 
            row_node_info: node_1, 
            row_tree_path: vec![(node_0.clone(), ChildPosition::Left)], 
            row_path_siblings: vec![None], 
            index_node_info: node_A.clone(), 
            index_tree_path: vec![], 
            index_path_siblings: vec![] 
        };
        let row_path_0 = RowPath { 
            row_node_info: node_0, 
            row_tree_path: vec![], 
            row_path_siblings: vec![], 
            index_node_info: node_A.clone(), 
            index_tree_path: vec![], 
            index_path_siblings: vec![] 
        };
        let row_path_2 = RowPath { 
            row_node_info: node_2, 
            row_tree_path: vec![], 
            row_path_siblings: vec![], 
            index_node_info: node_B.clone(), 
            index_tree_path: vec![(node_A.clone(), ChildPosition::Left)], 
            index_path_siblings: vec![Some(node_C.clone())] 
        };
        let row_path_4 = RowPath {
            row_node_info: node_4,
            row_tree_path: vec![(node_3.clone(), ChildPosition::Left)],
            row_path_siblings: vec![Some(node_5)],
            index_node_info: node_C.clone(),
            index_tree_path: vec![(node_A.clone(), ChildPosition::Right)], 
            index_path_siblings: vec![Some(node_B.clone())] 
        };
        let row_path_3 = RowPath {
            row_node_info: node_3,
            row_tree_path: vec![],
            row_path_siblings: vec![],
            index_node_info: node_C.clone(),
            index_tree_path: vec![(node_A.clone(), ChildPosition::Right)], 
            index_path_siblings: vec![Some(node_B.clone())] 
        };

        let circuit = TestRevelationCircuit::<ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, L, S, PH, PP> {
            circuit: RevelationCircuit::new(
                [row_path_0, row_path_1, row_path_2, row_path_3, row_path_4],
                L,
                NUM_ACTUAL_ITEMS_PER_OUTPUT,
                index_ids.into_iter().map(|id| id.to_canonical_u64()).collect_vec().try_into().unwrap(),
                &ids,
                results.map(|res| res.to_vec()),
                0,
                0,
                test_placeholders.check_placeholder_inputs,
            ).unwrap(),
            row_pis: &row_pis,
            original_tree_pis: &original_tree_pis,
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
    }
}




