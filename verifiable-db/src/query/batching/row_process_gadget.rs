use std::array;
use anyhow::Result;

use mp2_common::{types::CBuilder, u256::UInt256Target, F};
use plonky2::iop::{target::Target, witness::PartialWitness};
use serde::{Deserialize, Serialize};

use crate::query::{merkle_path::{MerklePathWithNeighborsGadget, MerklePathWithNeighborsTargetInputs}, 
    universal_circuit::{universal_circuit_inputs::RowCells, universal_query_gadget::{OutputComponent, UniversalQueryHashInputWires, UniversalQueryValueInputWires, UniversalQueryValueInputs, UniversalQueryValueWires}}};

use super::row_chunk::BoundaryRowNodeInfoTarget;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RowProcessingGadgetInputWires<
    const ROW_TREE_MAX_DEPTH: usize,
    const INDEX_TREE_MAX_DEPTH: usize,
    const MAX_NUM_COLUMNS: usize,
> 
where 
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
{
    row_path: MerklePathWithNeighborsTargetInputs<ROW_TREE_MAX_DEPTH>,
    index_path: MerklePathWithNeighborsTargetInputs<INDEX_TREE_MAX_DEPTH>,
    input_values: UniversalQueryValueInputWires<MAX_NUM_COLUMNS>,
}
#[derive(Clone, Debug)]
pub(crate) struct RowProcessingGadgetWires<
    const ROW_TREE_MAX_DEPTH: usize,
    const INDEX_TREE_MAX_DEPTH: usize,
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_RESULTS: usize,
> 
where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
{
    row_path: MerklePathWithNeighborsTargetInputs<ROW_TREE_MAX_DEPTH>,
    row_node_data: BoundaryRowNodeInfoTarget,
    index_path: MerklePathWithNeighborsTargetInputs<INDEX_TREE_MAX_DEPTH>,
    index_node_data: BoundaryRowNodeInfoTarget,
    value_wires: UniversalQueryValueWires<MAX_NUM_COLUMNS, MAX_NUM_RESULTS>,
}

#[derive(Clone, Debug)]
pub(crate) struct RowProcessingGadgetInputs<
    const ROW_TREE_MAX_DEPTH: usize,
    const INDEX_TREE_MAX_DEPTH: usize,
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
> 
where 
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
{
    row_path: MerklePathWithNeighborsGadget<ROW_TREE_MAX_DEPTH>,
    index_path: MerklePathWithNeighborsGadget<INDEX_TREE_MAX_DEPTH>,
    input_values: UniversalQueryValueInputs<MAX_NUM_COLUMNS, MAX_NUM_PREDICATE_OPS, MAX_NUM_RESULT_OPS, MAX_NUM_RESULTS>,
}

impl<
    const ROW_TREE_MAX_DEPTH: usize,
    const INDEX_TREE_MAX_DEPTH: usize,
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,  
> RowProcessingGadgetInputs<
    ROW_TREE_MAX_DEPTH, 
    INDEX_TREE_MAX_DEPTH, 
    MAX_NUM_COLUMNS, 
    MAX_NUM_PREDICATE_OPS, 
    MAX_NUM_RESULT_OPS, 
    MAX_NUM_RESULTS
> 
where 
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
{
    pub(crate) fn new(
        row_path: MerklePathWithNeighborsGadget<ROW_TREE_MAX_DEPTH>,
        index_path: MerklePathWithNeighborsGadget<INDEX_TREE_MAX_DEPTH>,
        row_cells: &RowCells, 
        is_non_dummy_row: bool
    ) -> Result<Self> {
        Ok(Self {
            row_path,
            index_path,
            input_values: UniversalQueryValueInputs::new(row_cells, is_non_dummy_row)?
        })
    }

    pub(crate) fn build<T: OutputComponent<MAX_NUM_RESULTS>>(
        b: &mut CBuilder,
        hash_input_wires: &UniversalQueryHashInputWires<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            T,
        >,
        min_secondary: &UInt256Target,
        max_secondary: &UInt256Target,
        min_primary: &UInt256Target,
        max_primary: &UInt256Target,
        num_overflows: &Target,
    ) -> RowProcessingGadgetWires<ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, MAX_NUM_COLUMNS, MAX_NUM_RESULTS> {
        let mut value_wires = UniversalQueryValueInputs::build(
            b, 
            hash_input_wires, 
            min_secondary, 
            max_secondary, 
            Some(min_primary), 
            Some(max_primary), 
            num_overflows
        );
        let [primary_index_id, secondary_index_id] = array::from_fn(|i| 
            hash_input_wires.column_extraction_wires.column_ids[i]
        );
        let [primary_index_value, secondary_index_value] = array::from_fn(|i|
            value_wires.input_wires.column_values[i].clone()
        );
        let row_path = MerklePathWithNeighborsGadget::build(
            b, 
            secondary_index_value, 
            value_wires.output_wires.tree_hash, // hash of the cells tree stored 
                // in the row node must be the one computed by universal query gadget
            secondary_index_id
        );
        let index_path = MerklePathWithNeighborsGadget::build(
            b, 
            primary_index_value, 
            row_path.root, // computed root of row tree must be the same as the root of 
			    // the subtree stored in `index_node`
            primary_index_id
        );

        // the tree hash in output values for the current row must correspond to the index tree hash
        value_wires.output_wires.tree_hash = index_path.root;

        RowProcessingGadgetWires {
            row_path: row_path.inputs,
            row_node_data: BoundaryRowNodeInfoTarget {
                end_node_hash: row_path.end_node_hash,
                predecessor_info: row_path.predecessor_info,
                successor_info: row_path.successor_info,
            },
            index_path: index_path.inputs,
            index_node_data: BoundaryRowNodeInfoTarget {
                end_node_hash: index_path.end_node_hash,
                predecessor_info: index_path.predecessor_info,
                successor_info: index_path.successor_info,
            },
            value_wires,
        }
    }

    pub(crate) fn assign(
        &self, 
        pw: &mut PartialWitness<F>, 
        wires: &RowProcessingGadgetInputWires<ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, MAX_NUM_COLUMNS>
    ) {
        self.row_path.assign(pw, &wires.row_path);
        self.index_path.assign(pw, &wires.index_path);
        self.input_values.assign(pw, &wires.input_values);
    } 
}
