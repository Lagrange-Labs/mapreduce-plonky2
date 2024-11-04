use anyhow::Result;
use std::array;

use mp2_common::{types::CBuilder, u256::UInt256Target, F};
use plonky2::iop::{target::Target, witness::PartialWitness};
use serde::{Deserialize, Serialize};

use crate::query::{
    merkle_path::{MerklePathWithNeighborsGadget, MerklePathWithNeighborsTargetInputs},
    universal_circuit::{
        universal_circuit_inputs::RowCells,
        universal_query_gadget::{
            OutputComponent, UniversalQueryHashInputWires, UniversalQueryValueInputWires,
            UniversalQueryValueInputs, UniversalQueryValueWires,
        },
    },
};

use super::row_chunk::{BoundaryRowDataTarget, BoundaryRowNodeInfoTarget, RowChunkDataTarget};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RowProcessingGadgetInputWires<
    const ROW_TREE_MAX_DEPTH: usize,
    const INDEX_TREE_MAX_DEPTH: usize,
    const MAX_NUM_COLUMNS: usize,
> where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
{
    pub(crate) row_path: MerklePathWithNeighborsTargetInputs<ROW_TREE_MAX_DEPTH>,
    pub(crate) index_path: MerklePathWithNeighborsTargetInputs<INDEX_TREE_MAX_DEPTH>,
    pub(crate) input_values: UniversalQueryValueInputWires<MAX_NUM_COLUMNS>,
}

impl<
        'a,
        const ROW_TREE_MAX_DEPTH: usize,
        const INDEX_TREE_MAX_DEPTH: usize,
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_RESULTS: usize,
    >
    From<
        &'a RowProcessingGadgetWires<
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_RESULTS,
        >,
    > for RowProcessingGadgetInputWires<ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, MAX_NUM_COLUMNS>
where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); MAX_NUM_RESULTS - 1]:,
{
    fn from(
        value: &'a RowProcessingGadgetWires<
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_RESULTS,
        >,
    ) -> Self {
        RowProcessingGadgetInputWires {
            row_path: value.row_path.clone(),
            index_path: value.index_path.clone(),
            input_values: value.value_wires.input_wires.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RowProcessingGadgetWires<
    const ROW_TREE_MAX_DEPTH: usize,
    const INDEX_TREE_MAX_DEPTH: usize,
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_RESULTS: usize,
> where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); MAX_NUM_RESULTS - 1]:,
{
    pub(crate) row_path: MerklePathWithNeighborsTargetInputs<ROW_TREE_MAX_DEPTH>,
    pub(crate) row_node_data: BoundaryRowNodeInfoTarget,
    pub(crate) index_path: MerklePathWithNeighborsTargetInputs<INDEX_TREE_MAX_DEPTH>,
    pub(crate) index_node_data: BoundaryRowNodeInfoTarget,
    pub(crate) value_wires: UniversalQueryValueWires<MAX_NUM_COLUMNS, MAX_NUM_RESULTS>,
}

impl<
        const ROW_TREE_MAX_DEPTH: usize,
        const INDEX_TREE_MAX_DEPTH: usize,
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_RESULTS: usize,
    > Into<RowChunkDataTarget<MAX_NUM_RESULTS>>
    for RowProcessingGadgetWires<
        ROW_TREE_MAX_DEPTH,
        INDEX_TREE_MAX_DEPTH,
        MAX_NUM_COLUMNS,
        MAX_NUM_RESULTS,
    >
where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); MAX_NUM_RESULTS - 1]:,
{
    fn into(self) -> RowChunkDataTarget<MAX_NUM_RESULTS> {
        RowChunkDataTarget {
            left_boundary_row: BoundaryRowDataTarget {
                row_node_info: self.row_node_data.clone(),
                index_node_info: self.index_node_data.clone(),
            },
            right_boundary_row: BoundaryRowDataTarget {
                row_node_info: self.row_node_data,
                index_node_info: self.index_node_data,
            },
            chunk_outputs: self.value_wires.output_wires,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RowProcessingGadgetInputs<
    const ROW_TREE_MAX_DEPTH: usize,
    const INDEX_TREE_MAX_DEPTH: usize,
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
> where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
{
    row_path: MerklePathWithNeighborsGadget<ROW_TREE_MAX_DEPTH>,
    index_path: MerklePathWithNeighborsGadget<INDEX_TREE_MAX_DEPTH>,
    input_values: UniversalQueryValueInputs<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
    >,
}

impl<
        const ROW_TREE_MAX_DEPTH: usize,
        const INDEX_TREE_MAX_DEPTH: usize,
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_PREDICATE_OPS: usize,
        const MAX_NUM_RESULT_OPS: usize,
        const MAX_NUM_RESULTS: usize,
    >
    RowProcessingGadgetInputs<
        ROW_TREE_MAX_DEPTH,
        INDEX_TREE_MAX_DEPTH,
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
    >
where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
    [(); MAX_NUM_RESULTS - 1]:,
{
    pub(crate) fn new(
        row_path: MerklePathWithNeighborsGadget<ROW_TREE_MAX_DEPTH>,
        index_path: MerklePathWithNeighborsGadget<INDEX_TREE_MAX_DEPTH>,
        row_cells: &RowCells,
    ) -> Result<Self> {
        Ok(Self {
            row_path,
            index_path,
            input_values: UniversalQueryValueInputs::new(row_cells, true)?,
        })
    }

    pub(crate) fn new_dummy_row(
        row_path: MerklePathWithNeighborsGadget<ROW_TREE_MAX_DEPTH>,
        index_path: MerklePathWithNeighborsGadget<INDEX_TREE_MAX_DEPTH>,
        row_cells: &RowCells,
    ) -> Result<Self> {
        Ok(Self {
            row_path,
            index_path,
            input_values: UniversalQueryValueInputs::new(row_cells, false)?,
        })
    }

    pub(crate) fn clone_to_dummy_row(&self) -> Self {
        let mut input_values = self.input_values.clone();
        input_values.is_non_dummy_row = false;
        Self {
            row_path: self.row_path.clone(),
            index_path: self.index_path.clone(),
            input_values,
        }
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
    ) -> RowProcessingGadgetWires<
        ROW_TREE_MAX_DEPTH,
        INDEX_TREE_MAX_DEPTH,
        MAX_NUM_COLUMNS,
        MAX_NUM_RESULTS,
    > {
        let zero = b.zero();
        let mut value_wires = UniversalQueryValueInputs::build(
            b,
            hash_input_wires,
            min_secondary,
            max_secondary,
            Some(min_primary),
            Some(max_primary),
            &zero,
        );
        let [primary_index_id, secondary_index_id] =
            array::from_fn(|i| hash_input_wires.column_extraction_wires.column_ids[i]);
        let [primary_index_value, secondary_index_value] =
            array::from_fn(|i| value_wires.input_wires.column_values[i].clone());
        let row_path = MerklePathWithNeighborsGadget::build(
            b,
            secondary_index_value,
            value_wires.output_wires.tree_hash, // hash of the cells tree stored
            // in the row node must be the one computed by universal query gadget
            secondary_index_id,
        );
        let index_path = MerklePathWithNeighborsGadget::build(
            b,
            primary_index_value,
            row_path.root, // computed root of row tree must be the same as the root of
            // the subtree stored in `index_node`
            primary_index_id,
        );

        // the tree hash in output values for the current row must correspond to the index tree hash
        value_wires.output_wires.tree_hash = index_path.root;

        let row_node_data = BoundaryRowNodeInfoTarget::from(&row_path);
        let index_node_data = BoundaryRowNodeInfoTarget::from(&index_path);
        RowProcessingGadgetWires {
            row_path: row_path.inputs,
            row_node_data,
            index_path: index_path.inputs,
            index_node_data,
            value_wires,
        }
    }

    pub(crate) fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &RowProcessingGadgetInputWires<
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
        >,
    ) {
        self.row_path.assign(pw, &wires.row_path);
        self.index_path.assign(pw, &wires.index_path);
        self.input_values.assign(pw, &wires.input_values);
    }
}
