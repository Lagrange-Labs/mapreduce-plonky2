use anyhow::Result;
use std::array;

use mp2_common::{types::CBuilder, u256::UInt256Target, F};
use plonky2::iop::witness::PartialWitness;
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
    api::RowInput,
};

use super::{BoundaryRowDataTarget, BoundaryRowNodeInfoTarget, RowChunkDataTarget};

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
#[allow(dead_code)] // only in this PR
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
    >
    From<
        RowProcessingGadgetWires<
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_RESULTS,
        >,
    > for RowChunkDataTarget<MAX_NUM_RESULTS>
where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); MAX_NUM_RESULTS - 1]:,
{
    fn from(
        value: RowProcessingGadgetWires<
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_RESULTS,
        >,
    ) -> Self {
        RowChunkDataTarget {
            left_boundary_row: BoundaryRowDataTarget {
                row_node_info: value.row_node_data.clone(),
                index_node_info: value.index_node_data.clone(),
            },
            right_boundary_row: BoundaryRowDataTarget {
                row_node_info: value.row_node_data,
                index_node_info: value.index_node_data,
            },
            chunk_outputs: value.value_wires.output_wires,
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
            input_values: UniversalQueryValueInputs::new(row_cells, false)?,
        })
    }

    #[allow(dead_code)] // unused for now, but could be a useful method
    pub(crate) fn new_dummy_row(
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

    pub(crate) fn clone_to_dummy_row(&self) -> Self {
        let mut input_values = self.input_values.clone();
        input_values.is_dummy_row = true;
        Self {
            row_path: self.row_path,
            index_path: self.index_path,
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
        min_query_secondary: &UInt256Target,
        max_query_secondary: &UInt256Target,
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
            min_query_secondary,
            max_query_secondary,
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

    #[allow(dead_code)] // only in this PR
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

impl<
        const ROW_TREE_MAX_DEPTH: usize,
        const INDEX_TREE_MAX_DEPTH: usize,
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_PREDICATE_OPS: usize,
        const MAX_NUM_RESULT_OPS: usize,
        const MAX_NUM_RESULTS: usize,
    > TryFrom<&RowInput>
    for RowProcessingGadgetInputs<
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
    [(); MAX_NUM_RESULTS - 1]:,
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
{
    fn try_from(value: &RowInput) -> Result<Self> {
        let index_path = MerklePathWithNeighborsGadget::new(
            &value.path.index_tree_path.path,
            &value.path.index_tree_path.siblings,
            &value.path.index_tree_path.node_info,
            value.path.index_tree_path.children,
        )?;
        let row_path = MerklePathWithNeighborsGadget::new(
            &value.path.row_tree_path.path,
            &value.path.row_tree_path.siblings,
            &value.path.row_tree_path.node_info,
            value.path.row_tree_path.children,
        )?;

        Self::new(row_path, index_path, &value.cells)
    }

    type Error = anyhow::Error;
}
