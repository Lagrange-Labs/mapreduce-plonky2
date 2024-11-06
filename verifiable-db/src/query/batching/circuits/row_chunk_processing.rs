use std::iter::repeat;

use alloy::primitives::U256;
use itertools::Itertools;
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::{circuit_builder::CircuitBuilder, proof::ProofWithPublicInputsTarget},
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::query::{
    aggregation::QueryBounds,
    batching::{
        public_inputs::PublicInputs,
        row_chunk,
        row_process_gadget::{RowProcessingGadgetInputWires, RowProcessingGadgetInputs},
    },
    computational_hash_ids::ColumnIDs,
    universal_circuit::{
        universal_circuit_inputs::{BasicOperation, PlaceholderId, Placeholders, ResultStructure},
        universal_query_gadget::{
            OutputComponent, UniversalQueryHashInputWires, UniversalQueryHashInputs,
        },
    },
};

use mp2_common::{
    public_inputs::PublicInputCommon,
    serialization::{deserialize_long_array, serialize_long_array},
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::ToTargets,
    D, F,
};

use self::row_chunk::{
    aggregate_chunks::aggregate_chunks, BoundaryRowDataTarget, RowChunkDataTarget,
};

use anyhow::{ensure, Result};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RowChunkProcessingWires<
    const NUM_ROWS: usize,
    const ROW_TREE_MAX_DEPTH: usize,
    const INDEX_TREE_MAX_DEPTH: usize,
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
    T: OutputComponent<MAX_NUM_RESULTS>,
> where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
{
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    row_inputs:
        [RowProcessingGadgetInputWires<ROW_TREE_MAX_DEPTH, INDEX_TREE_MAX_DEPTH, MAX_NUM_COLUMNS>;
            NUM_ROWS],
    universal_query_inputs: UniversalQueryHashInputWires<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
        T,
    >,
    min_primary: UInt256Target,
    max_primary: UInt256Target,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RowChunkProcessingCircuit<
    const NUM_ROWS: usize,
    const ROW_TREE_MAX_DEPTH: usize,
    const INDEX_TREE_MAX_DEPTH: usize,
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
    T: OutputComponent<MAX_NUM_RESULTS>,
> where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
{
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    row_inputs: [RowProcessingGadgetInputs<
        ROW_TREE_MAX_DEPTH,
        INDEX_TREE_MAX_DEPTH,
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
    >; NUM_ROWS],
    universal_query_inputs: UniversalQueryHashInputs<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
        T,
    >,
    min_primary: U256,
    max_primary: U256,
}

impl<
        const NUM_ROWS: usize,
        const ROW_TREE_MAX_DEPTH: usize,
        const INDEX_TREE_MAX_DEPTH: usize,
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_PREDICATE_OPS: usize,
        const MAX_NUM_RESULT_OPS: usize,
        const MAX_NUM_RESULTS: usize,
        T: OutputComponent<MAX_NUM_RESULTS>,
    >
    RowChunkProcessingCircuit<
        NUM_ROWS,
        ROW_TREE_MAX_DEPTH,
        INDEX_TREE_MAX_DEPTH,
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
        T,
    >
where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); MAX_NUM_RESULTS - 1]:,
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
{
    pub(crate) fn new(
        row_inputs: Vec<
            RowProcessingGadgetInputs<
                ROW_TREE_MAX_DEPTH,
                INDEX_TREE_MAX_DEPTH,
                MAX_NUM_COLUMNS,
                MAX_NUM_PREDICATE_OPS,
                MAX_NUM_RESULT_OPS,
                MAX_NUM_RESULTS,
            >,
        >,
        column_ids: &ColumnIDs,
        predicate_operations: &[BasicOperation],
        placeholders: &Placeholders,
        query_bounds: &QueryBounds,
        results: &ResultStructure,
    ) -> Result<Self> {
        let universal_query_inputs = UniversalQueryHashInputs::new(
            column_ids,
            predicate_operations,
            placeholders,
            query_bounds,
            results,
        )?;

        ensure!(
            row_inputs.len() >= 1,
            "Row chunk circuit input should be at least 1 row"
        );
        // dummy row used to pad `row_inputs` to `num_rows` is just copied from the last
        // real row provided as input
        let dummy_row = row_inputs.last().unwrap().clone_to_dummy_row();
        Ok(Self {
            row_inputs: row_inputs
                .into_iter()
                .chain(repeat(dummy_row.clone()))
                .take(NUM_ROWS)
                .collect_vec()
                .try_into()
                .unwrap(),
            universal_query_inputs,
            min_primary: query_bounds.min_query_primary(),
            max_primary: query_bounds.max_query_primary(),
        })
    }

    pub(crate) fn build(
        b: &mut CircuitBuilder<F, D>,
    ) -> RowChunkProcessingWires<
        NUM_ROWS,
        ROW_TREE_MAX_DEPTH,
        INDEX_TREE_MAX_DEPTH,
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
        T,
    > {
        let query_input_wires = UniversalQueryHashInputs::build(b);
        let [min_primary, max_primary] = b.add_virtual_u256_arr_unsafe(); // unsafe should be ok since
                                                                          // we are exposing these values as public inputs
        let first_row_wires = RowProcessingGadgetInputs::build(
            b,
            &query_input_wires.input_wires,
            &query_input_wires.min_secondary,
            &query_input_wires.max_secondary,
            &min_primary,
            &max_primary,
        );
        // enforce first row is non-dummy
        b.assert_one(
            first_row_wires
                .value_wires
                .input_wires
                .is_non_dummy_row
                .target,
        );

        let mut row_inputs = vec![RowProcessingGadgetInputWires::from(&first_row_wires)];

        let row_chunk: RowChunkDataTarget<MAX_NUM_RESULTS> = first_row_wires.into();

        let row_chunk = (1..NUM_ROWS).fold(row_chunk, |chunk, _| {
            let row_wires = RowProcessingGadgetInputs::build(
                b,
                &query_input_wires.input_wires,
                &query_input_wires.min_secondary,
                &query_input_wires.max_secondary,
                &min_primary,
                &max_primary,
            );
            row_inputs.push(RowProcessingGadgetInputWires::from(&row_wires));
            let is_second_non_dummy = row_wires.value_wires.input_wires.is_non_dummy_row;
            let current_chunk: RowChunkDataTarget<MAX_NUM_RESULTS> = row_wires.into();
            aggregate_chunks(
                b,
                &chunk,
                &current_chunk,
                &min_primary,
                &max_primary,
                &query_input_wires.min_secondary,
                &query_input_wires.max_secondary,
                &query_input_wires.agg_ops_ids,
                &is_second_non_dummy,
            )
        });
        // compute overflow flag
        let overflow = {
            let num_overflows = b.add(
                query_input_wires.num_bound_overflows,
                row_chunk.chunk_outputs.num_overflows,
            );
            let zero = b.zero();
            b.is_not_equal(num_overflows, zero)
        };

        PublicInputs::<Target, MAX_NUM_RESULTS>::new(
            &row_chunk.chunk_outputs.tree_hash.to_targets(),
            &row_chunk.chunk_outputs.values.to_targets(),
            &[row_chunk.chunk_outputs.count],
            &query_input_wires.agg_ops_ids,
            &row_chunk.left_boundary_row.to_targets(),
            &row_chunk.right_boundary_row.to_targets(),
            &min_primary.to_targets(),
            &max_primary.to_targets(),
            &query_input_wires.min_secondary.to_targets(),
            &query_input_wires.max_secondary.to_targets(),
            &[overflow.target],
            &query_input_wires.computational_hash.to_targets(),
            &query_input_wires.placeholder_hash.to_targets(),
        )
        .register(b);

        RowChunkProcessingWires {
            row_inputs: row_inputs.try_into().unwrap(),
            universal_query_inputs: query_input_wires.input_wires,
            min_primary,
            max_primary,
        }
    }

    pub(crate) fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &RowChunkProcessingWires<
            NUM_ROWS,
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            T,
        >,
    ) {
        self.row_inputs
            .iter()
            .zip(&wires.row_inputs)
            .for_each(|(value, target)| value.assign(pw, target));
        self.universal_query_inputs
            .assign(pw, &wires.universal_query_inputs);
        [
            (self.min_primary, &wires.min_primary),
            (self.max_primary, &wires.max_primary),
        ]
        .into_iter()
        .for_each(|(value, target)| pw.set_u256_target(target, value));
    }

    /// This method returns the ids of the placeholders employed to compute the placeholder hash,
    /// in the same order, so that those ids can be provided as input to other circuits that need
    /// to recompute this hash
    pub(crate) fn ids_for_placeholder_hash(&self) -> Vec<PlaceholderId> {
        self.universal_query_inputs.ids_for_placeholder_hash()
    }
}

impl<
        const NUM_ROWS: usize,
        const ROW_TREE_MAX_DEPTH: usize,
        const INDEX_TREE_MAX_DEPTH: usize,
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_PREDICATE_OPS: usize,
        const MAX_NUM_RESULT_OPS: usize,
        const MAX_NUM_RESULTS: usize,
        T: OutputComponent<MAX_NUM_RESULTS> + Serialize + DeserializeOwned,
    > CircuitLogicWires<F, D, 0>
    for RowChunkProcessingWires<
        NUM_ROWS,
        ROW_TREE_MAX_DEPTH,
        INDEX_TREE_MAX_DEPTH,
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
        T,
    >
where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); MAX_NUM_RESULTS - 1]:,
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
{
    type CircuitBuilderParams = ();

    type Inputs = RowChunkProcessingCircuit<
        NUM_ROWS,
        ROW_TREE_MAX_DEPTH,
        INDEX_TREE_MAX_DEPTH,
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
        T,
    >;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<Target, MAX_NUM_RESULTS>::total_len();

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        RowChunkProcessingCircuit::build(builder)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        array,
        iter::{once, repeat},
    };

    use alloy::primitives::U256;
    use itertools::Itertools;
    use mp2_common::{
        array::ToField,
        check_panic, default_config,
        group_hashing::map_to_curve_point,
        types::HashOutput,
        utils::{FromFields, ToFields, TryIntoBool},
        C, D, F,
    };
    use mp2_test::{
        cells_tree::{compute_cells_tree_hash, TestCell},
        circuit::{run_circuit, UserCircuit},
        utils::{gen_random_u256, random_vector},
    };
    use plonky2::{
        field::types::{Field, PrimeField64, Sample},
        plonk::{circuit_builder::CircuitBuilder, config::GenericHashOut},
    };
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::thread_rng;

    use crate::query::{
        aggregation::{
            tests::aggregate_output_values, ChildPosition, NodeInfo, QueryBoundSource, QueryBounds,
        },
        batching::{
            circuits::row_chunk_processing::RowChunkProcessingCircuit,
            public_inputs::{tests::gen_values_in_range, PublicInputs},
            row_chunk::tests::{BoundaryRowData, BoundaryRowNodeInfo},
            row_process_gadget::RowProcessingGadgetInputs,
        },
        computational_hash_ids::{
            AggregationOperation, ColumnIDs, Identifiers, Operation, PlaceholderIdentifier,
        },
        merkle_path::{
            tests::{build_node, NeighborInfo},
            MerklePathWithNeighborsGadget,
        },
        universal_circuit::{
            output_no_aggregation::Circuit as NoAggOutputCircuit,
            output_with_aggregation::Circuit as AggOutputCircuit,
            universal_circuit_inputs::{
                BasicOperation, ColumnCell, InputOperand, OutputItem, PlaceholderId, Placeholders,
                ResultStructure, RowCells,
            },
            universal_query_circuit::placeholder_hash,
            universal_query_gadget::{CurveOrU256, OutputValues},
            ComputationalHash,
        },
    };

    use super::{OutputComponent, RowChunkProcessingWires};

    impl<
            const NUM_ROWS: usize,
            const ROW_TREE_MAX_DEPTH: usize,
            const INDEX_TREE_MAX_DEPTH: usize,
            const MAX_NUM_COLUMNS: usize,
            const MAX_NUM_PREDICATE_OPS: usize,
            const MAX_NUM_RESULT_OPS: usize,
            const MAX_NUM_RESULTS: usize,
            T: OutputComponent<MAX_NUM_RESULTS>,
        > UserCircuit<F, D>
        for RowChunkProcessingCircuit<
            NUM_ROWS,
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            T,
        >
    where
        [(); ROW_TREE_MAX_DEPTH - 1]:,
        [(); INDEX_TREE_MAX_DEPTH - 1]:,
        [(); MAX_NUM_RESULTS - 1]:,
        [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
    {
        type Wires = RowChunkProcessingWires<
            NUM_ROWS,
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            T,
        >;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            Self::build(c)
        }

        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<F>, wires: &Self::Wires) {
            self.assign(pw, wires)
        }
    }

    #[derive(Clone, Debug)]
    struct TestRowsTreeNode {
        node: NodeInfo,
        values: Vec<U256>,
    }

    #[derive(Clone, Debug)]
    struct TestIndexTreeNode {
        node: NodeInfo,
        rows_tree: Vec<TestRowsTreeNode>,
    }

    /// Build a test index tree structured as follows:
    ///         1
    ///     0       2
    /// where 1 and 2 stores values in the primary index query range
    /// Then, node 0 stores the following rows tree:
    ///         A
    ///     B
    ///         C
    /// With only B being in the secondary index query range
    /// Node 1 stores the following rows tree:
    ///         A
    ///     B       C
    ///                 D
    /// Where nodes A and C are in the secondary index query range
    /// Node 2 stores the following rows tree:
    ///         A
    ///     B    
    ///  C    D
    /// Where all nodes except for C are in secondary index query range
    async fn build_test_tree(bounds: &QueryBounds, column_ids: &[F]) -> [TestIndexTreeNode; 3] {
        // sample primary index values
        let rng = &mut thread_rng();
        let [value_0] = gen_values_in_range(rng, U256::ZERO, bounds.min_query_primary()); // value of node 0 must be out of range
        let [value_1, value_2] =
            gen_values_in_range(rng, bounds.min_query_primary(), bounds.max_query_primary());
        // sample secondary index values for rows tree of node 0
        let [value_0C, value_0A] =
            gen_values_in_range(rng, *bounds.max_query_secondary().value(), U256::MAX);
        let [value_0B] = gen_values_in_range(
            rng,
            *bounds.min_query_secondary().value(),
            *bounds.max_query_secondary().value(),
        );
        // sample secondary index values for rows tree of node 1
        let [value_1B] =
            gen_values_in_range(rng, U256::ZERO, *bounds.min_query_secondary().value());
        let [value_1D] = gen_values_in_range(rng, *bounds.max_query_secondary().value(), U256::MAX);
        let [value_1A, value_1C] = gen_values_in_range(
            rng,
            *bounds.min_query_secondary().value(),
            *bounds.max_query_secondary().value(),
        );
        // sample secondary index values for rows tree of node 2
        let [value_2C] =
            gen_values_in_range(rng, U256::ZERO, *bounds.min_query_secondary().value());
        let [value_2B, value_2D, value_2A] = gen_values_in_range(
            rng,
            *bounds.min_query_secondary().value(),
            *bounds.max_query_secondary().value(),
        );
        let primary_index = column_ids[0];
        let secondary_index = column_ids[1];
        let build_cells = async |primary_index_value: U256, secondary_index_value: U256| {
            let rng = &mut thread_rng();
            let (mut cell_values, cells): (Vec<_>, Vec<_>) = column_ids
                .iter()
                .skip(2)
                .map(|id| {
                    let column_value = gen_random_u256(rng);
                    (column_value, TestCell::new(column_value, *id))
                })
                .unzip();
            let mut values = vec![primary_index_value, secondary_index_value];
            values.append(&mut cell_values);
            let hash = compute_cells_tree_hash(cells).await;
            (values, hash)
        };
        // build row 0C
        let (values, cell_tree_hash) = build_cells(value_0, value_0C).await;
        let node_0C = TestRowsTreeNode {
            node: build_node(
                None,
                None,
                value_0C,
                HashOutput::try_from(cell_tree_hash).unwrap(),
                secondary_index,
            ),
            values,
        };
        // build row 0B
        let (values, cell_tree_hash) = build_cells(value_0, value_0B).await;
        let node_0B = TestRowsTreeNode {
            node: build_node(
                None,
                Some(&node_0C.node),
                value_0B,
                HashOutput::try_from(cell_tree_hash).unwrap(),
                secondary_index,
            ),
            values,
        };
        // build row 0A
        let (values, cell_tree_hash) = build_cells(value_0, value_0A).await;
        let node_0A = TestRowsTreeNode {
            node: build_node(
                Some(&node_0B.node),
                None,
                value_0A,
                HashOutput::try_from(cell_tree_hash).unwrap(),
                secondary_index,
            ),
            values,
        };
        // build node 0
        let node_0 = TestIndexTreeNode {
            node: build_node(
                None,
                None,
                value_0,
                HashOutput::try_from(node_0A.node.compute_node_hash(secondary_index)).unwrap(),
                primary_index,
            ),
            rows_tree: vec![node_0A, node_0B, node_0C],
        };
        // build row 2C
        let (values, cell_tree_hash) = build_cells(value_2, value_2C).await;
        let node_2C = TestRowsTreeNode {
            node: build_node(
                None,
                None,
                value_2C,
                HashOutput::try_from(cell_tree_hash).unwrap(),
                secondary_index,
            ),
            values,
        };
        // build row 2D
        let (values, cell_tree_hash) = build_cells(value_2, value_2D).await;
        let node_2D = TestRowsTreeNode {
            node: build_node(
                None,
                None,
                value_2D,
                HashOutput::try_from(cell_tree_hash).unwrap(),
                secondary_index,
            ),
            values,
        };
        // build row 2B
        let (values, cell_tree_hash) = build_cells(value_2, value_2B).await;
        let node_2B = TestRowsTreeNode {
            node: build_node(
                Some(&node_2C.node),
                Some(&node_2D.node),
                value_2B,
                HashOutput::try_from(cell_tree_hash).unwrap(),
                secondary_index,
            ),
            values,
        };
        // build row 2A
        let (values, cell_tree_hash) = build_cells(value_2, value_2A).await;
        let node_2A = TestRowsTreeNode {
            node: build_node(
                Some(&node_2B.node),
                None,
                value_2A,
                HashOutput::try_from(cell_tree_hash).unwrap(),
                secondary_index,
            ),
            values,
        };
        // build node 2
        let node_2 = TestIndexTreeNode {
            node: build_node(
                None,
                None,
                value_2,
                HashOutput::try_from(node_2A.node.compute_node_hash(secondary_index)).unwrap(),
                primary_index,
            ),
            rows_tree: vec![node_2A, node_2B, node_2C, node_2D],
        };
        // build row 1D
        let (values, cell_tree_hash) = build_cells(value_1, value_1D).await;
        let node_1D = TestRowsTreeNode {
            node: build_node(
                None,
                None,
                value_1D,
                HashOutput::try_from(cell_tree_hash).unwrap(),
                secondary_index,
            ),
            values,
        };
        // build row 1B
        let (values, cell_tree_hash) = build_cells(value_1, value_1B).await;
        let node_1B = TestRowsTreeNode {
            node: build_node(
                None,
                None,
                value_1B,
                HashOutput::try_from(cell_tree_hash).unwrap(),
                secondary_index,
            ),
            values,
        };
        // build row 1C
        let (values, cell_tree_hash) = build_cells(value_1, value_1C).await;
        let node_1C = TestRowsTreeNode {
            node: build_node(
                None,
                Some(&node_1D.node),
                value_1C,
                HashOutput::try_from(cell_tree_hash).unwrap(),
                secondary_index,
            ),
            values,
        };
        // build row 1A
        let (values, cell_tree_hash) = build_cells(value_1, value_1A).await;
        let node_1A = TestRowsTreeNode {
            node: build_node(
                Some(&node_1B.node),
                Some(&node_1C.node),
                value_1A,
                HashOutput::try_from(cell_tree_hash).unwrap(),
                secondary_index,
            ),
            values,
        };
        // build node 1
        let node_1 = TestIndexTreeNode {
            node: build_node(
                Some(&node_0.node),
                Some(&node_2.node),
                value_1,
                HashOutput::try_from(node_1A.node.compute_node_hash(secondary_index)).unwrap(),
                primary_index,
            ),
            rows_tree: vec![node_1A, node_1B, node_1C, node_1D],
        };

        [node_0, node_1, node_2]
    }

    const NUM_ROWS: usize = 5;
    const ROW_TREE_MAX_DEPTH: usize = 10;
    const INDEX_TREE_MAX_DEPTH: usize = 15;
    const MAX_NUM_COLUMNS: usize = 30;
    const MAX_NUM_PREDICATE_OPS: usize = 20;
    const MAX_NUM_RESULT_OPS: usize = 30;
    const MAX_NUM_RESULTS: usize = 10;

    // SELECT SUM(C1*C2-C2/C3)), AVG(C1*C2), MIN(C1/C4+3), MAX(C4-$1), AVG(C5) FROM T WHERE (C5 > 5 AND C1*C2 <= C3+C4 OR C3 == $2) AND C2 >= 75 AND C2 < $3 AND C1 >= 456 AND C1 <= 6789
    #[tokio::test]
    async fn test_query_with_aggregation() {
        const NUM_ACTUAL_COLUMNS: usize = 5;

        let rng = &mut thread_rng();
        let column_ids = random_vector::<u64>(NUM_ACTUAL_COLUMNS);
        let primary_index = F::from_canonical_u64(column_ids[0]);
        let secondary_index = F::from_canonical_u64(column_ids[1]);
        let column_ids = ColumnIDs::new(column_ids[0], column_ids[1], column_ids[2..].to_vec());
        let min_primary = U256::from(456);
        let max_primary = U256::from(6789);
        let min_secondary = U256::from(75);
        let max_secondary = U256::from(97686754);
        // define placeholders
        let first_placeholder_id = PlaceholderId::Generic(0);
        let second_placeholder_id = PlaceholderIdentifier::Generic(1);
        let mut placeholders = Placeholders::new_empty(min_primary, max_primary);
        [first_placeholder_id, second_placeholder_id]
            .iter()
            .for_each(|id| placeholders.insert(*id, gen_random_u256(rng)));
        // 3-rd placeholder is max query bound + 1, since the bound is C2 < $3, rather than C2 <= $3
        let third_placeholder_id = PlaceholderId::Generic(2);
        placeholders.insert(third_placeholder_id, max_secondary + U256::from(1));
        let bounds = QueryBounds::new(
            &placeholders,
            Some(QueryBoundSource::Constant(min_secondary)),
            Some(
                QueryBoundSource::Operation(BasicOperation {
                    first_operand: InputOperand::Placeholder(third_placeholder_id),
                    second_operand: Some(InputOperand::Constant(U256::from(1))),
                    op: Operation::SubOp,
                }), // the bound is computed as $3-1 since in the query we specified that C2 < $3,
                    // while the bound computed in the circuit is expected to represent the maximum value
                    // possible for C2 (i.e., C2 < $3 => C2 <= $3 - 1)
            ),
        )
        .unwrap();
        // build predicate operations
        let mut predicate_operations = vec![];
        // C5 > 5
        let c5_comparison = BasicOperation {
            first_operand: InputOperand::Column(4),
            second_operand: Some(InputOperand::Constant(U256::from(5))),
            op: Operation::GreaterThanOp,
        };
        predicate_operations.push(c5_comparison);
        // C1*C2
        let column_prod = BasicOperation {
            first_operand: InputOperand::Column(0),
            second_operand: Some(InputOperand::Column(1)),
            op: Operation::MulOp,
        };
        predicate_operations.push(column_prod);
        // C3+C4
        let column_add = BasicOperation {
            first_operand: InputOperand::Column(2),
            second_operand: Some(InputOperand::Column(3)),
            op: Operation::AddOp,
        };
        predicate_operations.push(column_add);
        // C1*C3 <= C4 + C5
        let expr_comparison = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&predicate_operations, &column_prod)
                    .unwrap(),
            ),
            second_operand: Some(InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&predicate_operations, &column_add)
                    .unwrap(),
            )),
            op: Operation::LessThanOrEqOp,
        };
        predicate_operations.push(expr_comparison);
        // C3 == $2
        let placeholder_eq = BasicOperation {
            first_operand: InputOperand::Column(2),
            second_operand: Some(InputOperand::Placeholder(second_placeholder_id)),
            op: Operation::EqOp,
        };
        predicate_operations.push(placeholder_eq);
        // c5_comparison AND expr_comparison
        let and_comparisons = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&predicate_operations, &c5_comparison)
                    .unwrap(),
            ),
            second_operand: Some(InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&predicate_operations, &expr_comparison)
                    .unwrap(),
            )),
            op: Operation::AndOp,
        };
        predicate_operations.push(and_comparisons);
        // final filtering predicate: and_comparisons OR placeholder_eq
        let predicate = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&predicate_operations, &and_comparisons)
                    .unwrap(),
            ),
            second_operand: Some(InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&predicate_operations, &placeholder_eq)
                    .unwrap(),
            )),
            op: Operation::OrOp,
        };
        predicate_operations.push(predicate);

        // result computations operations
        let mut result_operations = vec![];
        // C1*C2
        let column_prod = BasicOperation {
            first_operand: InputOperand::Column(0),
            second_operand: Some(InputOperand::Column(1)),
            op: Operation::MulOp,
        };
        result_operations.push(column_prod);
        // C2/C3
        let column_div = BasicOperation {
            first_operand: InputOperand::Column(1),
            second_operand: Some(InputOperand::Column(2)),
            op: Operation::DivOp,
        };
        result_operations.push(column_div);
        let sub = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&result_operations, &column_prod)
                    .unwrap(),
            ),
            second_operand: Some(InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&result_operations, &column_div).unwrap(),
            )),
            op: Operation::SubOp,
        };
        result_operations.push(sub);
        // C1/C4
        let column_div_for_min = BasicOperation {
            first_operand: InputOperand::Column(0),
            second_operand: Some(InputOperand::Column(3)),
            op: Operation::DivOp,
        };
        result_operations.push(column_div_for_min);
        // C1/C4 + 3
        let add_for_min = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&result_operations, &column_div_for_min)
                    .unwrap(),
            ),
            second_operand: Some(InputOperand::Constant(U256::from(3))),
            op: Operation::AddOp,
        };
        result_operations.push(add_for_min);
        // C4 - $1
        let column_placeholder = BasicOperation {
            first_operand: InputOperand::Column(3),
            second_operand: Some(InputOperand::Placeholder(first_placeholder_id)),
            op: Operation::SubOp,
        };
        result_operations.push(column_placeholder);

        // output items are all computed values in this query, expect for the last item
        // which is a column
        let output_items = vec![
            OutputItem::ComputedValue(
                BasicOperation::locate_previous_operation(&result_operations, &sub).unwrap(),
            ),
            OutputItem::ComputedValue(
                BasicOperation::locate_previous_operation(&result_operations, &column_prod)
                    .unwrap(),
            ),
            OutputItem::ComputedValue(
                BasicOperation::locate_previous_operation(&result_operations, &add_for_min)
                    .unwrap(),
            ),
            OutputItem::ComputedValue(
                BasicOperation::locate_previous_operation(&result_operations, &column_placeholder)
                    .unwrap(),
            ),
            OutputItem::Column(4),
        ];
        let output_ops: [F; 5] = [
            AggregationOperation::SumOp.to_field(),
            AggregationOperation::AvgOp.to_field(),
            AggregationOperation::MinOp.to_field(),
            AggregationOperation::MaxOp.to_field(),
            AggregationOperation::AvgOp.to_field(),
        ];

        let results = ResultStructure::new_for_query_with_aggregation(
            result_operations,
            output_items,
            output_ops
                .iter()
                .map(|op| op.to_canonical_u64())
                .collect_vec(),
        )
        .unwrap();

        let [node_0, node_1, node_2] = build_test_tree(&bounds, &column_ids.to_vec()).await;

        let to_row_cells = |values: &[U256]| {
            let column_cells = values
                .iter()
                .zip(column_ids.to_vec().iter())
                .map(|(&value, &id)| ColumnCell { value, id })
                .collect_vec();
            RowCells::new(
                column_cells[0].clone(),
                column_cells[1].clone(),
                column_cells[2..].to_vec(),
            )
        };

        // run circuit over 3 consecutive rows: row 1C, row 2B and row 2D
        let [node_1A, node_1B, node_1C, node_1D] = node_1
            .rows_tree
            .iter()
            .map(|n| n.node.clone())
            .collect_vec()
            .try_into()
            .unwrap();
        let path_1C = vec![(node_1A.clone(), ChildPosition::Right)];
        let node_1B_hash =
            HashOutput::try_from(node_1B.compute_node_hash(secondary_index)).unwrap();
        let siblings_1C = vec![Some(node_1B_hash.clone())];
        let merkle_path_1C = MerklePathWithNeighborsGadget::new(
            &path_1C,
            &siblings_1C,
            &node_1C,
            [None, Some(node_1D.clone())],
        )
        .unwrap();
        let path_1 = vec![];
        let siblings_1 = vec![];
        let merkle_path_index_1 = MerklePathWithNeighborsGadget::new(
            &path_1,
            &siblings_1,
            &node_1.node,
            [Some(node_0.node.clone()), Some(node_2.node.clone())],
        )
        .unwrap();
        let row_cells_1C = to_row_cells(&node_1.rows_tree[2].values);
        let row_1C =
            RowProcessingGadgetInputs::new(merkle_path_1C, merkle_path_index_1, &row_cells_1C)
                .unwrap();

        let [node_2A, node_2B, node_2C, node_2D] = node_2
            .rows_tree
            .iter()
            .map(|n| n.node.clone())
            .collect_vec()
            .try_into()
            .unwrap();
        let path_2D = vec![
            (node_2B.clone(), ChildPosition::Right),
            (node_2A.clone(), ChildPosition::Left),
        ];
        let node_2C_hash =
            HashOutput::try_from(node_2C.compute_node_hash(secondary_index)).unwrap();
        let siblings_2D = vec![Some(node_2C_hash), None];
        let merkle_path_2D =
            MerklePathWithNeighborsGadget::new(&path_2D, &siblings_2D, &node_2D, [None, None])
                .unwrap();
        let path_2 = vec![(node_1.node.clone(), ChildPosition::Right)];
        let node_0_hash =
            HashOutput::try_from(node_0.node.compute_node_hash(primary_index)).unwrap();
        let siblings_2 = vec![Some(node_0_hash)];
        let merkle_path_index_2 =
            MerklePathWithNeighborsGadget::new(&path_2, &siblings_2, &node_2.node, [None, None])
                .unwrap();

        let row_cells_2D = to_row_cells(&node_2.rows_tree[3].values);

        let row_2D =
            RowProcessingGadgetInputs::new(merkle_path_2D, merkle_path_index_2, &row_cells_2D)
                .unwrap();

        let path_2B = vec![(node_2A.clone(), ChildPosition::Left)];
        let siblings_2B = vec![None];
        let merkle_path_2B = MerklePathWithNeighborsGadget::new(
            &path_2B,
            &siblings_2B,
            &node_2B,
            [Some(node_2C.clone()), Some(node_2D.clone())],
        )
        .unwrap();

        let row_cells_2B = to_row_cells(&node_2.rows_tree[1].values);

        let row_2B =
            RowProcessingGadgetInputs::new(merkle_path_2B, merkle_path_index_2, &row_cells_2B)
                .unwrap();

        let circuit = RowChunkProcessingCircuit::<
            NUM_ROWS,
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            AggOutputCircuit<MAX_NUM_RESULTS>,
        >::new(
            vec![row_1C.clone(), row_2B.clone(), row_2D.clone()],
            &column_ids,
            &predicate_operations,
            &placeholders,
            &bounds,
            &results,
        )
        .unwrap();

        // compute placeholder hash for `circuit`
        let placeholder_hash_ids = circuit.ids_for_placeholder_hash();
        let placeholder_hash =
            placeholder_hash(&placeholder_hash_ids, &placeholders, &bounds).unwrap();

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check public inputs
        let pis = PublicInputs::<F, MAX_NUM_RESULTS>::from_slice(&proof.public_inputs);

        let root = node_1.node.compute_node_hash(primary_index);
        assert_eq!(root, pis.tree_hash(),);
        assert_eq!(&pis.operation_ids()[..output_ops.len()], &output_ops,);

        // closure to compute predicate value and output values for a given row with cells `row_cells`.
        // Return also a flag sepcifying whether arithmetic errors have occurred during the computation or not
        let compute_output_values = |row_cells: &RowCells| {
            let column_values = row_cells
                .to_cells()
                .into_iter()
                .map(|cell| cell.value)
                .collect_vec();
            let (res, predicate_err) = BasicOperation::compute_operations(
                &predicate_operations,
                &column_values,
                &placeholders,
            )
            .unwrap();
            let predicate_value = res.last().unwrap().try_into_bool().unwrap();

            let (res, result_err) = results
                .compute_output_values(&column_values, &placeholders)
                .unwrap();

            let output_values = res
                .iter()
                .zip(output_ops.iter())
                .map(|(value, agg_op)| {
                    // if predicate_value is satisfied, then the actual output value
                    // is exposed as public input
                    if predicate_value {
                        *value
                    } else {
                        // otherwise, we just expose identity values for the given aggregation
                        // operation to ensure that the current record doesn't affect the
                        // aggregated result
                        U256::from_fields(
                            AggregationOperation::from_fields(&[*agg_op])
                                .identity_value()
                                .as_slice(),
                        )
                    }
                })
                .collect_vec();
            (
                predicate_value,
                predicate_err | result_err,
                OutputValues::<MAX_NUM_RESULTS>::new_aggregation_outputs(&output_values),
            )
        };

        // compute predicate value and output values for each of the 3 rows
        let (predicate_value_1C, err_1C, out_values_1C) = compute_output_values(&row_cells_1C);
        let (predicate_value_2B, err_2B, out_values_2B) = compute_output_values(&row_cells_2B);
        let (predicate_value_2D, err_2D, out_values_2D) = compute_output_values(&row_cells_2D);

        // aggregate out_values of the 3 rows
        let (expected_outputs, expected_err) = {
            let outputs = [out_values_1C, out_values_2B, out_values_2D];
            let mut num_overflows = 0;
            let outputs = output_ops
                .into_iter()
                .enumerate()
                .map(|(i, op)| {
                    let (out, overflows) = aggregate_output_values(i, &outputs, op);
                    num_overflows += overflows;
                    U256::from_fields(CurveOrU256::<F>::from_slice(&out).to_u256_raw())
                })
                .collect_vec();
            (outputs, num_overflows != 0)
        };

        let computational_hash = ComputationalHash::from_bytes(
            (&Identifiers::computational_hash_universal_circuit(
                &column_ids,
                &predicate_operations,
                &results,
                Some(bounds.min_query_secondary().into()),
                Some(bounds.max_query_secondary().into()),
            )
            .unwrap())
                .into(),
        );

        // compute expected left boundary row of the proven chunk: should correspond to row_1C
        let left_boundary_row = {
            // predecessor is node_1A, and it's in the path
            let predecessor_info_1C = NeighborInfo::new(
                node_1A.value,
                Some(node_1A.compute_node_hash(secondary_index)),
            );
            // successor is node_1D, and it's not in the path
            let successor_info_1C = NeighborInfo::new(node_1D.value, None);
            let row_1C_info = BoundaryRowNodeInfo {
                end_node_hash: node_1C.compute_node_hash(secondary_index),
                predecessor_info: predecessor_info_1C,
                successor_info: successor_info_1C,
            };
            // predecessor is node_0, and it's not in the path
            let predecessor_index_1 = NeighborInfo::new(node_0.node.value, None);
            // successor is node_2, and it's not in the path
            let successor_index_1 = NeighborInfo::new(node_2.node.value, None);
            let index_1_info = BoundaryRowNodeInfo {
                end_node_hash: node_1.node.compute_node_hash(primary_index),
                predecessor_info: predecessor_index_1,
                successor_info: successor_index_1,
            };
            BoundaryRowData {
                row_node_info: row_1C_info,
                index_node_info: index_1_info,
            }
        };
        // compute expected right boundary row of the proven chunk: should correspond to row_2D
        let right_boundary_row = {
            // predecessor is node_2B, and it's in the path
            let predecessor_2D = NeighborInfo::new(
                node_2B.value,
                Some(node_2B.compute_node_hash(secondary_index)),
            );
            // successor is node_2A, and it's in the path
            let successor_2D = NeighborInfo::new(
                node_2A.value,
                Some(node_2A.compute_node_hash(secondary_index)),
            );
            let row_2D_info = BoundaryRowNodeInfo {
                end_node_hash: node_2D.compute_node_hash(secondary_index),
                predecessor_info: predecessor_2D,
                successor_info: successor_2D,
            };

            // predecessor is node 1, and it's in the path
            let predecessor_index_2 = NeighborInfo::new(
                node_1.node.value,
                Some(node_1.node.compute_node_hash(primary_index)),
            );
            // no successor
            let successor_index_2 = NeighborInfo::new_dummy_successor();
            let index_2_info = BoundaryRowNodeInfo {
                end_node_hash: node_2.node.compute_node_hash(primary_index),
                predecessor_info: predecessor_index_2,
                successor_info: successor_index_2,
            };

            BoundaryRowData {
                row_node_info: row_2D_info,
                index_node_info: index_2_info,
            }
        };

        assert_eq!(pis.overflow_flag(), err_1C | err_2B | err_2D | expected_err);
        assert_eq!(
            pis.num_matching_rows(),
            F::from_canonical_u8(
                predicate_value_1C as u8 + predicate_value_2B as u8 + predicate_value_2D as u8
            ),
        );
        assert_eq!(pis.first_value_as_u256(), expected_outputs[0],);
        assert_eq!(
            expected_outputs[1..],
            pis.values()[..expected_outputs.len() - 1],
        );
        // check boundary rows
        assert_eq!(pis.to_left_row_raw(), &left_boundary_row.to_fields(),);
        assert_eq!(pis.to_right_row_raw(), &right_boundary_row.to_fields(),);

        assert_eq!(pis.min_primary(), min_primary,);
        assert_eq!(pis.max_primary(), max_primary,);
        assert_eq!(pis.min_secondary(), min_secondary,);
        assert_eq!(pis.max_secondary(), max_secondary,);
        assert_eq!(pis.computational_hash(), computational_hash,);
        assert_eq!(pis.placeholder_hash(), placeholder_hash,);

        // negative test: check that we cannot add an out of range row to the proven rows.
        // We try to add row 2C to the proven rows
        let path_2C = vec![
            (node_2B.clone(), ChildPosition::Left),
            (node_2A.clone(), ChildPosition::Left),
        ];
        let node_2D_hash =
            HashOutput::try_from(node_2D.compute_node_hash(secondary_index)).unwrap();
        let siblings_2C = vec![Some(node_2D_hash), None];
        let merkle_path_2C =
            MerklePathWithNeighborsGadget::new(&path_2C, &siblings_2C, &node_2C, [None, None])
                .unwrap();

        let row_cells_2C = to_row_cells(&node_2.rows_tree[2].values);

        let row_2C =
            RowProcessingGadgetInputs::new(merkle_path_2C, merkle_path_index_2, &row_cells_2C)
                .unwrap();

        let circuit = RowChunkProcessingCircuit::<
            NUM_ROWS,
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            AggOutputCircuit<MAX_NUM_RESULTS>,
        >::new(
            vec![row_1C, row_2C, row_2B, row_2D],
            &column_ids,
            &predicate_operations,
            &placeholders,
            &bounds,
            &results,
        )
        .unwrap();

        check_panic!(
            || run_circuit::<F, D, C, _>(circuit),
            "circuit didn't fail when aggregating row with secondary index out of range"
        )
    }

    #[tokio::test]
    // SELECT C1*C2 > 45, (C3+C7)/C4, C7, (C5-C6)%C1, C1/C5 - $1 FROM T WHERE ((NOT C3 != 42) OR C1*C2 <= C4/C6-C7 XOR C5 < $2) AND C2 >= $3 AND C2 < 44 AND C1 >= 523 AND C1 <= 657
    async fn test_query_without_aggregation() {
        const NUM_ACTUAL_COLUMNS: usize = 7;

        let rng = &mut thread_rng();
        let column_ids = random_vector::<u64>(NUM_ACTUAL_COLUMNS);
        let primary_index = F::from_canonical_u64(column_ids[0]);
        let secondary_index = F::from_canonical_u64(column_ids[1]);
        let column_ids = ColumnIDs::new(column_ids[0], column_ids[1], column_ids[2..].to_vec());
        let min_primary = U256::from(523);
        let max_primary = U256::from(657);
        let min_secondary = U256::from(42);
        let max_secondary = U256::from(43);
        // define placeholders
        let first_placeholder_id = PlaceholderId::Generic(0);
        let second_placeholder_id = PlaceholderIdentifier::Generic(1);
        let mut placeholders = Placeholders::new_empty(min_primary, max_primary);
        [first_placeholder_id, second_placeholder_id]
            .iter()
            .for_each(|id| placeholders.insert(*id, gen_random_u256(rng)));
        // 3-rd placeholder is the min query bound
        let third_placeholder_id = PlaceholderId::Generic(2);
        placeholders.insert(third_placeholder_id, min_secondary);
        let query_bounds = QueryBounds::new(
            &placeholders,
            Some(QueryBoundSource::Placeholder(third_placeholder_id)),
            Some(QueryBoundSource::Constant(max_secondary)),
        )
        .unwrap();

        // build predicate operations
        let mut predicate_operations = vec![];
        // C3 != 42
        let c5_comparison = BasicOperation {
            first_operand: InputOperand::Column(2),
            second_operand: Some(InputOperand::Constant(U256::from(42))),
            op: Operation::NeOp,
        };
        predicate_operations.push(c5_comparison);
        // C1*C2
        let column_prod = BasicOperation {
            first_operand: InputOperand::Column(0),
            second_operand: Some(InputOperand::Column(1)),
            op: Operation::MulOp,
        };
        predicate_operations.push(column_prod);
        // C4/C6
        let column_div = BasicOperation {
            first_operand: InputOperand::Column(3),
            second_operand: Some(InputOperand::Column(5)),
            op: Operation::DivOp,
        };
        predicate_operations.push(column_div);
        // C4/C6 - C7
        let expr_add = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&predicate_operations, &column_div)
                    .unwrap(),
            ),
            second_operand: Some(InputOperand::Column(6)),
            op: Operation::SubOp,
        };
        predicate_operations.push(expr_add);
        // C1*C2 <= C4/C6 - C7
        let expr_comparison = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&predicate_operations, &column_prod)
                    .unwrap(),
            ),
            second_operand: Some(InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&predicate_operations, &expr_add)
                    .unwrap(),
            )),
            op: Operation::LessThanOrEqOp,
        };
        predicate_operations.push(expr_comparison);
        // C5 < $2
        let placeholder_cmp = BasicOperation {
            first_operand: InputOperand::Column(4),
            second_operand: Some(InputOperand::Placeholder(second_placeholder_id)),
            op: Operation::LessThanOp,
        };
        predicate_operations.push(placeholder_cmp);
        // NOT c5_comparison
        let not_c5 = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&predicate_operations, &c5_comparison)
                    .unwrap(),
            ),
            second_operand: None,
            op: Operation::NotOp,
        };
        predicate_operations.push(not_c5);
        // NOT c5_comparison OR expr_comparison
        let or_comparisons = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&predicate_operations, &not_c5).unwrap(),
            ),
            second_operand: Some(InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&predicate_operations, &expr_comparison)
                    .unwrap(),
            )),
            op: Operation::OrOp,
        };
        predicate_operations.push(or_comparisons);
        // final filtering predicate: or_comparisons XOR placeholder_cmp
        let predicate = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&predicate_operations, &or_comparisons)
                    .unwrap(),
            ),
            second_operand: Some(InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&predicate_operations, &placeholder_cmp)
                    .unwrap(),
            )),
            op: Operation::XorOp,
        };
        predicate_operations.push(predicate);

        // result computations operations
        let mut result_operations = vec![];
        // C1*C2
        let column_prod = BasicOperation {
            first_operand: InputOperand::Column(0),
            second_operand: Some(InputOperand::Column(1)),
            op: Operation::MulOp,
        };
        result_operations.push(column_prod);
        // C1*C2 < 45
        let column_cmp = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&result_operations, &column_prod)
                    .unwrap(),
            ),
            second_operand: Some(InputOperand::Constant(U256::from(45))),
            op: Operation::LessThanOp,
        };
        result_operations.push(column_cmp);
        // C3+C7
        let column_add = BasicOperation {
            first_operand: InputOperand::Column(2),
            second_operand: Some(InputOperand::Column(6)),
            op: Operation::AddOp,
        };
        result_operations.push(column_add);
        // (C3+C7)/C4
        let expr_div = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&result_operations, &column_add).unwrap(),
            ),
            second_operand: Some(InputOperand::Column(3)),
            op: Operation::DivOp,
        };
        result_operations.push(expr_div);
        // C5 - C6
        let column_sub = BasicOperation {
            first_operand: InputOperand::Column(4),
            second_operand: Some(InputOperand::Column(5)),
            op: Operation::SubOp,
        };
        result_operations.push(column_sub);
        // (C5 - C6) % C1
        let column_mod = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&result_operations, &column_sub).unwrap(),
            ),
            second_operand: Some(InputOperand::Column(0)),
            op: Operation::ModOp,
        };
        result_operations.push(column_mod);
        // C1/C5
        let column_div = BasicOperation {
            first_operand: InputOperand::Column(0),
            second_operand: Some(InputOperand::Column(4)),
            op: Operation::DivOp,
        };
        result_operations.push(column_div);
        // C1/C5 - $1
        let sub_placeholder = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                BasicOperation::locate_previous_operation(&result_operations, &column_div).unwrap(),
            ),
            second_operand: Some(InputOperand::Placeholder(first_placeholder_id)),
            op: Operation::SubOp,
        };
        result_operations.push(sub_placeholder);

        let output_items = vec![
            OutputItem::ComputedValue(
                BasicOperation::locate_previous_operation(&result_operations, &column_cmp).unwrap(),
            ),
            OutputItem::ComputedValue(
                BasicOperation::locate_previous_operation(&result_operations, &expr_div).unwrap(),
            ),
            OutputItem::Column(6),
            OutputItem::ComputedValue(
                BasicOperation::locate_previous_operation(&result_operations, &column_mod).unwrap(),
            ),
            OutputItem::ComputedValue(
                BasicOperation::locate_previous_operation(&result_operations, &sub_placeholder)
                    .unwrap(),
            ),
        ];
        let output_ids = vec![F::rand(); output_items.len()];
        let results = ResultStructure::new_for_query_no_aggregation(
            result_operations,
            output_items,
            output_ids
                .iter()
                .map(|id| id.to_canonical_u64())
                .collect_vec(),
            false,
        )
        .unwrap();

        let [node_0, node_1, node_2] = build_test_tree(&query_bounds, &column_ids.to_vec()).await;

        let to_row_cells = |values: &[U256]| {
            let column_cells = values
                .iter()
                .zip(column_ids.to_vec().iter())
                .map(|(&value, &id)| ColumnCell { value, id })
                .collect_vec();
            RowCells::new(
                column_cells[0].clone(),
                column_cells[1].clone(),
                column_cells[2..].to_vec(),
            )
        };

        // run circuit over 4 consecutive rows: row 1A, row 1C, row 2B and row 2D
        let [node_1A, node_1B, node_1C, node_1D] = node_1
            .rows_tree
            .iter()
            .map(|n| n.node.clone())
            .collect_vec()
            .try_into()
            .unwrap();
        let path_1A = vec![];
        let siblings_1A = vec![];
        let merkle_path_1A = MerklePathWithNeighborsGadget::new(
            &path_1A,
            &siblings_1A,
            &node_1A,
            [Some(node_1B.clone()), Some(node_1C.clone())],
        )
        .unwrap();
        let path_1 = vec![];
        let siblings_1 = vec![];
        let merkle_path_index_1 = MerklePathWithNeighborsGadget::new(
            &path_1,
            &siblings_1,
            &node_1.node,
            [Some(node_0.node.clone()), Some(node_2.node.clone())],
        )
        .unwrap();

        let row_cells_1A = to_row_cells(&node_1.rows_tree[0].values);
        let row_1A =
            RowProcessingGadgetInputs::new(merkle_path_1A, merkle_path_index_1, &row_cells_1A)
                .unwrap();

        let path_1C = vec![(node_1A.clone(), ChildPosition::Right)];
        let node_1B_hash =
            HashOutput::try_from(node_1B.compute_node_hash(secondary_index)).unwrap();
        let siblings_1C = vec![Some(node_1B_hash.clone())];
        let merkle_path_1C = MerklePathWithNeighborsGadget::new(
            &path_1C,
            &siblings_1C,
            &node_1C,
            [None, Some(node_1D.clone())],
        )
        .unwrap();

        let row_cells_1C = to_row_cells(&node_1.rows_tree[2].values);
        let row_1C =
            RowProcessingGadgetInputs::new(merkle_path_1C, merkle_path_index_1, &row_cells_1C)
                .unwrap();

        let [node_2A, node_2B, node_2C, node_2D] = node_2
            .rows_tree
            .iter()
            .map(|n| n.node.clone())
            .collect_vec()
            .try_into()
            .unwrap();
        let path_2D = vec![
            (node_2B.clone(), ChildPosition::Right),
            (node_2A.clone(), ChildPosition::Left),
        ];
        let node_2C_hash =
            HashOutput::try_from(node_2C.compute_node_hash(secondary_index)).unwrap();
        let siblings_2D = vec![Some(node_2C_hash), None];
        let merkle_path_2D =
            MerklePathWithNeighborsGadget::new(&path_2D, &siblings_2D, &node_2D, [None, None])
                .unwrap();
        let path_2 = vec![(node_1.node.clone(), ChildPosition::Right)];
        let node_0_hash =
            HashOutput::try_from(node_0.node.compute_node_hash(primary_index)).unwrap();
        let siblings_2 = vec![Some(node_0_hash)];
        let merkle_path_index_2 =
            MerklePathWithNeighborsGadget::new(&path_2, &siblings_2, &node_2.node, [None, None])
                .unwrap();

        let row_cells_2D = to_row_cells(&node_2.rows_tree[3].values);

        let row_2D =
            RowProcessingGadgetInputs::new(merkle_path_2D, merkle_path_index_2, &row_cells_2D)
                .unwrap();

        let path_2B = vec![(node_2A.clone(), ChildPosition::Left)];
        let siblings_2B = vec![None];
        let merkle_path_2B = MerklePathWithNeighborsGadget::new(
            &path_2B,
            &siblings_2B,
            &node_2B,
            [Some(node_2C.clone()), Some(node_2D.clone())],
        )
        .unwrap();

        let row_cells_2B = to_row_cells(&node_2.rows_tree[1].values);

        let row_2B =
            RowProcessingGadgetInputs::new(merkle_path_2B, merkle_path_index_2, &row_cells_2B)
                .unwrap();

        let circuit = RowChunkProcessingCircuit::<
            NUM_ROWS,
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            NoAggOutputCircuit<MAX_NUM_RESULTS>,
        >::new(
            vec![
                row_1A.clone(),
                row_1C.clone(),
                row_2B.clone(),
                row_2D.clone(),
            ],
            &column_ids,
            &predicate_operations,
            &placeholders,
            &query_bounds,
            &results,
        )
        .unwrap();

        // compute placeholder hash for `circuit`
        let placeholder_hash_ids = circuit.ids_for_placeholder_hash();
        let placeholder_hash =
            placeholder_hash(&placeholder_hash_ids, &placeholders, &query_bounds).unwrap();

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check public inputs
        let pis = PublicInputs::<F, MAX_NUM_RESULTS>::from_slice(&proof.public_inputs);

        let root = node_1.node.compute_node_hash(primary_index);
        assert_eq!(root, pis.tree_hash(),);
        assert_eq!(
            <AggregationOperation as ToField<F>>::to_field(&AggregationOperation::IdOp),
            pis.operation_ids()[0]
        );
        // aggregation operation in the other MAX_NUM_RESULTS -1 slots are dummy ones, as in queries
        // without aggregation we accumulate all the results in the first output value,
        // and so we don't care about the other ones
        assert_eq!(
            [<AggregationOperation as ToField<F>>::to_field(&AggregationOperation::default());
                MAX_NUM_RESULTS - 1],
            pis.operation_ids()[1..]
        );

        // closure to compute predicate value and accumulator of output values for a given row with cells `row_cells`.
        // Return also a flag sepcifying whether arithmetic errors have occurred during the computation or not
        let compute_output_values = async |row_cells: &RowCells| {
            let column_values = row_cells
                .to_cells()
                .into_iter()
                .map(|cell| cell.value)
                .collect_vec();
            let (res, predicate_err) = BasicOperation::compute_operations(
                &predicate_operations,
                &column_values,
                &placeholders,
            )
            .unwrap();
            let predicate_value = res.last().unwrap().try_into_bool().unwrap();

            let (res, result_err) = results
                .compute_output_values(&column_values, &placeholders)
                .unwrap();
            let out_cells = res
                .iter()
                .zip(output_ids.iter())
                .map(|(value, id)| TestCell::new(*value, *id))
                .collect_vec();
            let output_acc = if predicate_value {
                // if predicate value is satisfied, then we expose the accumulator of all the output values
                // to be returned for the current row
                map_to_curve_point(
                    &once(out_cells[0].id)
                        .chain(out_cells[0].value.to_fields())
                        .chain(once(
                            out_cells.get(1).map(|cell| cell.id).unwrap_or_default(),
                        ))
                        .chain(
                            out_cells
                                .get(1)
                                .map(|cell| cell.value)
                                .unwrap_or_default()
                                .to_fields(),
                        )
                        .chain(
                            compute_cells_tree_hash(
                                out_cells.get(2..).unwrap_or_default().to_vec(),
                            )
                            .await
                            .to_vec(),
                        )
                        .collect_vec(),
                )
            } else {
                // otherwise, we expose the neutral point to ensure that the results for
                // the current record are not included in the accumulator of all the results
                // of the query
                Point::NEUTRAL
            };
            (predicate_value, predicate_err | result_err, output_acc)
        };

        // compute predicate value and accumulator of output values for each of the 4 rows being proven
        let (predicate_value_1A, err_1A, acc_1A) = compute_output_values(&row_cells_1A).await;
        let (predicate_value_1C, err_1C, acc_1C) = compute_output_values(&row_cells_1C).await;
        let (predicate_value_2B, err_2B, acc_2B) = compute_output_values(&row_cells_2B).await;
        let (predicate_value_2D, err_2D, acc_2D) = compute_output_values(&row_cells_2D).await;

        let computational_hash = ComputationalHash::from_bytes(
            (&Identifiers::computational_hash_universal_circuit(
                &column_ids,
                &predicate_operations,
                &results,
                Some(query_bounds.min_query_secondary().into()),
                Some(query_bounds.max_query_secondary().into()),
            )
            .unwrap())
                .into(),
        );
        // compute expected left boundary row of the proven chunk: should correspond to row_1A
        let left_boundary_row = {
            // predecessor is node_1B, and it's not in the path
            let predecessor_info_1A = NeighborInfo::new(node_1B.value, None);
            // successor is node_1C, and it's not in the path
            let successor_info_1A = NeighborInfo::new(node_1C.value, None);
            let row_1A_info = BoundaryRowNodeInfo {
                end_node_hash: node_1A.compute_node_hash(secondary_index),
                predecessor_info: predecessor_info_1A,
                successor_info: successor_info_1A,
            };
            // predecessor is node_0, and it's not in the path
            let predecessor_index_1 = NeighborInfo::new(node_0.node.value, None);
            // successor is node_2, and it's not in the path
            let successor_index_1 = NeighborInfo::new(node_2.node.value, None);
            let index_1_info = BoundaryRowNodeInfo {
                end_node_hash: node_1.node.compute_node_hash(primary_index),
                predecessor_info: predecessor_index_1,
                successor_info: successor_index_1,
            };
            BoundaryRowData {
                row_node_info: row_1A_info,
                index_node_info: index_1_info,
            }
        };
        // compute expected right boundary row of the proven chunk: should correspond to row_2D
        let right_boundary_row = {
            // predecessor is node_2B, and it's in the path
            let predecessor_2D = NeighborInfo::new(
                node_2B.value,
                Some(node_2B.compute_node_hash(secondary_index)),
            );
            // successor is node_2A, and it's in the path
            let successor_2D = NeighborInfo::new(
                node_2A.value,
                Some(node_2A.compute_node_hash(secondary_index)),
            );
            let row_2D_info = BoundaryRowNodeInfo {
                end_node_hash: node_2D.compute_node_hash(secondary_index),
                predecessor_info: predecessor_2D,
                successor_info: successor_2D,
            };

            // predecessor is node 1, and it's in the path
            let predecessor_index_2 = NeighborInfo::new(
                node_1.node.value,
                Some(node_1.node.compute_node_hash(primary_index)),
            );
            // no successor
            let successor_index_2 = NeighborInfo::new_dummy_successor();
            let index_2_info = BoundaryRowNodeInfo {
                end_node_hash: node_2.node.compute_node_hash(primary_index),
                predecessor_info: predecessor_index_2,
                successor_info: successor_index_2,
            };

            BoundaryRowData {
                row_node_info: row_2D_info,
                index_node_info: index_2_info,
            }
        };

        assert_eq!(pis.overflow_flag(), err_1A | err_1C | err_2B | err_2D,);
        assert_eq!(
            pis.num_matching_rows(),
            F::from_canonical_u8(
                predicate_value_1A as u8
                    + predicate_value_1C as u8
                    + predicate_value_2B as u8
                    + predicate_value_2D as u8
            ),
        );
        assert_eq!(
            pis.first_value_as_curve_point(),
            (acc_1A + acc_1C + acc_2B + acc_2D).to_weierstrass(),
        );
        // The other MAX_NUM_RESULTS -1 output values are dummy ones, as in queries
        // without aggregation we accumulate all the results in the first output value,
        // and so we don't care about the other ones
        assert_eq!(array::from_fn(|_| U256::ZERO), pis.values());
        // check boundary rows
        assert_eq!(pis.to_left_row_raw(), &left_boundary_row.to_fields(),);
        assert_eq!(pis.to_right_row_raw(), &right_boundary_row.to_fields(),);

        assert_eq!(pis.min_primary(), min_primary,);
        assert_eq!(pis.max_primary(), max_primary,);
        assert_eq!(pis.min_secondary(), min_secondary,);
        assert_eq!(pis.max_secondary(), max_secondary,);
        assert_eq!(pis.computational_hash(), computational_hash,);
        assert_eq!(pis.placeholder_hash(), placeholder_hash,);

        // negative test: check that we cannot add nodes in the index tree outside of the range. We try to add
        // row 0B to the set of proven rows
        let [node_0A, node_0B, node_0C] = node_0
            .rows_tree
            .iter()
            .map(|n| n.node.clone())
            .collect_vec()
            .try_into()
            .unwrap();
        let path_0B = vec![(node_0A.clone(), ChildPosition::Left)];
        let siblings_0B = vec![None];
        let merkle_path_0B = MerklePathWithNeighborsGadget::new(
            &path_0B,
            &siblings_0B,
            &node_0B,
            [None, Some(node_0C.clone())],
        )
        .unwrap();
        let path_0 = vec![(node_1.node.clone(), ChildPosition::Left)];
        let node_2_hash =
            HashOutput::try_from(node_2.node.compute_node_hash(primary_index)).unwrap();
        let siblings_0 = vec![Some(node_2_hash)];
        let merkle_path_index_2 =
            MerklePathWithNeighborsGadget::new(&path_0, &siblings_0, &node_0.node, [None, None])
                .unwrap();

        let row_cells_0B = to_row_cells(&node_0.rows_tree[1].values);
        let row_0B =
            RowProcessingGadgetInputs::new(merkle_path_0B, merkle_path_index_2, &row_cells_0B)
                .unwrap();

        let circuit = RowChunkProcessingCircuit::<
            NUM_ROWS,
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            NoAggOutputCircuit<MAX_NUM_RESULTS>,
        >::new(
            vec![row_0B, row_1A, row_1C, row_2B, row_2D],
            &column_ids,
            &predicate_operations,
            &placeholders,
            &query_bounds,
            &results,
        )
        .unwrap();

        check_panic!(
            || run_circuit::<F, D, C, _>(circuit),
            "circuit didn't fail when aggregating row with primary index out of range"
        )
    }
}
