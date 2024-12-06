pub(crate) mod chunk_aggregation;
pub(crate) mod non_existence;
pub(crate) mod row_chunk_processing;

#[cfg(test)]
mod tests {
    use alloy::primitives::U256;
    use itertools::Itertools;
    use mp2_common::{
        types::HashOutput,
        utils::{FromFields, TryIntoBool},
        F,
    };
    use mp2_test::{
        cells_tree::{compute_cells_tree_hash, TestCell},
        utils::gen_random_u256,
    };
    use rand::thread_rng;

    use crate::{query::{
        computational_hash_ids::AggregationOperation, merkle_path::tests::build_node, universal_circuit::{
            universal_circuit_inputs::{BasicOperation, Placeholders, ResultStructure, RowCells},
            universal_query_gadget::OutputValues,
        }, utils::{NodeInfo, QueryBounds}
    }, test_utils::gen_values_in_range};

    /// Data structure employed to represent a node of a rows tree in the tests
    #[derive(Clone, Debug)]
    pub(crate) struct TestRowsTreeNode {
        pub(crate) node: NodeInfo,
        pub(crate) values: Vec<U256>,
    }
    /// Data structure employed to represent a node of the index tree in the tests
    #[derive(Clone, Debug)]
    pub(crate) struct TestIndexTreeNode {
        pub(crate) node: NodeInfo,
        pub(crate) rows_tree: Vec<TestRowsTreeNode>,
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
    pub(crate) async fn build_test_tree(
        bounds: &QueryBounds,
        column_ids: &[F],
    ) -> [TestIndexTreeNode; 3] {
        // sample primary index values
        let rng = &mut thread_rng();
        let [value_0] = gen_values_in_range(rng, U256::ZERO, bounds.min_query_primary()); // value of node 0 must be out of range
        let [value_1, value_2] =
            gen_values_in_range(rng, bounds.min_query_primary(), bounds.max_query_primary());
        // sample secondary index values for rows tree of node 0
        let [value_0c, value_0a] =
            gen_values_in_range(rng, *bounds.max_query_secondary().value(), U256::MAX);
        let [value_0b] = gen_values_in_range(
            rng,
            *bounds.min_query_secondary().value(),
            *bounds.max_query_secondary().value(),
        );
        // sample secondary index values for rows tree of node 1
        let [value_1b] =
            gen_values_in_range(rng, U256::ZERO, *bounds.min_query_secondary().value());
        let [value_1d] = gen_values_in_range(rng, *bounds.max_query_secondary().value(), U256::MAX);
        let [value_1a, value_1c] = gen_values_in_range(
            rng,
            *bounds.min_query_secondary().value(),
            *bounds.max_query_secondary().value(),
        );
        // sample secondary index values for rows tree of node 2
        let [value_2c] =
            gen_values_in_range(rng, U256::ZERO, *bounds.min_query_secondary().value());
        let [value_2b, value_2d, value_2a] = gen_values_in_range(
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
        let (values, cell_tree_hash) = build_cells(value_0, value_0c).await;
        let node_0c = TestRowsTreeNode {
            node: build_node(
                None,
                None,
                value_0c,
                HashOutput::from(cell_tree_hash),
                secondary_index,
            ),
            values,
        };
        // build row 0B
        let (values, cell_tree_hash) = build_cells(value_0, value_0b).await;
        let node_0b = TestRowsTreeNode {
            node: build_node(
                None,
                Some(&node_0c.node),
                value_0b,
                HashOutput::from(cell_tree_hash),
                secondary_index,
            ),
            values,
        };
        // build row 0A
        let (values, cell_tree_hash) = build_cells(value_0, value_0a).await;
        let node_0a = TestRowsTreeNode {
            node: build_node(
                Some(&node_0b.node),
                None,
                value_0a,
                HashOutput::from(cell_tree_hash),
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
                HashOutput::from(node_0a.node.compute_node_hash(secondary_index)),
                primary_index,
            ),
            rows_tree: vec![node_0a, node_0b, node_0c],
        };
        // build row 2C
        let (values, cell_tree_hash) = build_cells(value_2, value_2c).await;
        let node_2c = TestRowsTreeNode {
            node: build_node(
                None,
                None,
                value_2c,
                HashOutput::from(cell_tree_hash),
                secondary_index,
            ),
            values,
        };
        // build row 2D
        let (values, cell_tree_hash) = build_cells(value_2, value_2d).await;
        let node_2d = TestRowsTreeNode {
            node: build_node(
                None,
                None,
                value_2d,
                HashOutput::from(cell_tree_hash),
                secondary_index,
            ),
            values,
        };
        // build row 2B
        let (values, cell_tree_hash) = build_cells(value_2, value_2b).await;
        let node_2b = TestRowsTreeNode {
            node: build_node(
                Some(&node_2c.node),
                Some(&node_2d.node),
                value_2b,
                HashOutput::from(cell_tree_hash),
                secondary_index,
            ),
            values,
        };
        // build row 2A
        let (values, cell_tree_hash) = build_cells(value_2, value_2a).await;
        let node_2a = TestRowsTreeNode {
            node: build_node(
                Some(&node_2b.node),
                None,
                value_2a,
                HashOutput::from(cell_tree_hash),
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
                HashOutput::from(node_2a.node.compute_node_hash(secondary_index)),
                primary_index,
            ),
            rows_tree: vec![node_2a, node_2b, node_2c, node_2d],
        };
        // build row 1D
        let (values, cell_tree_hash) = build_cells(value_1, value_1d).await;
        let node_1d = TestRowsTreeNode {
            node: build_node(
                None,
                None,
                value_1d,
                HashOutput::from(cell_tree_hash),
                secondary_index,
            ),
            values,
        };
        // build row 1B
        let (values, cell_tree_hash) = build_cells(value_1, value_1b).await;
        let node_1b = TestRowsTreeNode {
            node: build_node(
                None,
                None,
                value_1b,
                HashOutput::from(cell_tree_hash),
                secondary_index,
            ),
            values,
        };
        // build row 1C
        let (values, cell_tree_hash) = build_cells(value_1, value_1c).await;
        let node_1c = TestRowsTreeNode {
            node: build_node(
                None,
                Some(&node_1d.node),
                value_1c,
                HashOutput::from(cell_tree_hash),
                secondary_index,
            ),
            values,
        };
        // build row 1A
        let (values, cell_tree_hash) = build_cells(value_1, value_1a).await;
        let node_1a = TestRowsTreeNode {
            node: build_node(
                Some(&node_1b.node),
                Some(&node_1c.node),
                value_1a,
                HashOutput::from(cell_tree_hash),
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
                HashOutput::from(node_1a.node.compute_node_hash(secondary_index)),
                primary_index,
            ),
            rows_tree: vec![node_1a, node_1b, node_1c, node_1d],
        };

        [node_0, node_1, node_2]
    }

    /// Compute predicate value and output values for a given row with cells `row_cells`.
    /// Return also a flag sepcifying whether arithmetic errors have occurred during the computation or not
    pub(crate) fn compute_output_values_for_row<const MAX_NUM_RESULTS: usize>(
        row_cells: &RowCells,
        predicate_operations: &[BasicOperation],
        results: &ResultStructure,
        placeholders: &Placeholders,
    ) -> (bool, bool, OutputValues<MAX_NUM_RESULTS>)
    where
        [(); MAX_NUM_RESULTS - 1]:,
    {
        let column_values = row_cells
            .to_cells()
            .into_iter()
            .map(|cell| cell.value)
            .collect_vec();
        let (res, predicate_err) =
            BasicOperation::compute_operations(predicate_operations, &column_values, placeholders)
                .unwrap();
        let predicate_value = res.last().unwrap().try_into_bool().unwrap();

        let (res, result_err) = results
            .compute_output_values(&column_values, placeholders)
            .unwrap();

        let aggregation_ops = results.aggregation_operations();

        let output_values = res
            .iter()
            .zip(aggregation_ops.iter())
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
    }
}
