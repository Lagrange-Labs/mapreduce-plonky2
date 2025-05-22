use crate::{
    query::universal_circuit::universal_query_gadget::{
        OutputValuesTarget, UniversalQueryOutputWires,
    },
    CBuilder,
};
use mp2_common::{
    u256::UInt256Target,
    utils::{FromTargets, SelectTarget},
};
use plonky2::iop::target::{BoolTarget, Target};

use super::{consecutive_rows::are_consecutive_rows, BoundaryRowDataTarget, RowChunkDataTarget};

/// This method aggregates the 2 chunks `first` and `second`, also checking
/// that they are consecutive. The returned aggregated chunk will
/// correspond to first if `is_second_dummy` flag is true
#[allow(dead_code)] // only in this PR
pub(crate) fn aggregate_chunks<const MAX_NUM_RESULTS: usize>(
    b: &mut CBuilder,
    first: &RowChunkDataTarget<MAX_NUM_RESULTS>,
    second: &RowChunkDataTarget<MAX_NUM_RESULTS>,
    primary_query_bounds: (&UInt256Target, &UInt256Target),
    secondary_query_bounds: (&UInt256Target, &UInt256Target),
    ops: &[Target; MAX_NUM_RESULTS],
    is_second_non_dummy: &BoolTarget,
) -> RowChunkDataTarget<MAX_NUM_RESULTS>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    let (min_query_primary, max_query_primary) = primary_query_bounds;
    let (min_query_secondary, max_query_secondary) = secondary_query_bounds;
    let _true = b._true();
    // check that right boundary row of chunk1 and left boundary row of chunk2
    // are consecutive
    let are_consecutive = are_consecutive_rows(
        b,
        &first.right_boundary_row,
        &second.left_boundary_row,
        min_query_primary,
        max_query_primary,
        min_query_secondary,
        max_query_secondary,
    );
    // assert that the 2 chunks are consecutive only if the second one is not dummy
    let are_consecutive = b.and(are_consecutive, *is_second_non_dummy);
    b.connect(are_consecutive.target, is_second_non_dummy.target);

    // check the same root of the index tree is employed in both chunks to prove
    // membership of rows in the chunks
    b.connect_hashes(
        first.chunk_outputs.tree_hash,
        second.chunk_outputs.tree_hash,
    );
    // sum the number of matching rows of the 2 chunks
    let count = b.add(first.chunk_outputs.count, second.chunk_outputs.count);

    // aggregate output values. Note that we can aggregate outputs also if chunk2 is
    // dummy, since the universal queyr gadget guarantees that dummy rows output
    // values won't affect the final output values
    let mut output_values = vec![];
    let values = [
        first.chunk_outputs.values.clone(),
        second.chunk_outputs.values.clone(),
    ];

    let mut num_overflows = b.add(
        first.chunk_outputs.num_overflows,
        second.chunk_outputs.num_overflows,
    );
    for (i, op) in ops.iter().enumerate() {
        let (output, overflows) = OutputValuesTarget::aggregate_outputs(b, &values, *op, i);
        output_values.extend_from_slice(&output);
        num_overflows = b.add(num_overflows, overflows);
    }

    RowChunkDataTarget {
        left_boundary_row: first.left_boundary_row.clone(),
        right_boundary_row: // if `is_second_non_dummy`, then the right boundary row of the aggregated chunk will 
        // be the right boundary row of second chunk, otherwise we keep right boundary row of first chunk for the 
        // aggregated chunk  
            BoundaryRowDataTarget::select(
                b,
                is_second_non_dummy,
                &second.right_boundary_row,
                &first.right_boundary_row,
            ),
        chunk_outputs: UniversalQueryOutputWires {
            tree_hash: second.chunk_outputs.tree_hash, //  we check it's the same between the 2 chunks
            values: OutputValuesTarget::from_targets(&output_values),
            count,
            num_overflows,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::array;

    use alloy::primitives::U256;
    use itertools::Itertools;
    use mp2_common::{
        array::ToField,
        check_panic,
        types::{CBuilder, HashOutput},
        u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
        utils::{FromFields, ToFields, ToTargets},
        C, D, F,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::gen_random_u256,
    };
    use plonky2::{
        field::types::{Field, PrimeField64, Sample},
        hash::hash_types::{HashOut, HashOutTarget},
        iop::{
            target::{BoolTarget, Target},
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{circuit_builder::CircuitBuilder, config::GenericHashOut},
    };
    use rand::thread_rng;

    use crate::{
        query::{
            computational_hash_ids::{AggregationOperation, Identifiers},
            merkle_path::{
                tests::{build_node, generate_test_tree},
                MerklePathWithNeighborsGadget, MerklePathWithNeighborsTargetInputs, NeighborInfo,
            },
            public_inputs::PublicInputsQueryCircuits,
            row_chunk_gadgets::{
                tests::RowChunkData, BoundaryRowData, BoundaryRowDataTarget, BoundaryRowNodeInfo,
                BoundaryRowNodeInfoTarget, RowChunkDataTarget,
            },
            universal_circuit::universal_query_gadget::{
                OutputValues, OutputValuesTarget, UniversalQueryOutputWires,
            },
            utils::{tests::aggregate_output_values, ChildPosition, NodeInfo},
        },
        test_utils::random_aggregation_operations,
    };

    use super::aggregate_chunks;

    const MAX_NUM_RESULTS: usize = 10;
    const ROW_TREE_MAX_DEPTH: usize = 10;
    const INDEX_TREE_MAX_DEPTH: usize = 3;

    /// Data structure for the input wires necessary to compute the `RowChunkData` associated
    /// to a row chunk being tested
    #[derive(Clone, Debug)]
    struct RowChunkDataInputTarget {
        left_boundary_row_path: MerklePathWithNeighborsTargetInputs<ROW_TREE_MAX_DEPTH>,
        left_boundary_index_path: MerklePathWithNeighborsTargetInputs<INDEX_TREE_MAX_DEPTH>,
        left_boundary_row_value: UInt256Target,
        left_boundary_row_subtree_hash: HashOutTarget,
        left_boundary_index_value: UInt256Target,
        right_boundary_row_path: MerklePathWithNeighborsTargetInputs<ROW_TREE_MAX_DEPTH>,
        right_boundary_index_path: MerklePathWithNeighborsTargetInputs<INDEX_TREE_MAX_DEPTH>,
        right_boundary_row_value: UInt256Target,
        right_boundary_row_subtree_hash: HashOutTarget,
        right_boundary_index_value: UInt256Target,
        chunk_count: Target,
        chunk_num_overflows: Target,
        chunk_output_values: OutputValuesTarget<MAX_NUM_RESULTS>,
    }

    /// Data structure for input values necessary to compute the `RowChunkData` associated
    /// to a row chunk being tested
    #[derive(Clone, Debug)]
    struct RowChunkDataInput {
        left_boundary_row_path: MerklePathWithNeighborsGadget<ROW_TREE_MAX_DEPTH>,
        left_boundary_row_node: NodeInfo,
        left_boundary_index_path: MerklePathWithNeighborsGadget<INDEX_TREE_MAX_DEPTH>,
        left_boundary_index_node: NodeInfo,
        right_boundary_row_path: MerklePathWithNeighborsGadget<ROW_TREE_MAX_DEPTH>,
        right_boundary_row_node: NodeInfo,
        right_boundary_index_path: MerklePathWithNeighborsGadget<INDEX_TREE_MAX_DEPTH>,
        right_boundary_index_node: NodeInfo,
        chunk_count: F,
        chunk_num_overflows: F,
        chunk_output_values: OutputValues<MAX_NUM_RESULTS>,
    }

    impl RowChunkDataInput {
        fn build(
            b: &mut CBuilder,
            primary_index_id: Target,
            secondary_index_id: Target,
        ) -> (RowChunkDataInputTarget, RowChunkDataTarget<MAX_NUM_RESULTS>) {
            let [left_boundary_row_value, left_boundary_index_value, right_boundary_row_value, right_boundary_index_value] =
                b.add_virtual_u256_arr_unsafe();
            let [left_boundary_row_subtree_hash, right_boundary_row_subtree_hash] =
                array::from_fn(|_| b.add_virtual_hash());
            let left_boundary_row_path = MerklePathWithNeighborsGadget::build(
                b,
                left_boundary_row_value.clone(),
                left_boundary_row_subtree_hash,
                secondary_index_id,
            );
            let left_boundary_index_path = MerklePathWithNeighborsGadget::build(
                b,
                left_boundary_index_value.clone(),
                left_boundary_row_path.root,
                primary_index_id,
            );
            let right_boundary_row_path = MerklePathWithNeighborsGadget::build(
                b,
                right_boundary_row_value.clone(),
                right_boundary_row_subtree_hash,
                secondary_index_id,
            );
            let right_boundary_index_path = MerklePathWithNeighborsGadget::build(
                b,
                right_boundary_index_value.clone(),
                right_boundary_row_path.root,
                primary_index_id,
            );

            // Enforce that both boundary rows belong to the same tree
            b.connect_hashes(
                left_boundary_index_path.root,
                right_boundary_index_path.root,
            );

            let left_boundary_row_info = BoundaryRowNodeInfoTarget::from(&left_boundary_row_path);
            let left_boundary_index_info =
                BoundaryRowNodeInfoTarget::from(&left_boundary_index_path);
            let right_boundary_row_info = BoundaryRowNodeInfoTarget::from(&right_boundary_row_path);
            let right_boundary_index_info =
                BoundaryRowNodeInfoTarget::from(&right_boundary_index_path);

            let chunk_inputs = RowChunkDataInputTarget {
                left_boundary_row_path: left_boundary_row_path.inputs,
                left_boundary_index_path: left_boundary_index_path.inputs,
                left_boundary_row_value,
                left_boundary_row_subtree_hash,
                left_boundary_index_value,
                right_boundary_row_path: right_boundary_row_path.inputs,
                right_boundary_index_path: right_boundary_index_path.inputs,
                right_boundary_row_value,
                right_boundary_row_subtree_hash,
                right_boundary_index_value,
                chunk_count: b.add_virtual_target(),
                chunk_num_overflows: b.add_virtual_target(),
                chunk_output_values: OutputValuesTarget::build(b),
            };

            let row_chunk = RowChunkDataTarget {
                left_boundary_row: BoundaryRowDataTarget {
                    row_node_info: left_boundary_row_info,
                    index_node_info: left_boundary_index_info,
                },
                right_boundary_row: BoundaryRowDataTarget {
                    row_node_info: right_boundary_row_info,
                    index_node_info: right_boundary_index_info,
                },
                chunk_outputs: UniversalQueryOutputWires {
                    tree_hash: right_boundary_index_path.root,
                    values: chunk_inputs.chunk_output_values.clone(),
                    count: chunk_inputs.chunk_count,
                    num_overflows: chunk_inputs.chunk_num_overflows,
                },
            };

            (chunk_inputs, row_chunk)
        }

        fn assign(&self, pw: &mut PartialWitness<F>, wires: &RowChunkDataInputTarget) {
            self.left_boundary_row_path
                .assign(pw, &wires.left_boundary_row_path);
            self.left_boundary_index_path
                .assign(pw, &wires.left_boundary_index_path);
            self.right_boundary_row_path
                .assign(pw, &wires.right_boundary_row_path);
            self.right_boundary_index_path
                .assign(pw, &wires.right_boundary_index_path);
            [
                (
                    &wires.left_boundary_row_value,
                    self.left_boundary_row_node.value,
                ),
                (
                    &wires.left_boundary_index_value,
                    self.left_boundary_index_node.value,
                ),
                (
                    &wires.right_boundary_row_value,
                    self.right_boundary_row_node.value,
                ),
                (
                    &wires.right_boundary_index_value,
                    self.right_boundary_index_node.value,
                ),
            ]
            .into_iter()
            .for_each(|(t, v)| pw.set_u256_target(t, v));
            [
                (
                    wires.left_boundary_row_subtree_hash,
                    self.left_boundary_row_node.embedded_tree_hash,
                ),
                (
                    wires.right_boundary_row_subtree_hash,
                    self.right_boundary_row_node.embedded_tree_hash,
                ),
            ]
            .into_iter()
            .for_each(|(t, v)| pw.set_hash_target(t, v));
            [
                (wires.chunk_count, self.chunk_count),
                (wires.chunk_num_overflows, self.chunk_num_overflows),
            ]
            .into_iter()
            .for_each(|(t, v)| pw.set_target(t, v));
            wires
                .chunk_output_values
                .set_target(pw, &self.chunk_output_values);
        }
    }

    #[derive(Clone, Debug)]
    struct TestAggregateChunkWires {
        first: RowChunkDataInputTarget,
        second: RowChunkDataInputTarget,
        min_query_primary: UInt256Target,
        max_query_primary: UInt256Target,
        min_query_secondary: UInt256Target,
        max_query_secondary: UInt256Target,
        primary_index_id: Target,
        secondary_index_id: Target,
        ops: [Target; MAX_NUM_RESULTS],
        is_second_non_dummy: BoolTarget,
    }
    #[derive(Clone, Debug)]
    struct TestAggregateChunks {
        first: RowChunkDataInput,
        second: RowChunkDataInput,
        min_query_primary: Option<U256>,
        max_query_primary: Option<U256>,
        min_query_secondary: Option<U256>,
        max_query_secondary: Option<U256>,
        primary_index_id: F,
        secondary_index_id: F,
        ops: [F; MAX_NUM_RESULTS],
        is_second_dummy: bool,
    }

    impl UserCircuit<F, D> for TestAggregateChunks {
        type Wires = TestAggregateChunkWires;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let [primary_index_id, secondary_index_id] = c.add_virtual_target_arr();
            let (first_chunk_inputs, first_chunk_data) =
                RowChunkDataInput::build(c, primary_index_id, secondary_index_id);
            let (second_chunk_inputs, second_chunk_data) =
                RowChunkDataInput::build(c, primary_index_id, secondary_index_id);
            let [min_query_primary, max_query_primary, min_query_secondary, max_query_secondary] =
                c.add_virtual_u256_arr_unsafe();
            let ops = c.add_virtual_target_arr();
            let is_second_non_dummy = c.add_virtual_bool_target_unsafe();
            let aggregated_chunk = aggregate_chunks(
                c,
                &first_chunk_data,
                &second_chunk_data,
                (&min_query_primary, &max_query_primary),
                (&min_query_secondary, &max_query_secondary),
                &ops,
                &is_second_non_dummy,
            );

            c.register_public_inputs(&aggregated_chunk.to_targets());

            TestAggregateChunkWires {
                first: first_chunk_inputs,
                second: second_chunk_inputs,
                min_query_primary,
                max_query_primary,
                min_query_secondary,
                max_query_secondary,
                primary_index_id,
                secondary_index_id,
                ops,
                is_second_non_dummy,
            }
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.first.assign(pw, &wires.first);
            self.second.assign(pw, &wires.second);
            [
                (
                    &wires.min_query_primary,
                    self.min_query_primary.unwrap_or(U256::ZERO),
                ),
                (
                    &wires.max_query_primary,
                    self.max_query_primary.unwrap_or(U256::MAX),
                ),
                (
                    &wires.min_query_secondary,
                    self.min_query_secondary.unwrap_or(U256::ZERO),
                ),
                (
                    &wires.max_query_secondary,
                    self.max_query_secondary.unwrap_or(U256::MAX),
                ),
            ]
            .into_iter()
            .for_each(|(t, v)| pw.set_u256_target(t, v));
            [
                (wires.primary_index_id, self.primary_index_id),
                (wires.secondary_index_id, self.secondary_index_id),
            ]
            .into_iter()
            .chain(wires.ops.into_iter().zip(self.ops))
            .for_each(|(t, v)| pw.set_target(t, v));
            pw.set_bool_target(wires.is_second_non_dummy, !self.is_second_dummy);
        }
    }

    fn test_aggregate_chunks(ops: [F; MAX_NUM_RESULTS]) {
        let [primary_index_id, secondary_index_id] = F::rand_array();
        // generate a single rows tree that will contain the row chunks to be aggregated: no need to
        // use multiple rows tree in this test, as we already test `are_consecutive_rows` gadget.
        // The generated tree will have the following shape
        //              A
        //          B       C
        //      D               G
        //   E      F
        let [node_a, node_b, node_c, node_d, node_e, node_f, node_g] =
            generate_test_tree(secondary_index_id, None);
        let rows_tree_root = HashOutput::from(node_a.compute_node_hash(secondary_index_id));
        // build the node of the index tree that stores the rows tree being generated
        let rng = &mut thread_rng();
        let index_node = build_node(
            None,
            None,
            gen_random_u256(rng),
            rows_tree_root,
            primary_index_id,
        );
        let root = index_node.compute_node_hash(primary_index_id);

        // generate the output values associated to each chunk
        let inputs = PublicInputsQueryCircuits::<F, MAX_NUM_RESULTS>::sample_from_ops::<2>(&ops);
        let [(first_chunk_count, first_chunk_outputs, fist_chunk_num_overflows), (second_chunk_count, second_chunk_outputs, second_chunk_num_overflows)] =
            inputs
                .into_iter()
                .map(|input| {
                    let pis = PublicInputsQueryCircuits::<F, MAX_NUM_RESULTS>::from_slice(
                        input.as_slice(),
                    );
                    (
                        pis.num_matching_rows(),
                        OutputValues::from_fields(pis.to_values_raw()),
                        F::from_canonical_u8(pis.overflow_flag() as u8),
                    )
                })
                .collect_vec()
                .try_into()
                .unwrap();

        // the first row chunk for this test is given by nodes `B`, `D`, `E` and `F`. So left boundary row is `E` and
        // right boundary row is `B`
        let path_e = vec![
            (node_d, ChildPosition::Left),
            (node_b, ChildPosition::Left),
            (node_a, ChildPosition::Left),
        ];
        let node_f_hash = HashOutput::from(node_f.compute_node_hash(secondary_index_id));
        let node_c_hash = HashOutput::from(node_c.compute_node_hash(secondary_index_id));
        let siblings_e = vec![Some(node_f_hash), None, Some(node_c_hash)];
        let merkle_path_inputs_e = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_e,
            &siblings_e,
            &node_e,
            [None, None], // it's a leaf node
        )
        .unwrap();

        let path_b = vec![(node_a, ChildPosition::Left)];
        let siblings_b = vec![Some(node_c_hash)];
        let merkle_path_inputs_b = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_b,
            &siblings_b,
            &node_b,
            [Some(node_d), None],
        )
        .unwrap();

        let index_node_path = vec![];
        let index_node_siblings = vec![];
        let index_node_merkle_path = MerklePathWithNeighborsGadget::<INDEX_TREE_MAX_DEPTH>::new(
            &index_node_path,
            &index_node_siblings,
            &index_node,
            [None, None],
        )
        .unwrap();
        let first_chunk = RowChunkDataInput {
            left_boundary_row_path: merkle_path_inputs_e,
            left_boundary_row_node: node_e,
            left_boundary_index_path: index_node_merkle_path,
            left_boundary_index_node: index_node,
            right_boundary_row_path: merkle_path_inputs_b,
            right_boundary_row_node: node_b,
            right_boundary_index_path: index_node_merkle_path,
            right_boundary_index_node: index_node,
            chunk_count: first_chunk_count,
            chunk_num_overflows: fist_chunk_num_overflows,
            chunk_output_values: first_chunk_outputs.clone(),
        };

        // the second row chunk for this test is given by nodes `A`, `C`, and `G`. So left boundary row is `A` and
        // right boundary row is `G`
        let path_a = vec![];
        let siblings_a = vec![];
        let merkle_path_inputs_a = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_a,
            &siblings_a,
            &node_a,
            [Some(node_b), Some(node_c)],
        )
        .unwrap();

        let path_g = vec![
            (node_c, ChildPosition::Right),
            (node_a, ChildPosition::Right),
        ];
        let node_b_hash = HashOutput::from(node_b.compute_node_hash(secondary_index_id));
        let siblings_g = vec![None, Some(node_b_hash)];
        let merkle_path_inputs_g = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_g,
            &siblings_g,
            &node_g,
            [None, None],
        )
        .unwrap();

        let second_chunk = RowChunkDataInput {
            left_boundary_row_path: merkle_path_inputs_a,
            left_boundary_row_node: node_a,
            left_boundary_index_path: index_node_merkle_path,
            left_boundary_index_node: index_node,
            right_boundary_row_path: merkle_path_inputs_g,
            right_boundary_row_node: node_g,
            right_boundary_index_path: index_node_merkle_path,
            right_boundary_index_node: index_node,
            chunk_count: second_chunk_count,
            chunk_num_overflows: second_chunk_num_overflows,
            chunk_output_values: second_chunk_outputs.clone(),
        };

        let circuit = TestAggregateChunks {
            first: first_chunk.clone(),
            second: second_chunk.clone(),
            min_query_primary: None,
            max_query_primary: None,
            min_query_secondary: None,
            max_query_secondary: None,
            primary_index_id,
            secondary_index_id,
            ops,
            is_second_dummy: false,
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // compute expected aggregated chunk
        let node_e_info = BoundaryRowNodeInfo {
            end_node_hash: node_e.compute_node_hash(secondary_index_id),
            predecessor_info: NeighborInfo::new_dummy_predecessor(),
            successor_info: NeighborInfo::new(
                node_d.value,
                Some(node_d.compute_node_hash(secondary_index_id)),
            ),
        };
        let index_node_info = BoundaryRowNodeInfo {
            end_node_hash: root,
            predecessor_info: NeighborInfo::new_dummy_predecessor(),
            successor_info: NeighborInfo::new_dummy_successor(),
        };
        let node_g_info = BoundaryRowNodeInfo {
            end_node_hash: node_g.compute_node_hash(secondary_index_id),
            predecessor_info: NeighborInfo::new(
                node_c.value,
                Some(HashOut::from_bytes((&node_c_hash).into())),
            ),
            successor_info: NeighborInfo::new_dummy_successor(),
        };
        let (expected_outputs, expected_num_overflows) = {
            let outputs = [first_chunk_outputs.clone(), second_chunk_outputs.clone()];
            let mut num_overflows = fist_chunk_num_overflows + second_chunk_num_overflows;
            let outputs = ops
                .into_iter()
                .enumerate()
                .flat_map(|(i, op)| {
                    let (out, overflows) = aggregate_output_values(i, &outputs, op);
                    num_overflows += F::from_canonical_u32(overflows);
                    out
                })
                .collect_vec();
            (
                OutputValues::from_fields(&outputs),
                num_overflows.to_canonical_u64(),
            )
        };
        let expected_count = (first_chunk_count + second_chunk_count).to_canonical_u64();

        let expected_chunk = RowChunkData::<MAX_NUM_RESULTS> {
            left_boundary_row: BoundaryRowData {
                row_node_info: node_e_info.clone(),
                index_node_info: index_node_info.clone(),
            },
            right_boundary_row: BoundaryRowData {
                row_node_info: node_g_info,
                index_node_info: index_node_info.clone(),
            },
            chunk_tree_hash: root,
            output_values: expected_outputs.clone(),
            num_overflows: expected_num_overflows,
            count: expected_count,
        };

        assert_eq!(proof.public_inputs, expected_chunk.to_fields());

        // test with second chunk being dummy; we use a non-consecutive chunk as the dummy one: the row chunk
        // given by node_G only
        let second_chunk = RowChunkDataInput {
            left_boundary_row_path: merkle_path_inputs_g,
            left_boundary_row_node: node_g,
            left_boundary_index_path: index_node_merkle_path,
            left_boundary_index_node: index_node,
            right_boundary_row_path: merkle_path_inputs_g,
            right_boundary_row_node: node_g,
            right_boundary_index_path: index_node_merkle_path,
            right_boundary_index_node: index_node,
            chunk_count: second_chunk_count,
            chunk_num_overflows: second_chunk_num_overflows,
            chunk_output_values: second_chunk_outputs.clone(),
        };
        let circuit = TestAggregateChunks {
            first: first_chunk.clone(),
            second: second_chunk.clone(),
            min_query_primary: None,
            max_query_primary: None,
            min_query_secondary: None,
            max_query_secondary: None,
            primary_index_id,
            secondary_index_id,
            ops,
            is_second_dummy: true, // we set the second chunk to dummy
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // compute expected aggregated chunk
        // since we aggregate with a dummy chunk, we expect right boundary row to be the same as the
        // first chunk, that is node_B
        let node_b_info = BoundaryRowNodeInfo {
            end_node_hash: HashOut::from_bytes((&node_b_hash).into()),
            predecessor_info: NeighborInfo::new(node_f.value, None),
            successor_info: NeighborInfo::new(
                node_a.value,
                Some(HashOut::from_bytes((&rows_tree_root).into())),
            ),
        };
        let expected_chunk = RowChunkData::<MAX_NUM_RESULTS> {
            left_boundary_row: BoundaryRowData {
                row_node_info: node_e_info,
                index_node_info: index_node_info.clone(),
            },
            right_boundary_row: BoundaryRowData {
                row_node_info: node_b_info,
                index_node_info: index_node_info.clone(),
            },
            chunk_tree_hash: root,
            output_values: expected_outputs.clone(),
            num_overflows: expected_num_overflows,
            count: expected_count,
        };
        assert_eq!(proof.public_inputs, expected_chunk.to_fields());

        // negative test: check that we cannot aggregate non-consecutive non-dummy chunks
        let circuit = TestAggregateChunks {
            first: first_chunk.clone(),
            second: second_chunk.clone(),
            min_query_primary: None,
            max_query_primary: None,
            min_query_secondary: None,
            max_query_secondary: None,
            primary_index_id,
            secondary_index_id,
            ops,
            is_second_dummy: false,
        };

        check_panic!(
            || run_circuit::<F, D, C, _>(circuit),
            "circuit didn't fail when aggregating non-consecutive non-dummy chunks"
        );

        // negative test: check that we cannot aggregate a chunk with a wrong merkle root
        // we build the second chunk employing a fake index node
        let fake_node = build_node(
            None,
            None,
            gen_random_u256(rng),
            rows_tree_root,
            primary_index_id,
        );
        let fake_node_merkle_path = MerklePathWithNeighborsGadget::<INDEX_TREE_MAX_DEPTH>::new(
            &[],
            &[],
            &fake_node,
            [None, None],
        )
        .unwrap();
        let second_chunk = RowChunkDataInput {
            left_boundary_row_path: merkle_path_inputs_a,
            left_boundary_row_node: node_a,
            left_boundary_index_path: fake_node_merkle_path,
            left_boundary_index_node: fake_node,
            right_boundary_row_path: merkle_path_inputs_g,
            right_boundary_row_node: node_g,
            right_boundary_index_path: fake_node_merkle_path,
            right_boundary_index_node: fake_node,
            chunk_count: second_chunk_count,
            chunk_num_overflows: second_chunk_num_overflows,
            chunk_output_values: second_chunk_outputs.clone(),
        };

        let circuit = TestAggregateChunks {
            first: first_chunk.clone(),
            second: second_chunk.clone(),
            min_query_primary: None,
            max_query_primary: None,
            min_query_secondary: None,
            max_query_secondary: None,
            primary_index_id,
            secondary_index_id,
            ops,
            is_second_dummy: false,
        };

        check_panic!(
            || run_circuit::<F, D, C, _>(circuit),
            "circuit didn't fail when aggregating chunks with different merkle roots"
        );
    }

    #[test]
    fn test_aggregate_chunks_random_operations() {
        let ops = random_aggregation_operations();

        test_aggregate_chunks(ops);
    }

    #[test]
    fn test_aggregate_chunks_with_id_operation() {
        // Generate the random operations.
        let mut ops = random_aggregation_operations();

        // Set the first operation to ID for testing the digest computation.
        ops[0] = Identifiers::AggregationOperations(AggregationOperation::IdOp).to_field();

        test_aggregate_chunks(ops);
    }
}
