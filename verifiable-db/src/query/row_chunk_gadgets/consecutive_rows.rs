use mp2_common::{
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target},
    utils::HashBuilder,
    F,
};
use plonky2::{field::types::Field, iop::target::BoolTarget};

use super::{BoundaryRowDataTarget, BoundaryRowNodeInfoTarget};

/// This methods checks whether two nodes `first` and `second` are consecutive, according
/// to the definition found in the docs
/// (https://www.notion.so/lagrangelabs/Aggregating-Query-Results-with-Individual-Merkle-Paths-10628d1c65a880b1b151d4ac017fa445?pvs=4#10d28d1c65a8804fb11ed5d14fa70ea3)
/// The query bounds provided as inputs refer to either the secondary or primary index,
/// depending on whether the nodes are in a rows tree or in the index tree.
/// The method returns 2 flags:
/// - The first one being true iff the 2 nodes are consecutive
/// - The second one being true iff the successor of first node is found and its value is in the range
///   specified by the query bounds provided as inputs
#[allow(dead_code)] // only in this PR
fn are_consecutive_nodes(
    b: &mut CBuilder,
    first: &BoundaryRowNodeInfoTarget,
    second: &BoundaryRowNodeInfoTarget,
    min_query_bound: &UInt256Target,
    max_query_bound: &UInt256Target,
    are_rows_tree_nodes: bool,
) -> (BoolTarget, BoolTarget) {
    let mut are_consecutive = b._true();
    let first_node_successor_value = &first.successor_info.value;
    // ensure that we don't prove nodes outside of the range: the successor of the
    // first node must store a value bigger that `min_query_bound`
    let bigger_than_min = b.is_less_or_equal_than_u256(min_query_bound, first_node_successor_value);
    are_consecutive = b.and(are_consecutive, bigger_than_min);
    // determine whether the successor (if any) of the first node stores a value in the query range or not;
    // note that, since we previously checked that such value is >= min_query_bound,
    // we only need to check whether this value is not dummy (i.e., if the successor exists) and if
    // such value is <= max_query_bound
    let smaller_than_max =
        b.is_less_or_equal_than_u256(first_node_successor_value, max_query_bound);
    let first_node_succ_in_range = b.and(smaller_than_max, first.successor_info.is_found);
    // if first_node_succ_in_range is true, and the successor of the first node was found in the path from
    // such node to the root of the tree, then the hash of successor node will be placed in
    // `first.successor_info.hash` by `MerklePathWithNeighborsGadget: therefore, we can check that `second`
    // is consecutive of `first` by checking that `first.successor_info.hash` is the hash of the second node;
    // otherwise, we cannot check right now that the 2 nodes are consecutive, we will do it later
    let check_are_consecutive = b.and(first_node_succ_in_range, first.successor_info.is_in_path);
    let is_second_node_successor = b.hash_eq(&first.successor_info.hash, &second.end_node_hash);
    // update are_consecutive as `are_consecutive && is_second_node_successor`` if `check_are_consecutive` is true
    let new_are_consecutive = b.and(are_consecutive, is_second_node_successor);
    are_consecutive = BoolTarget::new_unsafe(b.select(
        check_are_consecutive,
        new_are_consecutive.target,
        are_consecutive.target,
    ));
    // we now look at the predecessor of second node, matching it with first node in case the
    // predecessor is found in the path of second node in the tree
    let second_node_predecessor_value = &second.predecessor_info.value;
    // ensure that we don't prove nodes outside of the range: the predecessor of the second
    // node must store a value smaller that `max_query_bound``
    let smaller_than_max =
        b.is_less_or_equal_than_u256(second_node_predecessor_value, max_query_bound);
    are_consecutive = b.and(are_consecutive, smaller_than_max);
    // determine whether the predecessor (if any) of the second node stores a value in the query range or not;
    // note that, since we previously checked that such value is <= max_query_bound,
    // we only need to check whether this value is not dummy (i.e., if the predecessor exists) and if
    // such value is >= min_query_bound
    let bigger_than_min =
        b.is_less_or_equal_than_u256(min_query_bound, second_node_predecessor_value);
    let second_node_pred_in_range = b.and(bigger_than_min, second.predecessor_info.is_found);
    // if second_node_pred_in_range is true, and the predecessor of the second node was found in the path from
    // such node to the root of the tree, then the hash of predecessor node will be placed in
    // `second.predecessor_info.hash` by `MerklePathWithNeighborsGadget: therefore, we can check that `second`
    // is consecutive of `first` by checking that `second.predecessor_info.hash` is the hash of the first node;
    // otherwise, we cannot check right now that the 2 nodes are consecutive, and it necessarily means we have
    // already done it before when checking that the successor of first node was the second node
    let check_are_consecutive = b.and(
        second_node_pred_in_range,
        second.predecessor_info.is_in_path,
    );
    let is_second_node_successor = b.hash_eq(&second.predecessor_info.hash, &first.end_node_hash);
    // update are_consecutive as `are_consecutive && is_second_node_successor`` if `check_are_consecutive` is true
    let new_are_consecutive = b.and(are_consecutive, is_second_node_successor);
    are_consecutive = BoolTarget::new_unsafe(b.select(
        check_are_consecutive,
        new_are_consecutive.target,
        are_consecutive.target,
    ));

    // lastly, check that either successor of first node is located in the path, or the predecessor of second node
    // is located in the path, which is necessarily true if the 2 nodes are consecutive. Note that we need to enforce
    // this always if we need to "strictly" prove that 2 nodes are consecutive, which happens in the following cases:
    // - if nodes are in the index tree
    // - if nodes are in a rows tree, but `first_node_succ_in_range` is true. Indeed, if the successor of first node
    //   is out of range or doesn't exist, then it means that second node belongs to another rows tree, and so it cannot
    //   be a successor of first node in the same rows tree
    let either_is_in_path = b.or(
        first.successor_info.is_in_path,
        second.predecessor_info.is_in_path,
    );

    if !are_rows_tree_nodes {
        // in case of index tree, we need to enforce that `either_is_in_path` must be true
        are_consecutive = b.and(are_consecutive, either_is_in_path);
        // furthermore, we also need to enforce that first_node_succ_in_range and second_node_pred_in_range
        // are both true; otherwise, the prover could provide the nodes at the boundary and prove them
        // to be consecutive, which is not ok in the index tree
        are_consecutive = b.and(are_consecutive, first_node_succ_in_range);
        are_consecutive = b.and(are_consecutive, second_node_pred_in_range);
    } else {
        // in case of rows tree nodes, we need to check that `first_row_succ_in_range == second_row_pred_in_range`,
        // which should always hold for consecutive rows since:
        // - if the successor of first row is in range, then second row must be its successor
        //   in the same rows tree, and so the predecessor of second row is the first row itself,
        //   which is expected to be in range since we never need to prove nodes not in range
        //   but with a successor in range
        // - if the successor of first row is out of range, then second row is expected to
        //   be a node in the "subsequent" rows tree (i.e., the rows tree stored in the index
        //   tree node which is the successor of the index tree node storing first row); this node
        //   can be either:
        //	    - the first node of the "subsequent" rows tree with value >= min_secondary;
        //        in this case, the predecessor of second row is < min_secondary, and so out of range
        //	    - if no such node can be found in the "subsequent" rows tree, then second row will be
        //        the last node in the "subsequent" rows tree with value < MIN_secondary; in
        //	      this case, also its predecessor will necessarily be < MIN_secondary, and so
        //	      out of range
        // we first compute first_row_succ_in_range XOR second_row_pred_in_range: a XOR b = a + b - 2*a*b
        let range_flags_sum = b.add(
            first_node_succ_in_range.target,
            second_node_pred_in_range.target,
        );
        let minus_2 = F::NEG_ONE + F::NEG_ONE;
        let range_flags_xor = b.arithmetic(
            minus_2,
            F::ONE,
            first_node_succ_in_range.target,
            second_node_pred_in_range.target,
            range_flags_sum,
        );
        // then, `are_consecutive = are_consecutive AND NOT(range_flags_xor) = are_consecutive - are_consecutive*range_flags_xor`
        are_consecutive = BoolTarget::new_unsafe(b.arithmetic(
            F::NEG_ONE,
            F::ONE,
            are_consecutive.target,
            range_flags_xor,
            are_consecutive.target,
        ));
        // in case of nodes in a rows tree, then we need to enforce that second is the successor of first only
        // if the nodes are in the same rows tree, that is if `first_node_succ_in_range` is true
        let new_are_consecutive = b.and(are_consecutive, either_is_in_path);
        are_consecutive = BoolTarget::new_unsafe(b.select(
            first_node_succ_in_range,
            new_are_consecutive.target,
            are_consecutive.target,
        ));
    }

    (are_consecutive, first_node_succ_in_range)
}

/// This methods checks whether two rows `first` and `second` are consecutive, according
/// to the definition found in the docs
/// (https://www.notion.so/lagrangelabs/Aggregating-Query-Results-with-Individual-Merkle-Paths-10628d1c65a880b1b151d4ac017fa445?pvs=4#10d28d1c65a8804fb11ed5d14fa70ea3)
#[allow(dead_code)] // only in this PR
pub(crate) fn are_consecutive_rows(
    b: &mut CBuilder,
    first: &BoundaryRowDataTarget,
    second: &BoundaryRowDataTarget,
    min_query_primary: &UInt256Target,
    max_query_primary: &UInt256Target,
    min_query_secondary: &UInt256Target,
    max_query_secondary: &UInt256Target,
) -> BoolTarget {
    let (are_consecutive, first_row_succ_in_range) = are_consecutive_nodes(
        b,
        &first.row_node_info,
        &second.row_node_info,
        min_query_secondary,
        max_query_secondary,
        true,
    );
    // at this stage we checked that the rows tree nodes storing first and second row are consecutive; we need
    // to check also index tree consistency.
    // if first_row_succ_in_range is true, then both the rows must be in the same rows tree; so, we simply
    // check this and we are done
    let is_same_rows_tree = b.hash_eq(
        &first.index_node_info.end_node_hash,
        &second.index_node_info.end_node_hash,
    );

    // otherwise, if the rows are in different rows trees, we need to check that they are stored in subsequent
    // rows trees
    let (are_index_nodes_consecutive, _) = are_consecutive_nodes(
        b,
        &first.index_node_info,
        &second.index_node_info,
        min_query_primary,
        max_query_primary,
        false,
    );
    // compute the flag to be accumulated in `are_consecutive`, depending on whether the 2 rows are in the same
    // rows tree or not (i.e., whether first_row_succ_in_range is true)
    let index_tree_check = BoolTarget::new_unsafe(b.select(
        first_row_succ_in_range,
        is_same_rows_tree.target,
        are_index_nodes_consecutive.target,
    ));
    b.and(are_consecutive, index_tree_check)
}

#[cfg(test)]
mod tests {
    use std::array;

    use alloy::primitives::U256;
    use mp2_common::{
        types::HashOutput,
        u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
        utils::TryIntoBool,
        C, D, F,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::gen_random_u256,
    };
    use plonky2::{
        field::types::Sample,
        hash::hash_types::HashOutTarget,
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::circuit_builder::CircuitBuilder,
    };
    use rand::thread_rng;

    use crate::query::{
        merkle_path::{
            tests::{build_node, generate_test_tree},
            MerklePathWithNeighborsGadget, MerklePathWithNeighborsTargetInputs,
        },
        utils::{ChildPosition, NodeInfo},
    };

    use super::{
        are_consecutive_nodes, are_consecutive_rows, BoundaryRowDataTarget,
        BoundaryRowNodeInfoTarget,
    };

    const ROW_TREE_MAX_DEPTH: usize = 10;
    const INDEX_TREE_MAX_DEPTH: usize = 15;

    #[derive(Clone, Debug)]
    struct TestConsecutiveNodes<const ROWS_TREE_NODES: bool, const MAX_DEPTH: usize>
    where
        [(); MAX_DEPTH - 1]:,
    {
        first_node_path: MerklePathWithNeighborsGadget<MAX_DEPTH>,
        first_node_info: NodeInfo,
        second_node_path: MerklePathWithNeighborsGadget<MAX_DEPTH>,
        second_node_info: NodeInfo,
        index_id: F,
        min_query_bound: Option<U256>,
        max_query_bound: Option<U256>,
    }

    #[derive(Clone, Debug)]
    struct TestConsecutiveNodesWires<const MAX_DEPTH: usize>
    where
        [(); MAX_DEPTH - 1]:,
    {
        first_node_path: MerklePathWithNeighborsTargetInputs<MAX_DEPTH>,
        first_node_value: UInt256Target,
        first_node_tree_hash: HashOutTarget,
        second_node_path: MerklePathWithNeighborsTargetInputs<MAX_DEPTH>,
        second_node_value: UInt256Target,
        second_node_tree_hash: HashOutTarget,
        index_id: Target,
        min_query_bound: UInt256Target,
        max_query_bound: UInt256Target,
    }

    impl<const MAX_DEPTH: usize> TestConsecutiveNodesWires<MAX_DEPTH>
    where
        [(); MAX_DEPTH - 1]:,
    {
        fn new(
            c: &mut CircuitBuilder<F, D>,
        ) -> (Self, BoundaryRowNodeInfoTarget, BoundaryRowNodeInfoTarget) {
            let [first_node_value, second_node_value, min_query_bound, max_query_bound] =
                c.add_virtual_u256_arr_unsafe();
            let [first_node_tree_hash, second_node_tree_hash] =
                array::from_fn(|_| c.add_virtual_hash());
            let index_id = c.add_virtual_target();
            let first_node_path = MerklePathWithNeighborsGadget::build(
                c,
                first_node_value,
                first_node_tree_hash,
                index_id,
            );
            let second_node_path = MerklePathWithNeighborsGadget::build(
                c,
                second_node_value,
                second_node_tree_hash,
                index_id,
            );

            let first_node = BoundaryRowNodeInfoTarget {
                end_node_hash: first_node_path.end_node_hash,
                predecessor_info: first_node_path.predecessor_info,
                successor_info: first_node_path.successor_info,
            };
            let second_node = BoundaryRowNodeInfoTarget {
                end_node_hash: second_node_path.end_node_hash,
                predecessor_info: second_node_path.predecessor_info,
                successor_info: second_node_path.successor_info,
            };

            (
                Self {
                    first_node_path: first_node_path.inputs,
                    first_node_value,
                    first_node_tree_hash,
                    second_node_path: second_node_path.inputs,
                    second_node_value,
                    second_node_tree_hash,
                    index_id,
                    min_query_bound,
                    max_query_bound,
                },
                first_node,
                second_node,
            )
        }
    }

    impl<const ROWS_TREE_NODES: bool, const MAX_DEPTH: usize> UserCircuit<F, D>
        for TestConsecutiveNodes<ROWS_TREE_NODES, MAX_DEPTH>
    where
        [(); MAX_DEPTH - 1]:,
    {
        type Wires = TestConsecutiveNodesWires<MAX_DEPTH>;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let (wires, first_node, second_node) = TestConsecutiveNodesWires::new(c);

            let (are_consecutive, _) = are_consecutive_nodes(
                c,
                &first_node,
                &second_node,
                &wires.min_query_bound,
                &wires.max_query_bound,
                ROWS_TREE_NODES,
            );

            c.register_public_input(are_consecutive.target);

            wires
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.first_node_path.assign(pw, &wires.first_node_path);
            self.second_node_path.assign(pw, &wires.second_node_path);
            [
                (self.first_node_info.value, &wires.first_node_value),
                (self.second_node_info.value, &wires.second_node_value),
                (
                    self.min_query_bound.unwrap_or(U256::ZERO),
                    &wires.min_query_bound,
                ),
                (
                    self.max_query_bound.unwrap_or(U256::MAX),
                    &wires.max_query_bound,
                ),
            ]
            .into_iter()
            .for_each(|(value, target)| pw.set_u256_target(target, value));
            [
                (
                    self.first_node_info.embedded_tree_hash,
                    wires.first_node_tree_hash,
                ),
                (
                    self.second_node_info.embedded_tree_hash,
                    wires.second_node_tree_hash,
                ),
            ]
            .into_iter()
            .for_each(|(value, target)| pw.set_hash_target(target, value));
            pw.set_target(wires.index_id, self.index_id);
        }
    }

    #[derive(Clone, Debug)]
    struct TestConsecutiveRows {
        row_tree_nodes: TestConsecutiveNodes<true, ROW_TREE_MAX_DEPTH>,
        index_tree_nodes: TestConsecutiveNodes<false, INDEX_TREE_MAX_DEPTH>,
    }

    #[derive(Clone, Debug)]
    struct TestConsecutiveRowsWires {
        row_tree_nodes: TestConsecutiveNodesWires<ROW_TREE_MAX_DEPTH>,
        index_tree_nodes: TestConsecutiveNodesWires<INDEX_TREE_MAX_DEPTH>,
    }

    impl UserCircuit<F, D> for TestConsecutiveRows {
        type Wires = TestConsecutiveRowsWires;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let (row_tree_nodes, first_row_node, second_row_node) =
                TestConsecutiveNodesWires::new(c);
            let (index_tree_nodes, first_index_node, second_index_node) =
                TestConsecutiveNodesWires::new(c);
            let first = BoundaryRowDataTarget {
                row_node_info: first_row_node,
                index_node_info: first_index_node,
            };
            let second = BoundaryRowDataTarget {
                row_node_info: second_row_node,
                index_node_info: second_index_node,
            };
            let are_consecutive = are_consecutive_rows(
                c,
                &first,
                &second,
                &index_tree_nodes.min_query_bound,
                &index_tree_nodes.max_query_bound,
                &row_tree_nodes.min_query_bound,
                &row_tree_nodes.max_query_bound,
            );

            c.register_public_input(are_consecutive.target);

            TestConsecutiveRowsWires {
                row_tree_nodes,
                index_tree_nodes,
            }
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.row_tree_nodes.prove(pw, &wires.row_tree_nodes);
            self.index_tree_nodes.prove(pw, &wires.index_tree_nodes);
        }
    }

    #[test]
    fn test_are_consecutive_nodes() {
        let index_id = F::rand();
        // Build the following Merkle-tree
        //              A
        //          B       C
        //      D               G
        //   E      F
        let [node_a, node_b, node_c, node_d, node_e, node_f, node_g] =
            generate_test_tree(index_id, None);

        // test that nodes F and D are consecutive
        let path_f = vec![
            (node_d, ChildPosition::Right), // we start from the ancestor of the start node of the path
            (node_b, ChildPosition::Left),
            (node_a, ChildPosition::Left),
        ];
        let node_e_hash = HashOutput::from(node_e.compute_node_hash(index_id));
        let node_c_hash = HashOutput::from(node_c.compute_node_hash(index_id));
        let siblings_f = vec![Some(node_e_hash), None, Some(node_c_hash)];
        let merkle_path_inputs_f = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_f,
            &siblings_f,
            &node_f,
            [None, None], // it's a leaf node
        )
        .unwrap();
        let path_d = vec![(node_b, ChildPosition::Left), (node_a, ChildPosition::Left)];
        let siblings_d = vec![None, Some(node_c_hash)];
        let merkle_path_inputs_d = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_d,
            &siblings_d,
            &node_d,
            [Some(node_e), Some(node_f)],
        )
        .unwrap();
        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_d,
            first_node_info: node_d,
            second_node_path: merkle_path_inputs_f,
            second_node_info: node_f,
            index_id,
            min_query_bound: None,
            max_query_bound: None,
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // test that nodes A and C are consecutive
        let path_a = vec![];
        let siblings_a = vec![];
        let merkle_path_inputs_a = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_a,
            &siblings_a,
            &node_a,
            [Some(node_b), Some(node_c)],
        )
        .unwrap();
        let path_c = vec![(node_a, ChildPosition::Right)];
        let node_b_hash = HashOutput::from(node_b.compute_node_hash(index_id));
        let siblings_c = vec![Some(node_b_hash)];
        let merkle_path_inputs_c = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_c,
            &siblings_c,
            &node_c,
            [None, Some(node_g)],
        )
        .unwrap();

        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_a,
            first_node_info: node_a,
            second_node_path: merkle_path_inputs_c,
            second_node_info: node_c,
            index_id,
            min_query_bound: None,
            max_query_bound: None,
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // test that nodes F and B are consecutive
        let path_b = vec![(node_a, ChildPosition::Left)];
        let siblings_b = vec![Some(node_c_hash)];
        let merkle_path_inputs_b = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_b,
            &siblings_b,
            &node_b,
            [Some(node_d), None],
        )
        .unwrap();

        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_f,
            first_node_info: node_f,
            second_node_path: merkle_path_inputs_b,
            second_node_info: node_b,
            index_id,
            min_query_bound: None,
            max_query_bound: None,
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // negative test: E and F are not consecutive
        let path_e = vec![
            (node_d, ChildPosition::Left),
            (node_b, ChildPosition::Left),
            (node_a, ChildPosition::Left),
        ];
        let node_f_hash = HashOutput::from(node_f.compute_node_hash(index_id));
        let siblings_e = vec![Some(node_f_hash), None, Some(node_c_hash)];
        let merkle_path_inputs_e = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_e,
            &siblings_e,
            &node_e,
            [None, None], // it's a leaf node
        )
        .unwrap();

        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_e,
            first_node_info: node_e,
            second_node_path: merkle_path_inputs_f,
            second_node_info: node_f,
            index_id,
            min_query_bound: None,
            max_query_bound: None,
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are not consecutive
        assert!(!proof.public_inputs[0].try_into_bool().unwrap());

        // negative test: A and B are not consecutive (wrong order)
        let path_a = vec![];
        let siblings_a = vec![];
        let merkle_path_inputs_a = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_a,
            &siblings_a,
            &node_a,
            [Some(node_b), Some(node_c)],
        )
        .unwrap();

        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_a,
            first_node_info: node_a,
            second_node_path: merkle_path_inputs_b,
            second_node_info: node_b,
            index_id,
            min_query_bound: None,
            max_query_bound: None,
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are not consecutive
        assert!(!proof.public_inputs[0].try_into_bool().unwrap());

        // but B and A are consecutive
        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_b,
            first_node_info: node_b,
            second_node_path: merkle_path_inputs_a,
            second_node_info: node_a,
            index_id,
            min_query_bound: None,
            max_query_bound: None,
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // check that if we are proving nodes in a rows tree, then we can prove that C and D are consecutive
        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_c,
            first_node_info: node_c,
            second_node_path: merkle_path_inputs_d,
            second_node_info: node_d,
            index_id,
            min_query_bound: Some(node_d.value),
            max_query_bound: Some(node_c.value),
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // instead, this is not possible if we are proving nodes in the index tree
        let circuit = TestConsecutiveNodes::<false, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_c,
            first_node_info: node_c,
            second_node_path: merkle_path_inputs_f,
            second_node_info: node_f,
            index_id,
            min_query_bound: Some(node_f.value),
            max_query_bound: Some(node_c.value),
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are not consecutive
        assert!(!proof.public_inputs[0].try_into_bool().unwrap());

        // check that if we are proving nodes in a rows tree, then we can prove that G and E are consecutive
        let path_g = vec![
            (node_c, ChildPosition::Right),
            (node_a, ChildPosition::Right),
        ];
        let siblings_g = vec![None, Some(node_b_hash)];
        let merkle_path_inputs_g = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_g,
            &siblings_g,
            &node_g,
            [None, None],
        )
        .unwrap();
        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_g,
            first_node_info: node_g,
            second_node_path: merkle_path_inputs_e,
            second_node_info: node_e,
            index_id,
            min_query_bound: None,
            max_query_bound: None,
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // instead, this is not possible if we are proving nodes in the index tree
        let circuit = TestConsecutiveNodes::<false, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_g,
            first_node_info: node_g,
            second_node_path: merkle_path_inputs_e,
            second_node_info: node_e,
            index_id,
            min_query_bound: None,
            max_query_bound: None,
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are not consecutive
        assert!(!proof.public_inputs[0].try_into_bool().unwrap());

        // check that, even in a rows tree, we cannot prove nodes which are not at the boundaries of the query range
        // to be consecutive: test that C and E are not consecutive
        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_c,
            first_node_info: node_c,
            second_node_path: merkle_path_inputs_e,
            second_node_info: node_e,
            index_id,
            min_query_bound: None,
            max_query_bound: None,
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are not consecutive
        assert!(!proof.public_inputs[0].try_into_bool().unwrap());

        // but check that C and E can be consecutive if they become at the boundaries of the range
        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_c,
            first_node_info: node_c,
            second_node_path: merkle_path_inputs_e,
            second_node_info: node_e,
            index_id,
            min_query_bound: None,
            max_query_bound: Some(node_c.value),
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());
    }

    #[test]
    fn test_are_consecutive_rows() {
        // structure representing the nodes of a tree generated with `generate_test_tree`
        struct RowsTree {
            node_a: NodeInfo,
            node_b: NodeInfo,
            node_c: NodeInfo,
            node_d: NodeInfo,
            node_e: NodeInfo,
            node_f: NodeInfo,
            node_g: NodeInfo,
        }

        impl From<[NodeInfo; 7]> for RowsTree {
            fn from(value: [NodeInfo; 7]) -> Self {
                Self {
                    node_a: value[0],
                    node_b: value[1],
                    node_c: value[2],
                    node_d: value[3],
                    node_e: value[4],
                    node_f: value[5],
                    node_g: value[6],
                }
            }
        }

        // we build an index tree with the following nodes:
        //              1
        //       0              3
        //                  2       4
        // where each node stores a rows tree generated with `generate_test_tree`
        // generate values to be stored in index tree nodes
        let rng = &mut thread_rng();
        let mut values: [U256; 5] = array::from_fn(|_| gen_random_u256(rng));
        values.sort();
        let secondary_index_id = F::rand();
        let primary_index_id = F::rand();
        // generate rows tree with values in decreasing order. This is a simple trick to ensure
        // that min_secondary <= max_secondary when using custom query bounds in tests, as we will always
        // take max_secondary from the set of values of rows_tree_i and min_secondary from the set of values
        // of rows_tree_{i+j}
        let rows_tree_0_value_range = (U256::MAX / U256::from(2), U256::MAX);
        let rows_tree_1_value_range = (U256::MAX / U256::from(4), U256::MAX / U256::from(2));
        let rows_tree_2_value_range = (U256::MAX / U256::from(8), U256::MAX / U256::from(4));
        let rows_tree_3_value_range = (U256::MAX / U256::from(16), U256::MAX / U256::from(8));
        let rows_tree_4_value_range = (U256::ZERO, U256::MAX / U256::from(16));
        let rows_tree_0 = RowsTree::from(generate_test_tree(
            secondary_index_id,
            Some(rows_tree_0_value_range),
        ));
        let root = HashOutput::from(rows_tree_0.node_a.compute_node_hash(secondary_index_id));
        let node_0 = build_node(None, None, values[0], root, primary_index_id);
        let rows_tree_2 = RowsTree::from(generate_test_tree(
            secondary_index_id,
            Some(rows_tree_2_value_range),
        ));
        let root = HashOutput::from(rows_tree_2.node_a.compute_node_hash(secondary_index_id));
        let node_2 = build_node(None, None, values[2], root, primary_index_id);
        let rows_tree_4 = RowsTree::from(generate_test_tree(
            secondary_index_id,
            Some(rows_tree_4_value_range),
        ));
        let root = HashOutput::from(rows_tree_4.node_a.compute_node_hash(secondary_index_id));
        let node_4 = build_node(None, None, values[4], root, primary_index_id);
        let rows_tree_3 = RowsTree::from(generate_test_tree(
            secondary_index_id,
            Some(rows_tree_3_value_range),
        ));
        let root = HashOutput::from(rows_tree_3.node_a.compute_node_hash(secondary_index_id));
        let node_3 = build_node(
            Some(&node_2),
            Some(&node_4),
            values[3],
            root,
            primary_index_id,
        );
        let rows_tree_1 = RowsTree::from(generate_test_tree(
            secondary_index_id,
            Some(rows_tree_1_value_range),
        ));
        let root = HashOutput::from(rows_tree_1.node_a.compute_node_hash(secondary_index_id));
        let node_1 = build_node(
            Some(&node_0),
            Some(&node_3),
            values[1],
            root,
            primary_index_id,
        );

        // test consecutive rows in the same rows tree: check that node_C and node_G in rows_tree_1 are consecutive
        let path_1c = vec![(rows_tree_1.node_a, ChildPosition::Right)];
        let node_1b_hash =
            HashOutput::from(rows_tree_1.node_b.compute_node_hash(secondary_index_id));
        let siblings_1c = vec![Some(node_1b_hash)];
        let merkle_inputs_1c = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_1c,
            &siblings_1c,
            &rows_tree_1.node_c,
            [None, Some(rows_tree_1.node_g)],
        )
        .unwrap();
        let path_1g = vec![
            (rows_tree_1.node_c, ChildPosition::Right),
            (rows_tree_1.node_a, ChildPosition::Right),
        ];
        let siblings_1g = vec![None, Some(node_1b_hash)];
        let merkle_inputs_1g = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_1g,
            &siblings_1g,
            &rows_tree_1.node_g,
            [None, None],
        )
        .unwrap();
        let path_1 = vec![];
        let siblings_1 = vec![];
        let merkle_inputs_index_1 = MerklePathWithNeighborsGadget::<INDEX_TREE_MAX_DEPTH>::new(
            &path_1,
            &siblings_1,
            &node_1,
            [Some(node_0), Some(node_3)],
        )
        .unwrap();
        let circuit = TestConsecutiveRows {
            row_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_1c,
                first_node_info: rows_tree_1.node_c,
                second_node_path: merkle_inputs_1g,
                second_node_info: rows_tree_1.node_g,
                index_id: secondary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
            index_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_index_1,
                first_node_info: node_1,
                second_node_path: merkle_inputs_index_1, // they belong to the same node in the index tree
                second_node_info: node_1,
                index_id: primary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // test consecutive rows in different rows trees: check that node_G of rows_tree_1 and node_E of rows_tree_2
        // are consecutive
        let path_2e = vec![
            (rows_tree_2.node_d, ChildPosition::Left),
            (rows_tree_2.node_b, ChildPosition::Left),
            (rows_tree_2.node_a, ChildPosition::Left),
        ];
        let node_2f_hash =
            HashOutput::from(rows_tree_2.node_f.compute_node_hash(secondary_index_id));
        let node_2c_hash =
            HashOutput::from(rows_tree_2.node_c.compute_node_hash(secondary_index_id));
        let siblings_2e = vec![Some(node_2f_hash), None, Some(node_2c_hash)];
        let merkle_inputs_2e = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_2e,
            &siblings_2e,
            &rows_tree_2.node_e,
            [None, None], // it's a leaf node
        )
        .unwrap();
        let path_2 = vec![
            (node_3, ChildPosition::Left),
            (node_1, ChildPosition::Right),
        ];
        let node_0_hash = HashOutput::from(node_0.compute_node_hash(primary_index_id));
        let node_4_hash = HashOutput::from(node_4.compute_node_hash(primary_index_id));
        let siblings_2 = vec![Some(node_4_hash), Some(node_0_hash)];
        let merkle_inputs_index_2 = MerklePathWithNeighborsGadget::<INDEX_TREE_MAX_DEPTH>::new(
            &path_2,
            &siblings_2,
            &node_2,
            [None, None],
        )
        .unwrap();
        let circuit = TestConsecutiveRows {
            row_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_1g,
                first_node_info: rows_tree_1.node_g,
                second_node_path: merkle_inputs_2e,
                second_node_info: rows_tree_2.node_e,
                index_id: secondary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
            index_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_index_1,
                first_node_info: node_1,
                second_node_path: merkle_inputs_index_2,
                second_node_info: node_2,
                index_id: primary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // negative test: check that node_G of rows_tree_1 and node_F of rows_tree_2 are not consecutive
        let path_2f = vec![
            (rows_tree_2.node_d, ChildPosition::Right),
            (rows_tree_2.node_b, ChildPosition::Left),
            (rows_tree_2.node_a, ChildPosition::Left),
        ];
        let node_2e_hash =
            HashOutput::from(rows_tree_2.node_e.compute_node_hash(secondary_index_id));
        let siblings_2f = vec![Some(node_2e_hash), None, Some(node_2c_hash)];
        let merkle_inputs_2f = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_2f,
            &siblings_2f,
            &rows_tree_2.node_f,
            [None, None], // it's a leaf node
        )
        .unwrap();
        let circuit = TestConsecutiveRows {
            row_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_1g,
                first_node_info: rows_tree_1.node_g,
                second_node_path: merkle_inputs_2f,
                second_node_info: rows_tree_2.node_f,
                index_id: secondary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
            index_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_index_1,
                first_node_info: node_1,
                second_node_path: merkle_inputs_index_2,
                second_node_info: node_2,
                index_id: primary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are not consecutive
        assert!(!proof.public_inputs[0].try_into_bool().unwrap());

        // negative test: check that node_C of rows_tree_1 and node_E of rows_tree_2 are not consecutive
        let path_1c = vec![(rows_tree_1.node_a, ChildPosition::Right)];
        let siblings_1c = vec![Some(node_1b_hash)];
        let merkle_inputs_1c = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_1c,
            &siblings_1c,
            &rows_tree_1.node_c,
            [None, Some(rows_tree_1.node_g)],
        )
        .unwrap();
        let circuit = TestConsecutiveRows {
            row_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_1c,
                first_node_info: rows_tree_1.node_c,
                second_node_path: merkle_inputs_2e,
                second_node_info: rows_tree_2.node_e,
                index_id: secondary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
            index_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_index_1,
                first_node_info: node_1,
                second_node_path: merkle_inputs_index_2,
                second_node_info: node_2,
                index_id: primary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are not consecutive
        assert!(!proof.public_inputs[0].try_into_bool().unwrap());

        // negative test: check that node_G of rows_tree_1 and node_E of rows_tree_3 are not consecutive
        let path_3e = vec![
            (rows_tree_3.node_d, ChildPosition::Left),
            (rows_tree_3.node_b, ChildPosition::Left),
            (rows_tree_3.node_a, ChildPosition::Left),
        ];
        let node_3f_hash =
            HashOutput::from(rows_tree_3.node_f.compute_node_hash(secondary_index_id));
        let node_3c_hash =
            HashOutput::from(rows_tree_3.node_c.compute_node_hash(secondary_index_id));
        let siblings_3e = vec![Some(node_3f_hash), None, Some(node_3c_hash)];
        let merkle_inputs_3e = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_3e,
            &siblings_3e,
            &rows_tree_3.node_e,
            [None, None], // it's a leaf node
        )
        .unwrap();
        let path_3 = vec![(node_1, ChildPosition::Right)];
        let siblings_3 = vec![Some(node_0_hash)];
        let merkle_inputs_index_3 = MerklePathWithNeighborsGadget::<INDEX_TREE_MAX_DEPTH>::new(
            &path_3,
            &siblings_3,
            &node_3,
            [Some(node_2), Some(node_4)],
        )
        .unwrap();
        let circuit = TestConsecutiveRows {
            row_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_1g,
                first_node_info: rows_tree_1.node_g,
                second_node_path: merkle_inputs_3e,
                second_node_info: rows_tree_3.node_e,
                index_id: secondary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
            index_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_index_1,
                first_node_info: node_1,
                second_node_path: merkle_inputs_index_3,
                second_node_info: node_3,
                index_id: primary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are not consecutive
        assert!(!proof.public_inputs[0].try_into_bool().unwrap());

        // test nodes at range boundaries across different rows trees: check that node_A of rows_tree_1 and node_D
        // of rows_tree_2 can be consecutive if the range on secondary index is [node_2D.value, node_1A.value]
        let path_1a = vec![];
        let siblings_1a = vec![];
        let merkle_inputs_1a = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_1a,
            &siblings_1a,
            &rows_tree_1.node_a,
            [Some(rows_tree_1.node_b), Some(rows_tree_1.node_c)],
        )
        .unwrap();
        let path_2d = vec![
            (rows_tree_2.node_b, ChildPosition::Left),
            (rows_tree_2.node_a, ChildPosition::Left),
        ];
        let siblings_2d = vec![None, Some(node_2c_hash)];
        let merkle_inputs_2d = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_2d,
            &siblings_2d,
            &rows_tree_2.node_d,
            [Some(rows_tree_2.node_e), Some(rows_tree_2.node_f)],
        )
        .unwrap();
        let circuit = TestConsecutiveRows {
            row_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_1a,
                first_node_info: rows_tree_1.node_a,
                second_node_path: merkle_inputs_2d,
                second_node_info: rows_tree_2.node_d,
                index_id: secondary_index_id,
                min_query_bound: Some(rows_tree_2.node_d.value),
                max_query_bound: Some(rows_tree_1.node_a.value),
            },
            index_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_index_1,
                first_node_info: node_1,
                second_node_path: merkle_inputs_index_2,
                second_node_info: node_2,
                index_id: primary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // negative test: check that node_A of rows_tree_1 and node_D of rows_tree_2 are not be consecutive
        // with a different range on secondary index
        let circuit = TestConsecutiveRows {
            row_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_1a,
                first_node_info: rows_tree_1.node_a,
                second_node_path: merkle_inputs_2d,
                second_node_info: rows_tree_2.node_d,
                index_id: secondary_index_id,
                min_query_bound: Some(rows_tree_2.node_e.value),
                max_query_bound: Some(rows_tree_1.node_a.value),
            },
            index_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_index_1,
                first_node_info: node_1,
                second_node_path: merkle_inputs_index_2,
                second_node_info: node_2,
                index_id: primary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are not consecutive
        assert!(!proof.public_inputs[0].try_into_bool().unwrap());

        // test rows tree without matching rows: check that node_A of rows_tree_1 is consecutive with node_G
        // of rows_tree_2, if all the nodes in rows_tree_2 store values smaller than the query range
        let circuit = TestConsecutiveRows {
            row_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_1a,
                first_node_info: rows_tree_1.node_a,
                second_node_path: merkle_inputs_2d,
                second_node_info: rows_tree_2.node_d,
                index_id: secondary_index_id,
                min_query_bound: Some(rows_tree_1.node_f.value),
                max_query_bound: Some(rows_tree_1.node_a.value),
            },
            index_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_index_1,
                first_node_info: node_1,
                second_node_path: merkle_inputs_index_2,
                second_node_info: node_2,
                index_id: primary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // test rows tree without matching rows: check that node_A of rows_tree_1 is consecutive with node_D
        // of rows_tree_2, if all the nodes in rows_tree_1 store values bigger than the query range
        let circuit = TestConsecutiveRows {
            row_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_1a,
                first_node_info: rows_tree_1.node_a,
                second_node_path: merkle_inputs_2d,
                second_node_info: rows_tree_2.node_d,
                index_id: secondary_index_id,
                min_query_bound: Some(rows_tree_2.node_d.value),
                max_query_bound: Some(rows_tree_2.node_a.value),
            },
            index_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_index_1,
                first_node_info: node_1,
                second_node_path: merkle_inputs_index_2,
                second_node_info: node_2,
                index_id: primary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // test rows tree without matching rows: check that we can merge 2 rows in rows trees where all
        // the values are smaller than the query range. Node_G of rows_tree_1 is consecutive with node_E of
        // rows_tree_2, if the query range is defined over values of rows_tree_0 (which are all bigger than
        // other rows trees by construction)
        let circuit = TestConsecutiveRows {
            row_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_1g,
                first_node_info: rows_tree_1.node_g,
                second_node_path: merkle_inputs_2e,
                second_node_info: rows_tree_2.node_e,
                index_id: secondary_index_id,
                min_query_bound: Some(rows_tree_0.node_d.value),
                max_query_bound: Some(rows_tree_0.node_a.value),
            },
            index_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_index_1,
                first_node_info: node_1,
                second_node_path: merkle_inputs_index_2,
                second_node_info: node_2,
                index_id: primary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // test rows tree without matching rows: check that we can merge 2 rows in rows trees where all
        // the values are bigger than the query range. Node_G of rows_tree_1 is consecutive with node_E of
        // rows_tree_2, if the query range is defined over values of rows_tree_4 (which are all smaller than
        // the other rows trees by construction)
        let circuit = TestConsecutiveRows {
            row_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_1g,
                first_node_info: rows_tree_1.node_g,
                second_node_path: merkle_inputs_2e,
                second_node_info: rows_tree_2.node_e,
                index_id: secondary_index_id,
                min_query_bound: Some(rows_tree_4.node_d.value),
                max_query_bound: Some(rows_tree_4.node_a.value),
            },
            index_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_index_1,
                first_node_info: node_1,
                second_node_path: merkle_inputs_index_2,
                second_node_info: node_2,
                index_id: primary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // negative test: check that node_G of rows_tree_1 and node_E of rows_tree_2 are not consecutive
        // if the index tree node storing rows_tree_2 is out of the query range over the primary index
        let circuit = TestConsecutiveRows {
            row_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_1g,
                first_node_info: rows_tree_1.node_g,
                second_node_path: merkle_inputs_2e,
                second_node_info: rows_tree_2.node_e,
                index_id: secondary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
            index_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_index_1,
                first_node_info: node_1,
                second_node_path: merkle_inputs_index_2,
                second_node_info: node_2,
                index_id: primary_index_id,
                min_query_bound: None,
                max_query_bound: Some(node_1.value),
            },
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are not consecutive
        assert!(!proof.public_inputs[0].try_into_bool().unwrap());

        // negative test: check that node_G of rows_tree_1 and node_E of rows_tree_2 are not consecutive
        // if the index tree node storing rows_tree_1 is out of the query range over the primary index
        let circuit = TestConsecutiveRows {
            row_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_1g,
                first_node_info: rows_tree_1.node_g,
                second_node_path: merkle_inputs_2e,
                second_node_info: rows_tree_2.node_e,
                index_id: secondary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
            index_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_index_1,
                first_node_info: node_1,
                second_node_path: merkle_inputs_index_2,
                second_node_info: node_2,
                index_id: primary_index_id,
                min_query_bound: Some(node_2.value),
                max_query_bound: None,
            },
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are not consecutive
        assert!(!proof.public_inputs[0].try_into_bool().unwrap());
    }
}
