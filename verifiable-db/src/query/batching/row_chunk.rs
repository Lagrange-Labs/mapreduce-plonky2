//! This module contains data structures and gadgets employed to build and aggregate
//! row chunks. A row chunk is a set of rows that have already been aggregated 
//! and whose rows are all proven to be consecutive. The first and last rows in
//! the chunk are labelled as the `left_boundary_row` and the `right_boundary_row`,
//! respectively, and are the rows employed to aggregate 2 different chunks.

use mp2_common::{types::CBuilder, u256::{CircuitBuilderU256, UInt256Target}, utils::HashBuilder, F};
use plonky2::{hash::hash_types::HashOutTarget, iop::target::BoolTarget, field::types::Field};

use crate::query::{merkle_path::NeighborInfoTarget, universal_circuit::universal_query_gadget::UniversalQueryOutputWires};


/// Data structure containing the wires representing the data realted to the node of 
/// the row/index tree containing a row that is on the boundary of a row chunk. 
#[derive(Clone, Debug)]
pub(crate) struct BoundaryRowNodeInfoTarget {
    /// Hash of the node storing the row in the row/index tree
    pub(crate) end_node_hash: HashOutTarget,
    /// Data about the predecessor of end_node in the row/index tree
    pub(crate) predecessor_info: NeighborInfoTarget,
    /// Data about the predecessor of end_node in the row/index tree
    pub(crate) successor_info: NeighborInfoTarget,
}

/// Data structure containing the `BoundaryRowNodeInfoTarget` wires for the nodes
/// realted to a given boundary row. In particular, it contains the 
/// `BoundaryRowNodeInfoTarget` related to the following nodes:
/// - `row_node`: the node of the rows tree containing the given boundary row
/// - `index_node`: the node of the index tree that stores the rows tree containing
///     `row_node` 
pub(crate) struct BoundaryRowData {
    row_node_info: BoundaryRowNodeInfoTarget,
    index_node_info: BoundaryRowNodeInfoTarget,
}

/// Data structure containing the wires associated to a given row chunk
pub(crate) struct RowChunkData<
    const MAX_NUM_RESULTS: usize,
>
{
    left_boundary_row: BoundaryRowData,
    right_boundary_row: BoundaryRowData,
    chunk_outputs: UniversalQueryOutputWires<MAX_NUM_RESULTS>,
}

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
    let bigger_than_min = b.is_less_or_equal_than_u256(min_query_bound, &first_node_successor_value);
    are_consecutive = b.and(are_consecutive, bigger_than_min);
    // determine whether the successor (if any) of the first node stores a value in the query range or not; 
    // note that, since we previously checked that such value is >= min_query_bound,
    // we only need to check whether this value is not dummy (i.e., if the successor exists) and if
    // such value is <= max_query_bound
    let smaller_than_max = b.is_less_or_equal_than_u256(first_node_successor_value, &max_query_bound);
    let first_node_succ_in_range = b.and(smaller_than_max, first.successor_info.is_found);
    // if first_node_succ_in_range is true, and the successor of the first node was found in the path from 
    // such node to the root of the tree, then the hash of successor node will be placed in 
    // `first.successor_info.hash` by `MerklePathWithNeighborsGadget: therefore, we can check that `second` 
    // is consecutive of `first` by checking that `first.successor_info.hash` is the hash of the second node;
    // otherwise, we cannot check right now that the 2 nodes are consecutive, we will do it later
    let check_are_consecutive = b.and(first_node_succ_in_range, first.successor_info.is_in_path);
    let is_second_node_successor = b.hash_eq(
        &first.successor_info.hash, 
        &second.end_node_hash,
    );
    // update are_consecutive as `are_consecutive && is_second_node_successor`` if `check_are_consecutive` is true 
    let new_are_consecutive = b.and(are_consecutive, is_second_node_successor);
    are_consecutive = BoolTarget::new_unsafe(
        b.select(check_are_consecutive, new_are_consecutive.target, are_consecutive.target)
    );
    // we now look at the predecessor of second node, matching it with first node in case the 
    // predecessor is found in the path of second node in the tree
    let second_node_predecessor_value = &second.predecessor_info.value;
    // ensure that we don't prove nodes outside of the range: the predecessor of the second 
    // node must store a value smaller that `max_query_bound``
    let smaller_than_max = b.is_less_or_equal_than_u256(second_node_predecessor_value, &max_query_bound);
    are_consecutive = b.and(are_consecutive, smaller_than_max);
    // determine whether the predecessor (if any) of the second node stores a value in the query range or not; 
    // note that, since we previously checked that such value is <= max_query_bound,
    // we only need to check whether this value is not dummy (i.e., if the predecessor exists) and if
    // such value is >= min_query_bound
    let bigger_than_min = b.is_less_or_equal_than_u256(min_query_bound, &second_node_predecessor_value);
    let second_node_pred_in_range = b.and(bigger_than_min, second.predecessor_info.is_found);
    // if second_node_pred_in_range is true, and the predecessor of the second node was found in the path from 
    // such node to the root of the tree, then the hash of predecessor node will be placed in 
    // `second..predecessor_info.hash` by `MerklePathWithNeighborsGadget: therefore, we can check that `second` 
    // is consecutive of `first` by checking that `second.predecessor_info.hash` is the hash of the first node;
    // otherwise, we cannot check right now that the 2 nodes are consecutive, and it necessarily means we have 
    // already done it before when checking that the successor of first node was the second node
    let check_are_consecutive = b.and(second_node_pred_in_range, second.predecessor_info.is_in_path);
    let is_second_node_successor = b.hash_eq(
        &second.predecessor_info.hash, 
        &first.end_node_hash,
    );
    // update are_consecutive as `are_consecutive && is_second_node_successor`` if `check_are_consecutive` is true 
    let new_are_consecutive = b.and(are_consecutive, is_second_node_successor);
    are_consecutive = BoolTarget::new_unsafe(
        b.select(check_are_consecutive, new_are_consecutive.target, are_consecutive.target)
    );

    // lastly, check that either successor of first node is located in the path, or the predecessor of second node
    // is located in the path, which is necessarily true if the 2 nodes are consecutive. Note that we need to enforce
    // this always if we need to "strictly" prove that 2 nodes are consecutive, which happens in the following cases:
    // - if nodes are in the index tree
    // - if nodes are in a rows tree, but `first_node_succ_in_range` is true. Indeed, if the successor of first node
    //   is out of range or doesn't exist, then it means that second node belongs to another rows tree, and so it cannot
    //   be a successor of first node in the same rows tree
    let either_is_in_path = b.or(first.successor_info.is_in_path, second.predecessor_info.is_in_path);

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
        let range_flags_sum = b.add(first_node_succ_in_range.target, second_node_pred_in_range.target);
        let range_flags_xor = b.arithmetic(
            F::NEG_ONE+F::NEG_ONE, 
            F::ONE, 
            first_node_succ_in_range.target, 
            second_node_pred_in_range.target, 
            range_flags_sum,
        );
        // then, `are_consecutive = are_consecutive AND NOT(range_flags_xor) = are_consecutive - are_consecutive*range_flags_xor`
        are_consecutive = BoolTarget::new_unsafe(
            b.arithmetic(
                F::NEG_ONE, 
                F::ONE, 
                are_consecutive.target, 
                range_flags_xor, 
                are_consecutive.target
            ));
        // in case of nodes in a rows tree, then we need to enforce that second is the successor of first only
        // if the nodes are in the same rows tree, that is if `first_node_succ_in_range` is true
        let new_are_consecutive = b.and(are_consecutive, either_is_in_path);
        are_consecutive = BoolTarget::new_unsafe(
            b.select(first_node_succ_in_range, new_are_consecutive.target, are_consecutive.target)
        );
    }

    (are_consecutive, first_node_succ_in_range)
}

pub(crate) fn are_consecutive_rows(
    b: &mut CBuilder,
    first: &BoundaryRowData,
    second: &BoundaryRowData,
    min_primary: &UInt256Target,
    max_primary: &UInt256Target,
    min_secondary: &UInt256Target,
    max_secondary: &UInt256Target,
) -> BoolTarget {
    let (
        mut are_consecutive, 
        first_row_succ_in_range, 
    ) = are_consecutive_nodes(
        b, 
        &first.row_node_info, 
        &second.row_node_info, 
        min_secondary, 
        max_secondary,
        true,
    );
    // at this stage we checked that the rows tree nodes storing first and second row are consecutive; we need
    // to check also index tree consistency.
    // if first_row_succ_in_range is true, then both the rows must be in the same rows tree; so, we simply
    // check this and we are done
    let is_same_rows_tree = b.hash_eq(
        &first.index_node_info.end_node_hash, 
        &second.index_node_info.end_node_hash
    );
   
    // otherwise, if the rows are in different rows trees, we need to check that they are stored in subsequent
    // rows trees
    let (are_index_nodes_consecutive, _) = are_consecutive_nodes(
        b, 
        &first.index_node_info, 
        &second.index_node_info, 
        &min_primary, 
        &max_primary,
        false,
    );
    // compute the flag to be accumulated in `are_consecutive`, depending on whether the 2 rows are in the same
    // rows tree or not (i.e., whether first_row_succ_in_range is true)
    let index_tree_check = BoolTarget::new_unsafe(
    b.select(first_row_succ_in_range, is_same_rows_tree.target, are_index_nodes_consecutive.target)
    );
    b.and(are_consecutive, index_tree_check)
}

#[cfg(test)]
mod tests {
    use std::array;

    use alloy::primitives::U256;
    use mp2_common::{types::HashOutput, u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256}, utils::TryIntoBool, C, D, F};
    use mp2_test::{circuit::{self, run_circuit, UserCircuit}, utils::gen_random_u256};
    use plonky2::{field::types::Sample, hash::hash_types::HashOutTarget, iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}}, plonk::circuit_builder::CircuitBuilder};
    use rand::thread_rng;

    use crate::query::{aggregation::{ChildPosition, NodeInfo}, merkle_path::{tests::{build_node, generate_test_tree}, EndNodeInputs, MerklePathWithNeighborsGadget, MerklePathWithNeighborsTargetInputs}};

    use super::{are_consecutive_nodes, are_consecutive_rows, BoundaryRowData, BoundaryRowNodeInfoTarget};

    const ROW_TREE_MAX_DEPTH: usize = 10;
    const INDEX_TREE_MAX_DEPTH: usize = 15;

    #[derive(Clone, Debug)]
    struct TestConsecutiveNodes<
        const ROWS_TREE_NODES: bool,
        const MAX_DEPTH: usize,
    > 
    where [(); MAX_DEPTH - 1]:,
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
    where [(); MAX_DEPTH - 1]:,
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

    impl<
        const MAX_DEPTH: usize,
    > TestConsecutiveNodesWires<MAX_DEPTH> 
    where [(); MAX_DEPTH - 1]:,
    {
        fn new(c: &mut CircuitBuilder<F, D>) -> (Self, BoundaryRowNodeInfoTarget, BoundaryRowNodeInfoTarget) {
            let [first_node_value, second_node_value, 
            min_query_bound, max_query_bound] = c.add_virtual_u256_arr_unsafe();
            let [first_node_tree_hash, second_node_tree_hash] = array::from_fn(|_| 
                c.add_virtual_hash()
            );
            let index_id = c.add_virtual_target();
            let first_node_path = MerklePathWithNeighborsGadget::build(
                c, 
                first_node_value.clone(), 
                first_node_tree_hash, 
                index_id
            );
            let second_node_path = MerklePathWithNeighborsGadget::build(
                c, 
                second_node_value.clone(), 
                second_node_tree_hash, 
                index_id
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
                second_node
            )
        }
    }

    impl<
        const ROWS_TREE_NODES: bool,
        const MAX_DEPTH: usize,
    >  UserCircuit<F, D> for TestConsecutiveNodes<ROWS_TREE_NODES, MAX_DEPTH> 
    where [(); MAX_DEPTH - 1]:,
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
                (self.min_query_bound.unwrap_or(U256::ZERO), &wires.min_query_bound),
                (self.max_query_bound.unwrap_or(U256::MAX), &wires.max_query_bound),
            ].into_iter().for_each(|(value, target)| 
                pw.set_u256_target(target, value)
            );
            [
                (self.first_node_info.embedded_tree_hash, wires.first_node_tree_hash),
                (self.second_node_info.embedded_tree_hash, wires.second_node_tree_hash)
            ].into_iter().for_each(|(value, target)|
                pw.set_hash_target(target, value)
            );
            pw.set_target(wires.index_id, self.index_id);
        }
    }

    #[derive(Clone, Debug)]
    struct TestConsecutiveRows
    {
        row_tree_nodes: TestConsecutiveNodes<true, ROW_TREE_MAX_DEPTH>,
        index_tree_nodes: TestConsecutiveNodes<false, INDEX_TREE_MAX_DEPTH>,
    }


    #[derive(Clone, Debug)]
    struct TestConsecutiveRowsWires 
    {
        row_tree_nodes: TestConsecutiveNodesWires<ROW_TREE_MAX_DEPTH>,
        index_tree_nodes: TestConsecutiveNodesWires<INDEX_TREE_MAX_DEPTH>, 
    }

    impl UserCircuit<F, D> for TestConsecutiveRows {
        type Wires = TestConsecutiveRowsWires;
    
        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let (row_tree_nodes, first_row_node, second_row_node) = TestConsecutiveNodesWires::new(c);
            let (index_tree_nodes, first_index_node, second_index_node) = TestConsecutiveNodesWires::new(c);
            let first = BoundaryRowData {
                row_node_info: first_row_node,
                index_node_info: first_index_node,
            };
            let second = BoundaryRowData {
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
        let [node_A, node_B, node_C, node_D, node_E, node_F, node_G] = generate_test_tree(index_id);

        // test that nodes F and D are consecutive
        let path_F = vec![
            (node_D.clone(), ChildPosition::Right), // we start from the ancestor of the start node of the path
            (node_B.clone(), ChildPosition::Left),
            (node_A.clone(), ChildPosition::Left),
        ];
        let node_E_hash = HashOutput::try_from(node_E.compute_node_hash(index_id)).unwrap();
        let node_C_hash = HashOutput::try_from(node_C.compute_node_hash(index_id)).unwrap();
        let siblings_F = vec![Some(node_E_hash), None, Some(node_C_hash.clone())];
        let merkle_path_inputs_F = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_F,
            &siblings_F,
            &node_F,
            [None, None], // it's a leaf node
        )
        .unwrap();
        let path_D = vec![
            (node_B.clone(), ChildPosition::Left),
            (node_A.clone(), ChildPosition::Left),
        ];
        let siblings_D = vec![None, Some(node_C_hash.clone())];
        let merkle_path_inputs_D = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_D,
            &siblings_D,
            &node_D,
            [Some(node_E.clone()), Some(node_F.clone())],
        )
        .unwrap();
        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_D,
            first_node_info: node_D.clone(),
            second_node_path: merkle_path_inputs_F.clone(),
            second_node_info: node_F.clone(),
            index_id,
            min_query_bound: None,
            max_query_bound: None,
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // test that nodes A and C are consecutive
        let path_A = vec![];
        let siblings_A = vec![];
        let merkle_path_inputs_A = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_A,
            &siblings_A,
            &node_A,
            [Some(node_B.clone()), Some(node_C.clone())],
        )
        .unwrap();
        let path_C = vec![
            (node_A.clone(), ChildPosition::Right),
        ];
        let node_B_hash = HashOutput::try_from(node_B.compute_node_hash(index_id)).unwrap();
        let siblings_C = vec![Some(node_B_hash.clone())];
        let merkle_path_inputs_C = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_C,
            &siblings_C,
            &node_C,
            [None, Some(node_G.clone())],
        )
        .unwrap();

        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_A,
            first_node_info: node_A.clone(),
            second_node_path: merkle_path_inputs_C,
            second_node_info: node_C.clone(),
            index_id,
            min_query_bound: None,
            max_query_bound: None,
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // test that nodes F and B are consecutive
        let path_B = vec![
            (node_A.clone(), ChildPosition::Left),
        ];
        let siblings_B = vec![Some(node_C_hash.clone())];
        let merkle_path_inputs_B = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_B,
            &siblings_B,
            &node_B,
            [Some(node_D.clone()), None],
        )
        .unwrap();

        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_F.clone(),
            first_node_info: node_F.clone(),
            second_node_path: merkle_path_inputs_B,
            second_node_info: node_B.clone(),
            index_id,
            min_query_bound: None,
            max_query_bound: None,
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // negative test: E and F are not consecutive
        let path_E = vec![
            (node_D.clone(), ChildPosition::Left),
            (node_B.clone(), ChildPosition::Left),
            (node_A.clone(), ChildPosition::Left),
        ];
        let node_F_hash = HashOutput::try_from(node_F.compute_node_hash(index_id)).unwrap();
        let siblings_E = vec![Some(node_F_hash), None, Some(node_C_hash.clone())];
        let merkle_path_inputs_E = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_E,
            &siblings_E,
            &node_E,
            [None, None], // it's a leaf node
        )
        .unwrap();
        
        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_E,
            first_node_info: node_E.clone(),
            second_node_path: merkle_path_inputs_F,
            second_node_info: node_F.clone(),
            index_id,
            min_query_bound: None,
            max_query_bound: None,
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are not consecutive
        assert!(!proof.public_inputs[0].try_into_bool().unwrap());

        // negative test: A and B are not consecutive (wrong order)        
        let path_A = vec![];
        let siblings_A = vec![];
        let merkle_path_inputs_A = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_A,
            &siblings_A,
            &node_A,
            [Some(node_B.clone()), Some(node_C.clone())],
        )
        .unwrap();
        
        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_A,
            first_node_info: node_A.clone(),
            second_node_path: merkle_path_inputs_B,
            second_node_info: node_B.clone(),
            index_id,
            min_query_bound: None,
            max_query_bound: None,
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are not consecutive
        assert!(!proof.public_inputs[0].try_into_bool().unwrap());

        // but B and A are consecutive
        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_B,
            first_node_info: node_B.clone(),
            second_node_path: merkle_path_inputs_A,
            second_node_info: node_A.clone(),
            index_id,
            min_query_bound: None,
            max_query_bound: None,
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // check that if we are proving nodes in a rows tree, then we can prove that C and D are consecutive
        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_C,
            first_node_info: node_C.clone(),
            second_node_path: merkle_path_inputs_D,
            second_node_info: node_D.clone(),
            index_id,
            min_query_bound: Some(node_D.value),
            max_query_bound: Some(node_C.value),
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // instead, this is not possible if we are proving nodes in the index tree
        let circuit = TestConsecutiveNodes::<false, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_C,
            first_node_info: node_C.clone(),
            second_node_path: merkle_path_inputs_F,
            second_node_info: node_F.clone(),
            index_id,
            min_query_bound: Some(node_F.value),
            max_query_bound: Some(node_C.value),
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are not consecutive
        assert!(!proof.public_inputs[0].try_into_bool().unwrap());

        // check that if we are proving nodes in a rows tree, then we can prove that G and E are consecutive
        let path_G = vec![
            (node_C.clone(), ChildPosition::Right),
            (node_A.clone(), ChildPosition::Right),
        ];
        let siblings_G = vec![None, Some(node_B_hash.clone())];
        let merkle_path_inputs_G = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_G,
            &siblings_G,
            &node_G,
            [None, None],
        )
        .unwrap();
        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_G,
            first_node_info: node_G.clone(),
            second_node_path: merkle_path_inputs_E,
            second_node_info: node_E.clone(),
            index_id,
            min_query_bound: None,
            max_query_bound: None,
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

        // instead, this is not possible if we are proving nodes in the index tree
        let circuit = TestConsecutiveNodes::<false, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_G,
            first_node_info: node_G.clone(),
            second_node_path: merkle_path_inputs_E,
            second_node_info: node_E.clone(),
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
            first_node_path: merkle_path_inputs_C,
            first_node_info: node_C.clone(),
            second_node_path: merkle_path_inputs_E,
            second_node_info: node_E.clone(),
            index_id,
            min_query_bound: None,
            max_query_bound: None,
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are not consecutive
        assert!(!proof.public_inputs[0].try_into_bool().unwrap());

        // but check that C and E can be consecutive if they become at the boundaries of the range
        let circuit = TestConsecutiveNodes::<true, ROW_TREE_MAX_DEPTH> {
            first_node_path: merkle_path_inputs_C,
            first_node_info: node_C.clone(),
            second_node_path: merkle_path_inputs_E,
            second_node_info: node_E.clone(),
            index_id,
            min_query_bound: None,
            max_query_bound: Some(node_C.value),
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());
    }

    #[test]
    fn test_are_consecutive_rows() {
        // structure representing the nodes of a tree generated with `generate_test_tree`
        struct RowsTree {
            node_A: NodeInfo,
            node_B: NodeInfo,
            node_C: NodeInfo,
            node_D: NodeInfo,
            node_E: NodeInfo,
            node_F: NodeInfo,
            node_G: NodeInfo,
        }

        impl From<[NodeInfo; 7]> for RowsTree {
            fn from(value: [NodeInfo; 7]) -> Self {
                Self {
                    node_A: value[0],
                    node_B: value[1],
                    node_C: value[2],
                    node_D: value[3],
                    node_E: value[4],
                    node_F: value[5],
                    node_G: value[6],
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
        let mut values: [U256; 5] = array::from_fn(|_|
            gen_random_u256(rng)
        );
        values.sort();
        let secondary_index_id = F::rand();
        let primary_index_id = F::rand();
        let rows_tree_0 = RowsTree::from(generate_test_tree(secondary_index_id));
        let root = HashOutput::try_from(
            rows_tree_0.node_A.compute_node_hash(secondary_index_id)
        ).unwrap();
        let node_0 = build_node(
            None, 
            
            None, 
            values[0], 
            root, 
            primary_index_id
        );
        let rows_tree_2 = RowsTree::from(generate_test_tree(secondary_index_id));
        let root = HashOutput::try_from(
            rows_tree_2.node_A.compute_node_hash(secondary_index_id)
        ).unwrap();
        let node_2 = build_node(
            None, 
            
            None, 
            values[2], 
            root, 
            primary_index_id
        );
        let rows_tree_4 = RowsTree::from(generate_test_tree(secondary_index_id));
        let root = HashOutput::try_from(
            rows_tree_4.node_A.compute_node_hash(secondary_index_id)
        ).unwrap();
        let node_4 = build_node(
            None, 
            
            None, 
            values[4], 
            root, 
            primary_index_id
        );
        let rows_tree_3 = RowsTree::from(generate_test_tree(secondary_index_id));
        let root = HashOutput::try_from(
            rows_tree_3.node_A.compute_node_hash(secondary_index_id)
        ).unwrap();
        let node_3 = build_node(
            Some(&node_2), 
            
            Some(&node_4), 
            values[3], 
            root, 
            primary_index_id
        );
        let rows_tree_1 = RowsTree::from(generate_test_tree(secondary_index_id));
        let root = HashOutput::try_from(
            rows_tree_1.node_A.compute_node_hash(secondary_index_id)
        ).unwrap();
        let node_1 = build_node(
            Some(&node_0), 
            
            Some(&node_3), 
            values[1], 
            root, 
            primary_index_id
        );

        // test consecutive rows in the same rows tree: check that node_C and node_G in rows_tree_1 are consecutive
        let path_1C = vec![
            (rows_tree_1.node_A.clone(), ChildPosition::Right)
        ];
        let node_1B_hash = HashOutput::try_from(rows_tree_1.node_B.compute_node_hash(secondary_index_id)).unwrap();
        let siblings_1C = vec![Some(node_1B_hash.clone())];
        let merkle_inputs_1C = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_1C,
            &siblings_1C,
            &rows_tree_1.node_C,
            [None, Some(rows_tree_1.node_G.clone())],
        )
        .unwrap();
        let path_1G = vec![
            (rows_tree_1.node_C.clone(), ChildPosition::Right),
            (rows_tree_1.node_A.clone(), ChildPosition::Right)
        ];
        let siblings_1G = vec![None, Some(node_1B_hash)];
        let merkle_inputs_1G = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_1G,
            &siblings_1G,
            &rows_tree_1.node_G,
            [None, None],
        )
        .unwrap();
        let path_1 = vec![];
        let siblings_1 = vec![];
        let merkle_inputs_index_1 = MerklePathWithNeighborsGadget::<INDEX_TREE_MAX_DEPTH>::new(
            &path_1,
            &siblings_1,
            &node_1,
            [Some(node_0.clone()), Some(node_3.clone())],
        )
        .unwrap();
        let circuit = TestConsecutiveRows {
            row_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_1C,
                first_node_info: rows_tree_1.node_C.clone(),
                second_node_path: merkle_inputs_1G,
                second_node_info: rows_tree_1.node_G.clone(),
                index_id: secondary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
            index_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_index_1,
                first_node_info: node_1.clone(),
                second_node_path: merkle_inputs_index_1, // they belong to the same node in the index tree
                second_node_info: node_1.clone(),
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
        let path_2E = vec![
            (rows_tree_2.node_D.clone(), ChildPosition::Left),
            (rows_tree_2.node_B.clone(), ChildPosition::Left),
            (rows_tree_2.node_A.clone(), ChildPosition::Left),
        ];
        let node_2F_hash = HashOutput::try_from(rows_tree_2.node_F.compute_node_hash(secondary_index_id)).unwrap();
        let node_2C_hash = HashOutput::try_from(rows_tree_2.node_C.compute_node_hash(secondary_index_id)).unwrap();
        let siblings_2E = vec![Some(node_2F_hash), None, Some(node_2C_hash.clone())];
        let merkle_inputs_2E = MerklePathWithNeighborsGadget::<ROW_TREE_MAX_DEPTH>::new(
            &path_2E,
            &siblings_2E,
            &rows_tree_2.node_E,
            [None, None], // it's a leaf node
        )
        .unwrap();
        let path_2 = vec![
            (node_3.clone(), ChildPosition::Left),
            (node_1.clone(), ChildPosition::Right),
        ];
        let node_0_hash = HashOutput::try_from(node_0.compute_node_hash(primary_index_id)).unwrap();
        let node_4_hash = HashOutput::try_from(node_4.compute_node_hash(primary_index_id)).unwrap();
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
                first_node_path: merkle_inputs_1G,
                first_node_info: rows_tree_1.node_G.clone(),
                second_node_path: merkle_inputs_2E,
                second_node_info: rows_tree_2.node_E.clone(),
                index_id: secondary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
            index_tree_nodes: TestConsecutiveNodes {
                first_node_path: merkle_inputs_index_1,
                first_node_info: node_1.clone(),
                second_node_path: merkle_inputs_index_2,
                second_node_info: node_2.clone(),
                index_id: primary_index_id,
                min_query_bound: None,
                max_query_bound: None,
            },
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the nodes are consecutive
        assert!(proof.public_inputs[0].try_into_bool().unwrap());

    }

}