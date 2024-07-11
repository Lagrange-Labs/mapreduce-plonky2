//! Query circuit utilities

use mp2_common::{
    poseidon::empty_poseidon_hash,
    types::CBuilder,
    u256::UInt256Target,
    utils::{SelectHashBuilder, ToTargets},
    CHasher,
};
use plonky2::{
    hash::hash_types::HashOutTarget,
    iop::target::{BoolTarget, Target},
};
use std::iter;

/// Re-compute the root hash of the cells tree by the column identifiers and values
/// except the first 2 which correspond to the indexed columns.
/// The root hash is calculated recursively from the leaves to root by each level as:
/// node-0    n1    n2    n3    n4    n5    n6    n7    n8    n9    n10
///   |             |           |           |           |           |
///   |             |           |           |           |           |
/// hash-0          h2          h4          h6          h8          h10       <--- level-1 (leaves)
///     \         /              \         /             \         /
///      \       /                \       /               \       /
///     h1 (h0, h2)               h5 (h4, h6)             h9 (h8, h10)        <--- level-2
///                  \         /                             \
///                   \       /                               \
///                  h3 (h1, h5)                         h11 (h9)             <--- level-3
///                                \               /
///                                 \             /
///                                  \           /
///                                   h7 (h3, h11)                            <--- level-4 (root)
pub(crate) fn build_cells_tree(
    b: &mut CBuilder,
    input_values: &[UInt256Target],
    input_ids: &[Target],
    is_real_value: &[BoolTarget],
) -> HashOutTarget {
    let empty_hash = b.constant_hash(*empty_poseidon_hash());

    // Get the input length and ensure these array arguments must have the same length.
    let input_len = input_ids.len();
    assert_eq!(input_len, input_values.len());
    assert_eq!(input_len, is_real_value.len());

    // Initialize the leaves (of level-1) by the values in even positions.
    let mut nodes: Vec<_> = input_ids
        .iter()
        .zip(input_values)
        .zip(is_real_value)
        .step_by(2)
        .map(|((id, value), is_real)| {
            // H(H("") || H("") || id || value)
            let inputs: Vec<_> = empty_hash
                .elements
                .iter()
                .chain(empty_hash.elements.iter())
                .chain(iter::once(id))
                .cloned()
                .chain(value.to_targets())
                .collect();
            let hash = b.hash_n_to_hash_no_pad::<CHasher>(inputs);

            b.select_hash(*is_real, &hash, &empty_hash)
        })
        .collect();

    // Accumulate the hashes from leaves up to root, starting from level-2 and
    // the current leftmost node.
    let mut starting_index = 1;
    let mut level = 2;

    // Return the root hash when there's only one node.
    while nodes.len() > 1 {
        // Make the node length even by padding an empty hash.
        if nodes.len() % 2 != 0 {
            nodes.push(empty_hash);
        }

        let new_node_len = nodes.len() >> 1;
        for i in 0..new_node_len {
            // Calculate the item index which should be hashed for the current node.
            let item_index = starting_index + i * (1 << level);

            // It may occur at the last of this loop (as `h11` of the above example).
            if item_index >= input_len {
                nodes[i] = nodes[i * 2];
                continue;
            }

            // H(H(left_child) || H(right_child) || id || value)
            let inputs: Vec<_> = nodes[i * 2]
                .elements
                .iter()
                .chain(nodes[i * 2 + 1].elements.iter())
                .chain(iter::once(&input_ids[item_index]))
                .cloned()
                .chain(input_values[item_index].to_targets())
                .collect();
            let parent = b.hash_n_to_hash_no_pad::<CHasher>(inputs);

            // Save it to the re-used node vector.
            nodes[i] = b.select_hash(is_real_value[item_index], &parent, &nodes[i * 2]);
        }

        // Calculate the next level and starting index.
        starting_index += 1 << (level - 1);
        level += 1;

        // Truncate the node vector to the new length.
        nodes.truncate(new_node_len);
    }

    // Return the root hash.
    nodes[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use mp2_common::{poseidon::H, C, D, F};
    use mp2_test::{
        cells_tree::{compute_cells_tree_hash, TestCell, TestCellTarget},
        circuit::{run_circuit, UserCircuit},
    };
    use plonky2::{
        hash::hash_types::HashOut,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::config::Hasher,
    };
    use std::array;

    #[derive(Clone, Debug)]
    struct TestCellsTreeCircuit<const MAX_NUM_CELLS: usize> {
        real_num_cells: usize,
        input_cells: [TestCell; MAX_NUM_CELLS],
        exp_root_hash: HashOut<F>,
    }

    impl<const MAX_NUM_CELLS: usize> UserCircuit<F, D> for TestCellsTreeCircuit<MAX_NUM_CELLS> {
        // Input cell targets
        // + input real flag targets
        // + expected output root hash
        type Wires = (
            [TestCellTarget; MAX_NUM_CELLS],
            [BoolTarget; MAX_NUM_CELLS],
            HashOutTarget,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let input_cells = array::from_fn(|_| TestCell::build(b));
            let is_real_cell = array::from_fn(|_| b.add_virtual_bool_target_safe());
            let exp_root_hash = b.add_virtual_hash();

            // Compute the root hash of cells tree.
            let (input_ids, input_values): (Vec<_>, Vec<_>) =
                input_cells.iter().map(|c| (c.id, c.value.clone())).unzip();
            let real_root_hash = build_cells_tree(b, &input_values, &input_ids, &is_real_cell);

            // Check the output root hash.
            b.connect_hashes(real_root_hash, exp_root_hash);

            (input_cells, is_real_cell, exp_root_hash)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.input_cells
                .iter()
                .zip(wires.0.iter())
                .for_each(|(v, t)| v.assign(pw, t));
            wires
                .1
                .iter()
                .enumerate()
                .for_each(|(i, t)| pw.set_bool_target(*t, i < self.real_num_cells));
            pw.set_hash_target(wires.2, self.exp_root_hash);
        }
    }

    impl<const MAX_NUM_CELLS: usize> TestCellsTreeCircuit<MAX_NUM_CELLS> {
        fn new(mut input_cells: Vec<TestCell>) -> Self {
            let real_num_cells = input_cells.len();
            assert!(real_num_cells <= MAX_NUM_CELLS);

            // Compute the expected root hash of cells tree.
            let exp_root_hash = compute_cells_tree_hash(&input_cells);

            input_cells.resize(MAX_NUM_CELLS, TestCell::default());
            let input_cells = input_cells.try_into().unwrap();

            Self {
                real_num_cells,
                input_cells,
                exp_root_hash,
            }
        }
    }

    fn test_cells_tree_circuit<const MAX_NUM_CELLS: usize, const REAL_NUM_CELLS: usize>() {
        // Generate the random cell data.
        let test_cells = [0; REAL_NUM_CELLS].map(|_| TestCell::random()).to_vec();

        // Construct the test circuit.
        let test_circuit = TestCellsTreeCircuit::<MAX_NUM_CELLS>::new(test_cells);

        // Prove for the test circuit.
        run_circuit::<F, D, C, _>(test_circuit);
    }

    // c1 c2 c3 c4 c5 c6 c7
    // \     /     \     /
    //  \   /       \   /
    //    |           |
    //     \         /
    //      \       /
    //        root (c4)
    #[test]
    fn test_query_cells_tree_circuit_saturated() {
        const MAX_NUM_CELLS: usize = 13;
        const REAL_NUM_CELLS: usize = 7;

        test_cells_tree_circuit::<MAX_NUM_CELLS, REAL_NUM_CELLS>();
    }

    // c1 c2 c3 c4 c5
    // \     /     |
    //  \   /      |
    //    |        |
    //     \      /
    //      \    /
    //        root (c4)
    #[test]
    fn test_query_cells_tree_circuit_partial_unsaturated() {
        const MAX_NUM_CELLS: usize = 13;
        const REAL_NUM_CELLS: usize = 5;

        test_cells_tree_circuit::<MAX_NUM_CELLS, REAL_NUM_CELLS>();
    }

    // c1 c2 c3 c4 c5 c6 c7 c8
    // \     /     \     /
    //  \   /       \   /
    //    |           |
    //     \         /
    //      \       /
    //       \     /
    //          |
    //           \
    //            \
    //             \
    //              \
    //                  root (c8), has no right child
    #[test]
    fn test_query_cells_tree_circuit_completely_unsaturated() {
        const MAX_NUM_CELLS: usize = 15;
        const REAL_NUM_CELLS: usize = 8;

        test_cells_tree_circuit::<MAX_NUM_CELLS, REAL_NUM_CELLS>();
    }
}
