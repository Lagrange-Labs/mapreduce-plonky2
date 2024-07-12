//! Cells tree utilities for query circuit

use itertools::Itertools;
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
use ryhope::{
    storage::memory::InMemory,
    tree::{sbbst, TreeTopology},
    MerkleTreeKvDb, NodePayload,
};
use serde::{Deserialize, Serialize};
use std::iter::once;

type CellTree = sbbst::Tree;
#[derive(Serialize, Deserialize, Debug, Clone)]
/// Empty payload used just to instantiate a dummy storage to employ `CellTree` methods
struct Payload(());
impl NodePayload for Payload {}
type CellStorage = InMemory<CellTree, Payload>;
type MerkleTree = MerkleTreeKvDb<CellTree, Payload, CellStorage>;

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
    // Get the input length and ensure these array arguments must have the same length.
    let input_len = input_ids.len();
    assert_eq!(input_len, input_values.len());
    assert_eq!(input_len, is_real_value.len());

    // we create a dummy storage representing a sbbst tree with `input_len` elements;
    // the storage is fake becuase we don't store anything in the nodes, as we are just
    // interested in the tree topology
    let fake_storage = MerkleTree::create((0, input_len), ()).unwrap();

    let root_key = fake_storage.tree().root().unwrap();
    build_cells_subtree_at_key(
        b,
        input_values,
        input_ids,
        is_real_value,
        &root_key,
        &fake_storage,
    )
}

fn build_cells_subtree_at_key(
    b: &mut CBuilder,
    input_values: &[UInt256Target],
    input_ids: &[Target],
    is_real_value: &[BoolTarget],
    key: &<CellTree as TreeTopology>::Key,
    fake_storage: &MerkleTree,
) -> HashOutTarget {
    let empty_hash = b.constant_hash(*empty_poseidon_hash());
    let node_context = fake_storage.node_context(&key).unwrap();
    let children = node_context
        .iter_children()
        .map(|child| {
            if let Some(child_key) = child {
                build_cells_subtree_at_key(
                    b,
                    input_values,
                    input_ids,
                    is_real_value,
                    &child_key,
                    fake_storage,
                )
            } else {
                empty_hash
            }
        })
        .collect_vec();
    assert_eq!(children.len(), 2);
    let node_key = key - 1; // sbbst stores key starting by 1, while slice starts from 0
    let node_hash = b.hash_n_to_hash_no_pad::<CHasher>(
        children
            .iter()
            .flat_map(|child_hash| child_hash.to_targets())
            .chain(once(input_ids[node_key]))
            .chain(input_values[node_key].to_targets())
            .collect(),
    );
    // if is_real_value[node_key] == true, then the hash of the node is the computed one, otherwise
    // we just propagate the hash of the left child
    b.select_hash(is_real_value[node_key], &node_hash, &children[0])
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
        async fn new(mut input_cells: Vec<TestCell>) -> Self {
            let real_num_cells = input_cells.len();
            assert!(real_num_cells <= MAX_NUM_CELLS);

            // Compute the expected root hash of cells tree.
            let exp_root_hash = compute_cells_tree_hash(&input_cells).await;

            input_cells.resize(MAX_NUM_CELLS, TestCell::default());
            let input_cells = input_cells.try_into().unwrap();

            Self {
                real_num_cells,
                input_cells,
                exp_root_hash,
            }
        }
    }

    async fn test_cells_tree_circuit<const MAX_NUM_CELLS: usize, const REAL_NUM_CELLS: usize>() {
        // Generate the random cell data.
        let test_cells = [0; REAL_NUM_CELLS].map(|_| TestCell::random()).to_vec();

        // Construct the test circuit.
        let test_circuit = TestCellsTreeCircuit::<MAX_NUM_CELLS>::new(test_cells).await;

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
    #[tokio::test]
    async fn test_query_cells_tree_circuit_saturated() {
        const MAX_NUM_CELLS: usize = 13;
        const REAL_NUM_CELLS: usize = 7;

        test_cells_tree_circuit::<MAX_NUM_CELLS, REAL_NUM_CELLS>().await;
    }

    // c1 c2 c3 c4 c5
    // \     /     |
    //  \   /      |
    //    |        |
    //     \      /
    //      \    /
    //        root (c4)
    #[tokio::test]
    async fn test_query_cells_tree_circuit_partial_unsaturated() {
        const MAX_NUM_CELLS: usize = 13;
        const REAL_NUM_CELLS: usize = 5;

        test_cells_tree_circuit::<MAX_NUM_CELLS, REAL_NUM_CELLS>().await;
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
    #[tokio::test]
    async fn test_query_cells_tree_circuit_completely_unsaturated() {
        const MAX_NUM_CELLS: usize = 15;
        const REAL_NUM_CELLS: usize = 8;

        test_cells_tree_circuit::<MAX_NUM_CELLS, REAL_NUM_CELLS>().await;
    }

    // c1 c2 c3 c4 c5 c6 c7 c8 c9
    // \     /     \     /     |
    //  \   /       \   /      |
    //    |           |        | Try to get c10 to trigger out of range for the cell array
    //     \         /         | (MAX_NUM = REAL_NUM = 9)
    //      \       /          |
    //       \     /           |
    //          |              |
    //           \            /
    //            \          /
    //             \        /
    //              \      /
    //                  root (c8)
    #[tokio::test]
    async fn test_query_cells_tree_circuit_index_out_of_range() {
        const MAX_NUM_CELLS: usize = 9;
        const REAL_NUM_CELLS: usize = 9;

        test_cells_tree_circuit::<MAX_NUM_CELLS, REAL_NUM_CELLS>().await;
    }

    // c1 c2 c3 c4 c5 c6 c7 c8 c9
    // \     /     \     /     |
    //  \   /       \   /      |
    //    |           |        | Try to get c10 which is a dummy cell
    //     \         /         | (MAX_NUM = 13, REAL_NUM = 9, c10 is padded)
    //      \       /          |
    //       \     /           |
    //          |              |
    //           \            /
    //            \          /
    //             \        /
    //              \      /
    //                  root (c8)
    #[tokio::test]
    async fn test_query_cells_tree_circuit_index_dummy_cell() {
        const MAX_NUM_CELLS: usize = 13;
        const REAL_NUM_CELLS: usize = 9;

        test_cells_tree_circuit::<MAX_NUM_CELLS, REAL_NUM_CELLS>().await;
    }
}
