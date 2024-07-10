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
///                  h3 (h1, h5)                         h11 (h9, empty_hash) <--- level-3
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

    let total_len = input_ids.len();

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
            if item_index >= total_len {
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
