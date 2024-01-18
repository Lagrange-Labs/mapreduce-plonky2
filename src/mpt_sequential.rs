use crate::array::VectorWire;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::keccak::{compute_size_with_padding, KeccakCircuit, OutputHash};

/// a simple alias to keccak::compute_size_with_padding to make the code a bit
/// more tiny with all these const generics
#[allow(non_snake_case)]
const fn PADDING_LEN(d: usize) -> usize {
    compute_size_with_padding(d)
}
/// Circuit that simoply proves the inclusion of a value inside a MPT tree.
/// * DEPTH is the maximal depth of the tree. If the tree is smaller, the circuit
/// will continue proving for "imaginary" nodes
/// * NODE_LEN is the max length of a node in the list of MPT nodes that form
/// the MPT proof. For example, in storage trie, a leaf is 32 bytes max, and a
/// branch node can be up to 32 * 17 = 544 bytes.
///     - Note since it uses keccak, the array being hashed is larger because
/// keccak requires padding.
#[derive(Clone, Debug)]
struct Circuit<const DEPTH: usize, const NODE_LEN: usize> {}

struct Wires<const DEPTH: usize, const NODE_LEN: usize>
where
    [(); PADDING_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    /// a vector of buffers whose size is the padded size of the maximum node length
    /// the padding may occur anywhere in the array but it can fit the maximum node size
    /// NOTE: this makes the code a bit harder grasp at first, but it's a straight
    /// way to define everything according to max size of the data and
    /// "not care" about the padding size (almost!)
    nodes: [VectorWire<{ PADDING_LEN(NODE_LEN) }>; DEPTH],

    /// in the case of a fixed circuit, the actual tree depth might be smaller.
    /// In this case, we set false on the part of the path we should not process.
    /// NOTE: for node at index i in the path, the boolean indicating if we should
    /// process it is at index i-1
    should_process: [BoolTarget; DEPTH - 1],
    /// At each intermediate node up to the root, we should find the hash of the children
    /// in its byte representation. That array indicates where the hash is located in the
    /// node.
    /// NOTE: for node at index  i in the path, the index where to find the children hash is
    /// located at index i-1.
    index_hashes: [Target; DEPTH - 1],
}

impl<const DEPTH: usize, const NODE_LEN: usize> Circuit<DEPTH, NODE_LEN>
where
    [(); PADDING_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
    // bound required from keccak
    [(); PADDING_LEN(NODE_LEN) / 4]:,
{
    pub fn build_from_leaf_array<F, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        leaf: &VectorWire<{ PADDING_LEN(NODE_LEN) }>,
    ) -> (OutputHash, Wires<DEPTH, NODE_LEN>)
    where
        F: RichField + Extendable<D>,
    {
        let should_process: [BoolTarget; DEPTH - 1] =
            core::array::from_fn(|_| b.add_virtual_bool_target_safe());
        let index_hashes: [Target; DEPTH - 1] = core::array::from_fn(|_| b.add_virtual_target());
        // nodes should be ordered from leaf to root and padded at the end
        // depth -1 because we already are given the leaf
        let nodes: [VectorWire<_>; DEPTH] = std::iter::once(leaf.clone())
            .chain((0..DEPTH - 1).map(|_| VectorWire::<{ PADDING_LEN(NODE_LEN) }>::new(b)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        // hash the leaf first
        let mut last_hash_output =
            KeccakCircuit::<{ PADDING_LEN(NODE_LEN) }>::hash_vector(b, leaf).output_array;
        // we skip the first node which is the leaf
        let t = b._true();
        for i in 1..DEPTH {
            let is_real = should_process[i - 1];
            // hash the next node first. We do this so we can get the U32 equivalence of the node
            let hash_wires = KeccakCircuit::<{ PADDING_LEN(NODE_LEN) }>::hash_vector(b, &nodes[i]);
            // look if hash is inside the node (in u32 format)
            let at = index_hashes[i];
            let found_hash_in_parent = hash_wires
                .padded_u32 // this is the node but in u32 format
                .contains_subarray(&last_hash_output, at, b);

            // if we don't have to process it, then circuit should never fail at that step
            // otherwise, we should always enforce finding the hash in the parent node
            let is_parent = b.select(is_real, found_hash_in_parent.target, t.target);
            b.connect(is_parent, t.target);

            // and select whether we should update or not
            last_hash_output = hash_wires
                .output_array
                .select(is_real, &last_hash_output, b);
        }
        (
            last_hash_output,
            Wires {
                nodes,
                should_process,
                index_hashes,
            },
        )
    }
}
