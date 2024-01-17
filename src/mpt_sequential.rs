use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::PartialWitness,
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    array::{Array, ArrayWire},
    circuit::UserCircuit,
    keccak::{compute_size_with_padding, KeccakCircuit, OutputHash},
};

/// a simple alias to keccak::compute_size_with_padding to make the code a bit
/// more tiny with all these const generics
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
struct Circuit<const DEPTH: usize, const NODE_LEN: usize>
where
    [(); PADDING_LEN(NODE_LEN)]:,
{
    /// a vector of buffers whose size is the padded size of the maximum node length
    /// the padding may occur anywhere in the array but it can fit the maximum node size
    /// NOTE: this makes the code a bit harder grasp at first, but it's a straight
    /// way to define everything according to max size of the data and
    /// "not care" about the padding size (almost!)
    nodes: Vec<Array<{ PADDING_LEN(NODE_LEN) }>>,
}

struct Wires<const DEPTH: usize>
where
    [(); DEPTH - 1]:,
{
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
{
    pub fn build_from_leaf_array<F, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        leaf: &ArrayWire<{ PADDING_LEN(NODE_LEN) }>,
    ) -> (OutputHash, Wires<DEPTH>)
    where
        F: RichField + Extendable<D>,
    {
        let should_process: [BoolTarget; DEPTH - 1] =
            core::array::from_fn(|_| b.add_virtual_bool_target_safe());
        let index_hashes: [Target; DEPTH - 1] = core::array::from_fn(|_| b.add_virtual_target());
        // nodes should be ordered from leaf to root and padded at the end
        // depth -1 because we already are given the leaf
        let nodes = (0..DEPTH - 1)
            .map(|_| ArrayWire::<{ PADDING_LEN(NODE_LEN) }>::new(b))
            .collect::<Vec<_>>();
        // hash the leaf first
        let mut last_hash =
            KeccakCircuit::<{ PADDING_LEN(NODE_LEN) }>::build_from_array(b, leaf).output_array;
        // we skip the first node which is the leaf
        let t = b._true();
        for i in 1..DEPTH {
            let is_real = should_process[i - 1];
            // look if hash is inside the node
            // XXX TODO
            let found_hash = b._true();

            // if we don't have to process it, then circuit should never fail at that step
            // otherwise, we should always enforce finding the hash in the parent node
            let link = b.select(is_real, found_hash.target, t.target);
            b.connect(link, t.target);

            // hash the next node
            let new_hash =
                KeccakCircuit::<{ PADDING_LEN(NODE_LEN) }>::build_from_array(b, &nodes[i])
                    .output_array;
            // and select whether we should update or not
            last_hash = new_hash.select(is_real, &last_hash, b);
        }
        (
            last_hash,
            Wires {
                should_process,
                index_hashes,
            },
        )
    }

    pub fn prove<F: RichField>(&self, pw: PartialWitness<F>) {}
}

struct CircuitWires;
