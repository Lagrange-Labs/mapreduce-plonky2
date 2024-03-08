//! Merkle tree recursive proof for the intermediate node.

use std::iter;

use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::state::BlockLinkingPublicInputs;

mod public_inputs;

#[cfg(test)]
mod tests;

pub(crate) use public_inputs::PublicInputs;

/// The wires structure of [NodeCircuit].
#[derive(Clone)]
pub struct NodeWires<'i> {
    block_linking: BlockLinkingPublicInputs<'i, Target>,
    left: HashOutTarget,
    right: HashOutTarget,
    root: HashOutTarget,
}

impl<'i> NodeWires<'i> {
    /// Returns an iterator with the following items, in sequence:
    ///
    /// - `p` The node constant prefix
    /// - `A` Smart contract address
    /// - `C` Merkle root of the storage database
    /// - `S` Storage slot of the variable holding the length
    /// - `M` Storage slot of the mapping
    ///
    /// Such iterator will be used to compute the root of the intermediate node.
    pub fn node_preimage<T, L, R>(
        prefix: T,
        left_sibling: L,
        right_sibling: R,
    ) -> impl Iterator<Item = T> + 'i
    where
        T: Clone + 'i,
        L: IntoIterator<Item = &'i T>,
        <L as IntoIterator>::IntoIter: 'i,
        R: IntoIterator<Item = &'i T>,
        <R as IntoIterator>::IntoIter: 'i,
    {
        iter::once(prefix)
            .chain(left_sibling.into_iter().cloned())
            .chain(right_sibling.into_iter().cloned())
    }
}

/// Circuit to prove the correct formation of the intermediate node.
///
/// Will take the [BlockLinkingPublicInputs] as argument.
///
/// # Circuit description
///
/// +----------------------------------------+
/// | previous node left sibling.merkle root +-------+
/// +----------------------------------------+       |
/// +-----------------------------------------+      |
/// | previous node right sibling.merkle root +--------+
/// +-----------------------------------------+      | |
/// +--------------------------+                     | |
/// | block linking.block hash +----------+          | |
/// +--------------------------+          |          | |
/// +----------------------------+        |          | |
/// | block linking.block number +--------|-+        | |
/// +----------------------------+        | |        | |
/// +-----------------------------------+ | |        | |
/// | block linking.previous block hash +-|-|-+      | |
/// +-----------------------------------+ | | |      | |
///                                       | | |      | |
/// +------------------+                  | | |      | |
/// | node.merkle root +------------------------+H(0,+,+)
/// +------------------+                  | | |
/// +-----------------+                   | | |
/// | node.block hash +-------------------+ | |
/// +-----------------+                     | |
/// +-------------------+                   | |
/// | node.block number +-------------------+ |
/// +-------------------+                     |
/// +--------------------------+              |
/// | node.previous block hash +--------------+
/// +--------------------------+
#[derive(Clone)]
pub struct NodeCircuit;

impl NodeCircuit {
    /// Composes the circuit structure by assigning the virtual targets and performing the
    /// constraints.
    pub fn build<'i, F, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        block_linking: BlockLinkingPublicInputs<'i, Target>,
        left_sibling: PublicInputs<'i, Target>,
        right_sibling: PublicInputs<'i, Target>,
    ) -> NodeWires<'i>
    where
        F: RichField + Extendable<D>,
    {
        let left = left_sibling.root();
        let right = right_sibling.root();
        let preimage =
            NodeWires::node_preimage(b.zero(), &left.elements, &right.elements).collect::<Vec<_>>();
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(preimage);

        let wires = NodeWires {
            block_linking,
            left,
            right,
            root,
        };

        PublicInputs::register(b, &wires);

        wires
    }
}
