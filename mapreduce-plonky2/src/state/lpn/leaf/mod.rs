//! Circuit to prove the correct formation of the leaf node and its intermediate nodes that
//! describes a Merkle opening.

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

/// Circuit to prove the correct formation of the leaf node.
///
/// Will take the [BlockLinkingPublicInputs] as argument.
///
/// # Circuit description
///
/// +--------------------------------------+
/// | block linking.smart contract address +---------+
/// +--------------------------------------+         |
/// +---------------------------------------------+  |
/// | block linking.merkle root of the storage db +--|-+
/// +---------------------------------------------+  | |
/// +------------------------------------------+     | |
/// | block linking.storage slot of the length +-----|-|-+
/// +------------------------------------------+     | | |
/// +-------------------------------------------+    | | |
/// | block linking.storage slot of the mapping +----|-|-|-+
/// +-------------------------------------------+    | | | |
/// +--------------------------+                     | | | |
/// | block linking.block hash +----------+          | | | |
/// +--------------------------+          |          | | | |
/// +----------------------------+        |          | | | |
/// | block linking.block number +--------|-+        | | | |
/// +----------------------------+        | |        | | | |
/// +-----------------------------------+ | |        | | | |
/// | block linking.previous block hash +-|-|-+      | | | |
/// +-----------------------------------+ | | |      | | | |
///                                       | | |      | | | |
/// +----------------+                    | | |      | | | |
/// | leaf.node root +--------------------------+H(1,+,+,+,+)
/// +----------------+                    | | |
/// +-----------------+                   | | |
/// | leaf.block hash +-------------------+ | |
/// +-----------------+                     | |
/// +-------------------+                   | |
/// | leaf.block number +-------------------+ |
/// +-------------------+                     |
/// +--------------------------+              |
/// | leaf.previous block hash +--------------+
/// +--------------------------+
#[derive(Clone)]
pub struct LeafCircuit;

impl LeafCircuit {
    /// Returns an iterator with the following items, in sequence:
    ///
    /// - `A` Smart contract address
    /// - `C` Merkle root of the storage database
    /// - `S` Storage slot of the variable holding the length
    /// - `M` Storage slot of the mapping
    ///
    /// Such iterator will be used to compute the root node of the leaf.
    pub fn node_preimage<'i, T: Clone>(
        prefix: T,
        block_linking: &'i BlockLinkingPublicInputs<'i, T>,
    ) -> impl Iterator<Item = T> + 'i {
        let a = block_linking.a().iter().cloned();
        let c = block_linking.merkle_root().iter().cloned();
        let s = iter::once(block_linking.s()[0].clone());
        let m = iter::once(block_linking.m()[0].clone());

        iter::once(prefix).chain(a).chain(c).chain(s).chain(m)
    }

    /// Composes the circuit structure by assigning the virtual targets and performing the
    /// constraints.
    ///
    /// The returned [HashOutTarget] will correspond to the Merkle root of the leaf.
    pub fn build<'i, F, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        block_linking: &BlockLinkingPublicInputs<'i, Target>,
    ) -> HashOutTarget
    where
        F: RichField + Extendable<D>,
    {
        let preimage = Self::node_preimage(b.one(), &block_linking).collect::<Vec<_>>();
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(preimage);

        PublicInputs::register(b, &root, block_linking);

        root
    }
}
