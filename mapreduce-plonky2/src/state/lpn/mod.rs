//! Circuit to prove the correct formation of the leaf node and its intermediate nodes that
//! describes a Merkle opening.

use std::iter;

use anyhow::Context;
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField},
        hashing::hash_n_to_hash_no_pad,
        poseidon::{PoseidonHash, PoseidonPermutation},
    },
    iop::{
        target::Target,
        witness::{PartialWitness, Witness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::state::BlockLinkingPublicInputs;

mod public_inputs;

#[cfg(test)]
mod tests;

pub(crate) use public_inputs::PublicInputs;

/// The wires structure of [LeafCircuit].
#[derive(Clone)]
pub struct LeafWires<'i> {
    block_linking: BlockLinkingPublicInputs<'i, Target>,
    root: HashOutTarget,
}

impl<'i> LeafWires<'i> {
    /// Returns an iterator with the following items, in sequence:
    ///
    /// - `A` Smart contract address
    /// - `C` Merkle root of the storage database
    /// - `S` Storage slot of the variable holding the length
    /// - `M` Storage slot of the mapping
    ///
    /// Such iterator will be used to compute the root node of the leaf.
    pub fn node_preimage(&self) -> impl Iterator<Item = Target> + '_ {
        let a = self.block_linking.a().iter().copied();
        let c = self.block_linking.merkle_root().iter().copied();
        let s = iter::once(self.block_linking.s()[0]);
        let m = iter::once(self.block_linking.m()[0]);

        a.chain(c).chain(s).chain(m)
    }
}

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
    /// Composes the circuit structure by assigning the virtual targets and performing the
    /// constraints.
    pub fn build<'i, F, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        block_linking: BlockLinkingPublicInputs<'i, Target>,
    ) -> LeafWires<'i>
    where
        F: RichField + Extendable<D>,
    {
        let wires = LeafWires {
            block_linking,
            root: b.add_virtual_hash(),
        };

        PublicInputs::register(b, &wires);

        // constrain the merkle root preimage

        let preimage = wires.node_preimage();
        let preimage = iter::once(b.one()).chain(preimage).collect::<Vec<_>>();
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(preimage);

        root.elements
            .iter()
            .zip(wires.root.elements.iter())
            .for_each(|(r, w)| b.connect(*r, *w));

        wires
    }

    /// Assigns the data of [BlockLinkingPublicInputs] into the circuit wires.
    pub fn assign<F>(&self, pw: &mut PartialWitness<F>, wires: &LeafWires) -> anyhow::Result<()>
    where
        F: RichField,
    {
        let preimage = wires.node_preimage().map(|p| pw.try_get_target(p));
        let preimage = iter::once(Some(F::ONE))
            .chain(preimage)
            .map(|p| p.context("Block linking witness value unavailable on partial witness"))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let root = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&preimage);

        wires
            .root
            .elements
            .iter()
            .zip(root.elements.iter())
            .for_each(|(&t, &v)| pw.set_target(t, v));

        Ok(())
    }
}
