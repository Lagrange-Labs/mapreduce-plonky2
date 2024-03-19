//! Circuit to prove the correct formation of the leaf node and its intermediate nodes that
//! describes a Merkle opening.

use std::iter;

use ethers::types::{spoof::storage, Address};
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::target::Target,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{GenericHashOut, Hasher},
    },
};

use crate::{
    state::{lpn::StateInputs, BlockLinkingInputs},
    types::HashOutput,
    utils::convert_u8_to_u32_slice,
};

#[cfg(test)]
mod tests;

/// Circuit to prove the correct formation of the leaf node.
///
/// Will take the [BlockLinkingInputs] as argument.
#[derive(Clone, Debug)]
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
        block_linking: &'i BlockLinkingInputs<'i, T>,
    ) -> impl Iterator<Item = T> + 'i {
        let address = block_linking.packed_address().iter().cloned();
        let storage_root = block_linking.merkle_root().iter().cloned();
        let length_slot = iter::once(block_linking.length_slot().clone());
        let mapping_slot = iter::once(block_linking.mapping_slot().clone());

        address
            .chain(mapping_slot)
            .chain(length_slot)
            .chain(storage_root)
    }

    /// Composes the circuit structure by assigning the virtual targets and performing the
    /// constraints.
    ///
    /// The returned [HashOutTarget] will correspond to the Merkle root of the leaf.
    pub fn build<F, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        block_linking: &BlockLinkingInputs<Target>,
    ) -> HashOutTarget
    where
        F: RichField + Extendable<D>,
    {
        let preimage = Self::node_preimage(block_linking).collect::<Vec<_>>();
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(preimage);

        StateInputs::register(b, &root, block_linking);

        root
    }
}
