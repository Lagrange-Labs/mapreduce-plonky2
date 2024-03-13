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

use crate::{state::BlockLinkingPublicInputs, types::HashOutput, utils::convert_u8_to_u32_slice};

mod public_inputs;

#[cfg(test)]
mod tests;

pub(crate) use public_inputs::PublicInputs;

/// Domain separation tag for the leaf value hashing scheme for the state database
const STATE_LEAF_DST: u8 = 0x22;
/// Returns the hash in bytes of the leaf of the state database. It takes as parameters
/// * the address of the contract,
/// * the mapping slot for which we're building the database over (v0 only functionality)
///     and the length slot corresponding to the variable holding the length of the mapping.
/// * the storage root of the lpn database corresponding to this contract
pub fn state_leaf_hash(
    add: Address,
    mapping_slot: u8,
    length_slot: u8,
    storage_root: HashOutput,
) -> HashOutput {
    let packed = convert_u8_to_u32_slice(add.as_bytes());
    let f_slice = std::iter::once(STATE_LEAF_DST as u32)
        .chain(packed)
        .chain(std::iter::once(mapping_slot as u32))
        .chain(std::iter::once(length_slot as u32))
        .map(GoldilocksField::from_canonical_u32)
        .chain(HashOut::from_bytes(&storage_root).elements)
        .collect::<Vec<_>>();
    let hash_f = PoseidonHash::hash_no_pad(&f_slice);
    hash_f.to_bytes().try_into().unwrap()
}

/// Circuit to prove the correct formation of the leaf node.
///
/// Will take the [BlockLinkingPublicInputs] as argument.
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
        let address = block_linking.packed_address().iter().cloned();
        let storage_root = block_linking.merkle_root().iter().cloned();
        let length_slot = iter::once(block_linking.length_slot()[0].clone());
        let mapping_slot = iter::once(block_linking.mapping_slot()[0].clone());

        iter::once(prefix)
            .chain(address)
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
        block_linking: &BlockLinkingPublicInputs<Target>,
    ) -> HashOutTarget
    where
        F: RichField + Extendable<D>,
    {
        let dst = b.constant(F::from_canonical_u8(STATE_LEAF_DST));
        let preimage = Self::node_preimage(dst, block_linking).collect::<Vec<_>>();
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(preimage);

        PublicInputs::register(b, &root, block_linking);

        root
    }
}
