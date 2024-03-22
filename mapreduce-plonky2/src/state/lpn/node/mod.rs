//! Merkle tree recursive proof for the intermediate node.

use std::iter;

use plonky2::{
    field::extension::Extendable,
    hash::{hash_types::RichField, poseidon::PoseidonHash},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use crate::state::StateInputs;

#[cfg(test)]
mod tests;

/// Circuit to prove the correct formation of the intermediate node.
///
/// Will take the [BlockLinkingInputs] as argument.
///
/// # Circuit description
///
/// +---------------------+
/// | left leaf.node root +------------------+
/// +---------------------+                  |
/// +----------------------+                 |
/// | left leaf.block hash +---------------+ |
/// +----------------------+               | |
/// +------------------------+             | |
/// | left leaf.block number +-----------+ | |
/// +------------------------+           | | |
/// +-------------------------------+    | | |
/// | left leaf.previous block hash +--+ | | |
/// +-------------------------------+  | | | |
///                                    | | | |
/// +----------------------+           | | | |
/// | right leaf.node root +-------------------+
/// +----------------------+           | | | | |
/// +-----------------------+          | | | | |
/// | right leaf.block hash +--------------+ | |
/// +-----------------------+          | |   | |
/// +-------------------------+        | |   | |
/// | right leaf.block number +----------+   | |
/// +-------------------------+        |     | |
/// +--------------------------------+ |     | |
/// | right leaf.previous block hash +-+     | |
/// +--------------------------------+       | |
///                                          | |
/// +------------------+                     | |
/// | node.merkle root +----------------+H(0,+,+)
/// +------------------+
#[derive(Clone, Debug)]
pub struct NodeCircuit;

impl NodeCircuit {
    /// Returns an iterator with the following items, in sequence:
    ///
    /// - `p` The node constant prefix
    /// - `A` Smart contract address
    /// - `C` Merkle root of the storage database
    /// - `S` Storage slot of the variable holding the length
    /// - `M` Storage slot of the mapping
    ///
    /// Such iterator will be used to compute the root of the intermediate node.
    pub fn node_preimage<'i, T, L, R>(
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
        left_sibling
            .into_iter()
            .chain(right_sibling.into_iter())
            .cloned()
    }

    /// Composes the circuit structure by assigning the virtual targets and performing the
    /// constraints. This circuit specifically ensures both children proofs are proving inclusion for
    /// the same block header, same previous block header, and same block number. The circuit
    /// then exposes the relevant information as public for the next proof layer to consume.
    pub fn build<'i, F, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        left_sibling: StateInputs<'i, Target>,
        right_sibling: StateInputs<'i, Target>,
    ) where
        F: RichField + Extendable<D>,
    {
        left_sibling
            .block_header()
            .arr
            .iter()
            .zip(right_sibling.block_header().arr.iter())
            .for_each(|(l, r)| b.connect(l.0, r.0));

        left_sibling
            .prev_block_header()
            .arr
            .iter()
            .zip(right_sibling.prev_block_header().arr.iter())
            .for_each(|(l, r)| b.connect(l.0, r.0));

        b.connect(
            left_sibling.block_number().0,
            right_sibling.block_number().0,
        );

        let left = left_sibling.root();
        let right = right_sibling.root();
        let preimage = Self::node_preimage(&left.elements, &right.elements).collect::<Vec<_>>();

        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(preimage);

        b.register_public_inputs(&root.elements);
        left_sibling.register_block_linking_data(b);
    }
}
#[derive(Serialize, Deserialize)]
pub(crate) struct NodeCircuitWires;

type F = crate::api::F;
type C = crate::api::C;
const D: usize = crate::api::D;

impl CircuitLogicWires<F, D, 2> for NodeCircuitWires {
    type CircuitBuilderParams = ();

    type Inputs = ();

    const NUM_PUBLIC_INPUTS: usize = StateInputs::<Target>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<D>; 2],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let left_sibling = StateInputs::from_slice(Self::public_input_targets(verified_proofs[0]));
        let right_sibling = StateInputs::from_slice(Self::public_input_targets(verified_proofs[1]));
        NodeCircuit::build(builder, left_sibling, right_sibling);

        NodeCircuitWires {}
    }

    fn assign_input(
        &self,
        _inputs: Self::Inputs,
        _pw: &mut plonky2::iop::witness::PartialWitness<F>,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}
