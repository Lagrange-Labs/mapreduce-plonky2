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
        circuit_data::VerifierCircuitData,
        config::{GenericHashOut, Hasher},
        proof::ProofWithPublicInputsTarget,
    },
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use crate::{
    api::ProofWithVK,
    state::{lpn::StateInputs, BlockLinkingInputs},
    types::HashOutput,
    utils::convert_u8_to_u32_slice,
    verifier_gadget::VerifierTarget,
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
    ) where
        F: RichField + Extendable<D>,
    {
        let preimage = Self::node_preimage(block_linking).collect::<Vec<_>>();
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(preimage);

        StateInputs::register(b, &root, block_linking);
    }
}

type F = crate::api::F;
type C = crate::api::C;
const D: usize = crate::api::D;

#[derive(Serialize, Deserialize)]
pub(crate) struct LeafCircuitWires(VerifierTarget<D>);

impl CircuitLogicWires<F, D, 0> for LeafCircuitWires {
    type CircuitBuilderParams = VerifierCircuitData<F, C, D>;

    type Inputs = ProofWithVK;

    const NUM_PUBLIC_INPUTS: usize = StateInputs::<Target>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        // verify block linking proof
        let block_linking_proof_wires = VerifierTarget::verify_proof(builder, &builder_parameters);
        let block_linking_pi =
            BlockLinkingInputs::from_slice(&block_linking_proof_wires.get_proof().public_inputs);
        LeafCircuit::build(builder, &block_linking_pi);
        Self(block_linking_proof_wires)
    }

    fn assign_input(
        &self,
        inputs: Self::Inputs,
        pw: &mut plonky2::iop::witness::PartialWitness<F>,
    ) -> anyhow::Result<()> {
        let (proof, vd) = inputs.into();
        Ok(self.0.set_target(pw, &proof, &vd))
    }
}
