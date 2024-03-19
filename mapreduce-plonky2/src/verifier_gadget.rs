//! This module contains a data structure employed to recursively verify a Plonky2
//! proof inside a circuit identified by its `VerifierCircuitData`

use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{VerifierCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use recursion_framework::serialization::{
    circuit_data_serialization::SerializableRichField, deserialize, serialize,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
/// Data structure storing the wires necessary to recursively verify a proof in a Plonky2 circuit
pub(crate) struct VerifierTarget<const D: usize> {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    proof: ProofWithPublicInputsTarget<D>,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    vd: VerifierCircuitTarget,
}

impl<const D: usize> VerifierTarget<D> {
    /// Recursively verify a proof for a circuit with the given `verifier_data`
    pub(crate) fn verify_proof<F: SerializableRichField<D>, C: GenericConfig<D, F = F> + 'static>(
        cb: &mut CircuitBuilder<F, D>,
        verifier_data: &VerifierCircuitData<F, C, D>,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let proof = cb.add_virtual_proof_with_pis(&verifier_data.common);
        let vd = cb.add_virtual_verifier_data(verifier_data.common.fri_params.config.cap_height);
        cb.verify_proof::<C>(&proof, &vd, &verifier_data.common);
        Self { proof, vd }
    }

    /// Set targets of `self` employing the proof to be verifier and the `VerifierOnlyCircuitData`
    /// of the associated circuit
    pub(crate) fn set_target<F: SerializableRichField<D>, C: GenericConfig<D, F = F> + 'static>(
        &self,
        pw: &mut PartialWitness<F>,
        proof: &ProofWithPublicInputs<F, C, D>,
        vd: &VerifierOnlyCircuitData<C, D>,
    ) where
        C::Hasher: AlgebraicHasher<F>,
    {
        pw.set_proof_with_pis_target(&self.proof, proof);
        pw.set_verifier_data_target(&self.vd, vd);
    }

    pub(crate) fn get_proof(&self) -> &ProofWithPublicInputsTarget<D> {
        &self.proof
    }
}
