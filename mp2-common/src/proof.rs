//! Proof related common structures

use crate::{
    serialization::{circuit_data_serialization::SerializableRichField, deserialize, serialize},
    C, D, F,
};
use anyhow::Result;
use plonky2::plonk::{
    circuit_data::VerifierOnlyCircuitData, config::GenericConfig, proof::ProofWithPublicInputs,
};
use serde::{Deserialize, Serialize};

/// This data structure allows to specify the inputs for a circuit that needs to
/// recursively verify proofs; the generic type `T` allows to specify the
/// specific inputs of each circuits besides the proofs that need to be
/// recursively verified, while the proofs are serialized in byte format.
#[derive(Serialize, Deserialize)]
pub struct ProofInputSerialized<T> {
    pub input: T,
    pub serialized_child_proofs: Vec<Vec<u8>>,
}

impl<T> ProofInputSerialized<T> {
    /// Deserialize child proofs and return the set of deserialized 'MTPProof`s
    pub fn get_child_proofs(&self) -> anyhow::Result<Vec<ProofWithVK>> {
        self.serialized_child_proofs
            .iter()
            .map(|proof| ProofWithVK::deserialize(proof))
            .collect::<Result<Vec<_>, _>>()
    }
}

/// ProofWithVK is a generic struct holding a child proof and its associated verification key.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ProofWithVK {
    pub proof: ProofWithPublicInputs<F, C, D>,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub vk: VerifierOnlyCircuitData<C, D>,
}

impl ProofWithVK {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let buff = bincode::serialize(&self)?;
        Ok(buff)
    }

    pub fn deserialize(buff: &[u8]) -> Result<Self> {
        let s = bincode::deserialize(buff)?;
        Ok(s)
    }

    pub fn proof(&self) -> &ProofWithPublicInputs<F, C, D> {
        &self.proof
    }

    pub fn verifier_data(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.vk
    }
}

impl
    From<(
        ProofWithPublicInputs<F, C, D>,
        VerifierOnlyCircuitData<C, D>,
    )> for ProofWithVK
{
    fn from(
        (proof, vk): (
            ProofWithPublicInputs<F, C, D>,
            VerifierOnlyCircuitData<C, D>,
        ),
    ) -> Self {
        ProofWithVK { proof, vk }
    }
}

pub fn serialize_proof<F: SerializableRichField<D>, C: GenericConfig<D, F = F>, const D: usize>(
    proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<Vec<u8>> {
    Ok(bincode::serialize(&proof)?)
}

pub fn deserialize_proof<
    F: SerializableRichField<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    bytes: &[u8],
) -> Result<ProofWithPublicInputs<F, C, D>> {
    Ok(bincode::deserialize(bytes)?)
}

impl From<ProofWithVK>
    for (
        ProofWithPublicInputs<F, C, D>,
        VerifierOnlyCircuitData<C, D>,
    )
{
    fn from(val: ProofWithVK) -> Self {
        (val.proof, val.vk)
    }
}

impl<'a> From<&'a ProofWithVK>
    for (
        &'a ProofWithPublicInputs<F, C, D>,
        &'a VerifierOnlyCircuitData<C, D>,
    )
{
    fn from(val: &'a ProofWithVK) -> Self {
        (val.proof(), val.verifier_data())
    }
}
