use anyhow::Result;
use plonky2::{iop::witness::{PartialWitness, WitnessWrite}, plonk::{
    circuit_builder::CircuitBuilder, circuit_data::{VerifierCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData}, config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}
}};
use recursion_framework::serialization::{circuit_data_serialization::SerializableRichField, deserialize, serialize};
use serde::{Deserialize, Serialize};

pub use crate::storage::{
    self,
    length_extract::{self},
    lpn, mapping,
};

use self::storage::length_match;

// TODO: put every references here. remove one from mapping
pub(crate) const D: usize = 2;
pub(crate) type C = PoseidonGoldilocksConfig;
pub(crate) type F = <C as GenericConfig<D>>::F;

pub enum CircuitInput {
    Mapping(mapping::CircuitInput),
    LengthExtract(storage::length_extract::CircuitInput),
    Storage(lpn::Input),
    LengthMatch(length_match::CircuitInput),
}

#[derive(Serialize, Deserialize)]
pub struct PublicParameters {
    mapping: mapping::PublicParameters,
    length_extract: length_extract::PublicParameters,
    length_match: length_match::Parameters,
    lpn_storage: lpn::PublicParameters,
}

pub fn build_circuits_params() -> PublicParameters {
    let mapping = mapping::build_circuits_params();
    let length_extract = length_extract::PublicParameters::build();
    let length_match = length_match::Parameters::build(
        mapping.get_mapping_circuit_set(), 
        &length_extract.circuit_data().verifier_data()
    );
    PublicParameters {
        mapping,
        length_extract,
        length_match,
        lpn_storage: lpn::PublicParameters::build(),
    }
}

pub fn generate_proof(params: &PublicParameters, input: CircuitInput) -> Result<Vec<u8>> {
    match input {
        CircuitInput::Mapping(mapping_input) => {
            mapping::generate_proof(&params.mapping, mapping_input)
        }
        CircuitInput::LengthExtract(length_extract_input) => {
            params.length_extract.generate(length_extract_input)
        }
        CircuitInput::LengthMatch(length_match_input) => {
            let (mapping_proof, length_proof) = length_match_input.try_into()?;
            let length_match_proof = ProofWithVK::from(
                (
                    length_proof,
                    params.length_extract.circuit_data().verifier_only.clone(),
                )
            );
            params.length_match.generate_proof(
                params.mapping.get_mapping_circuit_set(), 
                &mapping_proof, 
                &length_match_proof
            )
        }
        CircuitInput::Storage(storage_input) => params.lpn_storage.generate_proof(storage_input),
    }
}

/// ProofWithVK is a generic struct holding a child proof and its associated verification key.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub(crate) struct ProofWithVK {
    pub(crate) proof: ProofWithPublicInputs<F, C, D>,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub(crate) vk: VerifierOnlyCircuitData<C, D>,
}

impl ProofWithVK {
    pub(crate) fn serialize(&self) -> Result<Vec<u8>> {
        let buff = bincode::serialize(&self)?;
        Ok(buff)
    }

    pub(crate) fn deserialize(buff: &[u8]) -> Result<Self> {
        let s = bincode::deserialize(buff)?;
        Ok(s)
    }

    pub(crate) fn get_proof(&self) -> &ProofWithPublicInputs<F, C, D> {
        &self.proof
    }

    pub(crate) fn get_verifier_data(&self) -> &VerifierOnlyCircuitData<C, D> {
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

pub(crate) fn serialize_proof<
    F: SerializableRichField<D>,
    C: GenericConfig<D, F=F>,
    const D: usize,
>(proof: &ProofWithPublicInputs<F, C, D>) -> Result<Vec<u8>> {
    Ok(bincode::serialize(&proof)?)
}

pub(crate) fn deserialize_proof<
    F: SerializableRichField<D>,
    C: GenericConfig<D, F=F>,
    const D: usize,
>(bytes: &[u8]) -> Result<ProofWithPublicInputs<F, C, D>> {
    Ok(bincode::deserialize(bytes)?)
}

#[derive(Serialize, Deserialize)]
/// Data structure storing the wires necessary to recursively verify a proof in a Plonky2 circuit 
pub(crate) struct RecursiveVerifierTarget<const D: usize> {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    proof: ProofWithPublicInputsTarget<D>,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    vd: VerifierCircuitTarget,
}

impl<const D: usize> RecursiveVerifierTarget<D> 
{
    /// Recursively verify a proof for a circuit with the given `verifier_data`
    pub(crate) fn verify_proof<
        F: SerializableRichField<D>,
        C: GenericConfig<D, F = F> + 'static,
    >(
        cb: &mut CircuitBuilder<F, D>,
        verifier_data: &VerifierCircuitData<F, C, D>
    ) -> Self 
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let proof = cb.add_virtual_proof_with_pis(&verifier_data.common);
        let vd = cb.add_virtual_verifier_data(
            verifier_data.common.fri_params.config.cap_height
        );
        cb.verify_proof::<C>(&proof, &vd, &verifier_data.common);
        Self {
            proof,
            vd,
        }
    }

    /// Set targets of `self` employing the proof to be verifier and the `VerifierOnlyCircuitData`
    /// of the associated circuit
    pub(crate) fn set_target<
        F: SerializableRichField<D>,
        C: GenericConfig<D, F = F> + 'static,
    >(
        &self,
        pw: &mut PartialWitness<F>,
        proof: &ProofWithPublicInputs<F, C, D>,
        vd: &VerifierOnlyCircuitData<C, D>,
    ) 
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        pw.set_proof_with_pis_target(&self.proof, proof);
        pw.set_verifier_data_target(&self.vd, vd);
    }

    pub(crate) fn get_proof(&self) -> &ProofWithPublicInputsTarget<D> {
        &self.proof
    }
}




impl Into<(
        ProofWithPublicInputs<F, C, D>,
        VerifierOnlyCircuitData<C, D>,
    )> for ProofWithVK {
        fn into(self) -> (
        ProofWithPublicInputs<F, C, D>,
        VerifierOnlyCircuitData<C, D>,
    ) {
        (self.proof, self.vk)
    }
}

impl<'a> Into<(
    &'a ProofWithPublicInputs<F, C, D>,
    &'a VerifierOnlyCircuitData<C, D>
)> for &'a ProofWithVK {
    fn into(self) -> (
        &'a ProofWithPublicInputs<F, C, D>,
        &'a VerifierOnlyCircuitData<C, D>
    ) {
        (self.get_proof(), self.get_verifier_data())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use plonky2::{iop::witness::PartialWitness, plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData, VerifierOnlyCircuitData}, proof::ProofWithPublicInputs}};
    use recursion_framework::{circuit_builder::CircuitLogicWires, framework_testing::DummyCircuitWires};
    use anyhow::Result;

pub(crate) struct TestDummyCircuit<const NUM_PUBLIC_INPUTS: usize> {
    data: CircuitData<F, C, D>,
    wires: DummyCircuitWires<NUM_PUBLIC_INPUTS>,
}

impl<const NUM_PUBLIC_INPUTS: usize> TestDummyCircuit<NUM_PUBLIC_INPUTS> {
    pub(crate) fn build() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut cb = CircuitBuilder::<F, D>::new(config);
        let wires = DummyCircuitWires::circuit_logic(&mut cb, [], ());
        let data = cb.build::<C>();
        Self {
            data,
            wires,
        }
    }

    pub(crate) fn generate_proof(&self, public_inputs: [F; NUM_PUBLIC_INPUTS]) 
    -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        <DummyCircuitWires<NUM_PUBLIC_INPUTS> as CircuitLogicWires<F, D, 0>>::assign_input(
            &self.wires, 
            public_inputs, 
            &mut pw
        )?;
        self.data.prove(pw)
    }

    pub(crate) fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}

}
