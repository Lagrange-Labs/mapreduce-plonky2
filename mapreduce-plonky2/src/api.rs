use anyhow::Result;
use plonky2::plonk::{
    circuit_data::VerifierOnlyCircuitData,
    config::{GenericConfig, PoseidonGoldilocksConfig},
    proof::ProofWithPublicInputs,
};
use recursion_framework::serialization::{deserialize, serialize};
use serde::{Deserialize, Serialize};

pub use crate::storage::{
    self,
    length_extract::{self},
    mapping,
};

// TODO: put every references here. remove one from mapping
pub(crate) const D: usize = 2;
pub(crate) type C = PoseidonGoldilocksConfig;
pub(crate) type F = <C as GenericConfig<D>>::F;

pub enum CircuitInput {
    Mapping(mapping::CircuitInput),
    LengthExtract(storage::length_extract::CircuitInput),
}

#[derive(Serialize, Deserialize)]
pub struct PublicParameters {
    mapping: mapping::PublicParameters,
    length_extract: length_extract::PublicParameters,
}

pub fn build_circuits_params() -> PublicParameters {
    PublicParameters {
        mapping: mapping::build_circuits_params(),
        length_extract: length_extract::PublicParameters::build(),
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
        let s = bincode::deserialize(&buff)?;
        Ok(s)
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
