use anyhow::Result;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use serde::{Deserialize, Serialize};

use crate::{
    mpt_sequential::PAD_LEN,
    storage::{
        self,
        length_extract::{self, MAX_DEPTH_TRIE},
        mapping, MAX_BRANCH_NODE_LEN,
    },
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
