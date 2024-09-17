pub(crate) mod api;
mod base_circuit;
mod lengthed_circuit;
mod merge;
mod public_inputs;
mod simple_circuit;

pub use api::{CircuitInput, PublicParameters};
use derive_more::{From, Into};
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    serialization::{deserialize, serialize},
    utils::ToTargets,
    D, F,
};
use plonky2::{
    iop::{
        target::BoolTarget,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget};
pub use public_inputs::PublicInputs;

pub(crate) use base_circuit::BaseCircuitProofInputs;
pub(crate) use lengthed_circuit::LengthedCircuitInput as LengthedCircuit;
use serde::{Deserialize, Serialize};
pub(crate) use simple_circuit::SimpleCircuitInput as SimpleCircuit;
