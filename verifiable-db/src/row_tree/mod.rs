use alloy::primitives::U256;
use derive_more::Constructor;
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{ToFields, ToTargets},
    D, F,
};
use plonky2::{
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::CurveTarget;
use serde::{Deserialize, Serialize};

mod api;
mod full_node;
mod leaf;
mod partial_node;
mod public_inputs;

pub use api::{extract_hash_from_proof, CircuitInput, PublicParameters};
pub use public_inputs::PublicInputs;
