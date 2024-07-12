// Add this to allow generic const expressions, e.g. `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]
#![feature(variant_count)]
/// Module for circuits for simple queries
pub mod simple_query_circuits;

use anyhow::Result;
use plonky2::{
    field::types::Field,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};

pub mod api;
pub mod block_tree;
pub mod cells_tree;
pub mod extraction;
pub mod ivc;
pub mod row_tree;
