pub(crate) mod api;
mod base_circuit;
mod lengthed_circuit;
mod public_inputs;
mod simple_circuit;

pub use {public_inputs::PublicInputs, api::{PublicParameters, CircuitInput}};

pub(crate) use {
    simple_circuit::SimpleCircuitInput as SimpleCircuit,
    lengthed_circuit::LengthedCircuitInput as LengthedCircuit,
    base_circuit::BaseCircuitProofInputs, 
};