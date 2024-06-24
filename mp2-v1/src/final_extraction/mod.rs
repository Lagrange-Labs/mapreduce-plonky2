pub(crate) mod api;
mod base_circuit;
mod lengthed_circuit;
mod public_inputs;
mod simple_circuit;

pub use {
    api::{CircuitInput, PublicParameters},
    public_inputs::PublicInputs,
};

pub(crate) use {
    base_circuit::BaseCircuitProofInputs,
    lengthed_circuit::LengthedCircuitInput as LengthedCircuit,
    simple_circuit::SimpleCircuitInput as SimpleCircuit,
};
