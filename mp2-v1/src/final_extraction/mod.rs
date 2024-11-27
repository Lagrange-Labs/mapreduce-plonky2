pub(crate) mod api;
mod base_circuit;
mod dummy_circuit;
mod lengthed_circuit;
mod merge_circuit;
mod public_inputs;
mod simple_circuit;

pub use api::{CircuitInput, PublicParameters};
pub use public_inputs::PublicInputs;

pub(crate) use base_circuit::BaseCircuitProofInputs;
pub(crate) use dummy_circuit::DummyCircuit;
pub(crate) use lengthed_circuit::LengthedCircuitInput as LengthedCircuit;
pub(crate) use merge_circuit::MergeCircuitInput as MergeCircuit;
pub(crate) use simple_circuit::SimpleCircuitInput as SimpleCircuit;

/// The prefix to ensure the metadata digest will keep track of whether
/// we use this dummy circuit or not
pub(crate) const DUMMY_METADATA_DIGEST_PREFIX: &[u8] = b"DUMMY_EXTRACTION";
