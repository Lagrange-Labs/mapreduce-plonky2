use plonky2::iop::target::Target;
use public_inputs::PublicInputs;

pub mod api;
pub(crate) mod circuits;
pub mod computational_hash_ids;
pub mod merkle_path;
pub(crate) mod output_computation;
pub mod public_inputs;
pub(crate) mod row_chunk_gadgets;
pub mod universal_circuit;
pub mod utils;

pub const fn pi_len<const MAX_NUM_RESULTS: usize>() -> usize {
    PublicInputs::<Target, MAX_NUM_RESULTS>::total_len()
}
