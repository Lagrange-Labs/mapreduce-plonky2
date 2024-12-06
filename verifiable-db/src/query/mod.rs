use plonky2::iop::target::Target;
use public_inputs::PublicInputs;

pub mod api;
pub mod computational_hash_ids;
pub mod merkle_path;
pub mod public_inputs;
pub mod universal_circuit;
pub(crate) mod circuits;
pub(crate) mod row_chunk_gadgets;
pub(crate) mod output_computation;
pub mod utils;

pub const fn pi_len<const MAX_NUM_RESULTS: usize>() -> usize {
    PublicInputs::<Target, MAX_NUM_RESULTS>::total_len()
}
