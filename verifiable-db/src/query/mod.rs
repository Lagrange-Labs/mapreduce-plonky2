use mp2_common::F;
use public_inputs::PublicInputs;

pub mod aggregation;
pub mod api;
pub mod computational_hash_ids;
pub mod merkle_path;
pub mod public_inputs;
pub mod universal_circuit;

pub const fn pi_len<const MAX_NUM_RESULTS: usize>() -> usize {
    PublicInputs::<F, MAX_NUM_RESULTS>::total_len()
}
