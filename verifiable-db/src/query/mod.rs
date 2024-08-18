use mp2_common::F;
use public_inputs::PublicInputs;

pub mod aggregation;
pub mod api;
pub mod computational_hash_ids;
pub mod public_inputs;
pub mod universal_circuit;

// Without this skipping config, the generic parameter was deleted when `cargo fmt`.
#[rustfmt::skip]
pub const PI_LEN<const MAX_NUM_RESULTS: usize>: usize = PublicInputs::<F, MAX_NUM_RESULTS>::total_len();
