use mp2_common::F;
use public_inputs::PublicInputs;

pub(crate) mod binding_results;
pub(crate) mod public_inputs;

// Without this skipping config, the generic parameter was deleted when `cargo fmt`.
#[rustfmt::skip]
pub(crate) const PI_LEN: usize = PublicInputs::<F>::total_len();
