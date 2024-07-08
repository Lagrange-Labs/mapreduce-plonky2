mod api;
mod circuit;
mod public_inputs;

pub use api::{CircuitInput, PublicParameters};
use plonky2::iop::target::Target;
pub use public_inputs::PublicInputs;
pub(crate) const NUM_IO: usize = PublicInputs::<Target>::TOTAL_LEN;
