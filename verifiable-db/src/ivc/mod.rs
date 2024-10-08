mod api;
mod circuit;
pub(crate) mod public_inputs;

pub use api::{CircuitInput, PublicParameters};
use plonky2::iop::target::Target;
pub use public_inputs::PublicInputs;
pub const NUM_IO: usize = PublicInputs::<Target>::TOTAL_LEN;
