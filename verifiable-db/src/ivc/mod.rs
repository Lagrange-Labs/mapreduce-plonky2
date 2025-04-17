mod api;
mod circuit;
pub(crate) mod public_inputs;

pub use api::{CircuitInput, PublicParameters};
pub use circuit::add_provable_data_commitment_prefix;
use plonky2::iop::target::Target;
pub use public_inputs::PublicInputs;
pub const NUM_IO: usize = PublicInputs::<Target>::TOTAL_LEN;
