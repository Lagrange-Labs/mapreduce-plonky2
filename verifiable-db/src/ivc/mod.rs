mod api;
mod circuit;
mod public_inputs;

pub use api::{CircuitInput, PublicParameters};
use plonky2::iop::target::Target;
pub use public_inputs::PublicInputs;
/// Contains the regular outputs defined in the public inputs struct but as well a flag
/// to identify the dummy proof at the beginning. This is implementation specific and should
/// not be used outside of this module.
pub(crate) const EXTENDED_PUBLIC_INPUTS: usize = PublicInputs::<Target>::TOTAL_LEN + 1;
