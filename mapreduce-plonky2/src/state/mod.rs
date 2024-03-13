//! Handle state database proofs, the proving process should be:
//! previous-storage-proof -->
//!     block-linking-circuit --> ...
//!     leaf-circuit --> ...

mod block_linking;
mod branch;
mod lpn;

pub use block_linking::PublicInputs as BlockLinkingPublicInputs;
pub use branch::PublicInputs;
