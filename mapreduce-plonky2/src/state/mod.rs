//! Handle state database proofs, the proving process should be:
//! previous-storage-proof -->
//!     block-linking-circuit --> ...
//!     leaf-circuit --> ...

mod block_linking;
mod lpn;

pub use block_linking::BlockLinkingInputs;
pub use lpn::LeafInputs;
