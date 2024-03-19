//! Handle state database proofs, the proving process should be:
//! previous-storage-proof -->
//!     block-linking-circuit --> ...
//!     leaf-circuit --> ...

pub mod block_linking;
pub mod lpn;

pub use block_linking::BlockLinkingInputs;
pub use lpn::StateInputs;
