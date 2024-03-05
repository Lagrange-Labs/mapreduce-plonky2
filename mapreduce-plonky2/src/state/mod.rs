//! Handle state database proofs, the proving process should be:
//! previous-storage-proof -->
//!     block-linking-circuit --> ...

mod block_linking;
mod branch;

pub use branch::PublicInputs;
