//! Length extraction circuits
//!
//! # Leaf
//!
//! The leaf extraction circuit derives the MPT key from the length slot and replaces the current
//! key pointer with the supplied witness. This replacement is necessary since the initial key
//! pointer corresponds to the depth of the proven leaf in the MPT. Subsequently, the circuit
//! traverses the MPT key by one tree level, computes the latest hash along such traversal path,
//! and calculates the RLP headers.
//!
//! It exposes as public input a curve point commitment derived from both the length slot and the
//! unconstrained variable slot. The circuit exposes the Keccak hash of the current node (H), the
//! DM commitment, MPT key (K), MPT key pointer for the next tree level (T), and the decoded leaf
//! node length (N).
//!
//! A leaf node located at depth 5 in the MPT is expected to have its key pointer initialized as 3.
//! This expectation arises due to the leaf node being bypassed during traversal, allowing the
//! circuit to present the pointer for the subsequent iteration (therefore, we always subtract 2
//! from the leaf depth).
//!
//! # Extension
//!
//! The extension node circuit accepts a branch child proof as input and extracts the expected
//! branch node value, which serves as the root value in the traversal path up to that point.
//! Subsequently, it navigates through the MPT based on the consumed depth of the proof, updating
//! the next tree level accordingly (T).
//!
//! # Branch
//!
//! The branch node traverses the tree until it reaches the MPT root node, represented by a T value
//! of -1. At each level, it returns the new root and an updated T value, having traversed that
//! specific depth within the tree.

mod branch;
mod extension;
mod leaf;
mod public_inputs;

#[cfg(test)]
mod tests;

pub use branch::{BranchLengthCircuit, BranchLengthWires};
pub use extension::{ExtensionLengthCircuit, ExtensionLengthWires};
pub use leaf::{LeafLengthCircuit, LeafLengthWires};
pub use public_inputs::PublicInputs;
