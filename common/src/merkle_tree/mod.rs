//! Circuits for proving Merkle Tree nodes recursively.

mod backup;
mod merkle_tree;
mod state_tree;

#[cfg(any(feature = "test", test))]
pub use backup::DigestArityCircuit;
#[cfg(any(feature = "test", test))]
pub use merkle_tree::{MerkleLeafValue, MerkleNode, MerkleTree};

/// The trait of digest tree circuit
/// With this trait, both the arity circuit and multiset hashing circuit could
/// be reused in the same benchmark and testing functions.
pub trait DigestTreeCircuit<O> {
    /// Create a circuit instance for a leaf of Merkle tree.
    fn new_leaf(value: [u8; 32]) -> Self;

    /// Create a circuit instance for a branch of Merkle tree.
    fn new_branch(children: Vec<O>) -> Self;
}

pub use state_tree::StateTreeWires;
