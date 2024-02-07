//! Digest tree circuits used to prove Merkle tree nodes recursively.

mod arity;
mod hash_to_field;
mod merkle_tree;
mod multiset_hashing;

pub use arity::DigestArityCircuit;
pub use hash_to_field::{hash_to_curve_point_target, hash_to_curve_point_value};
pub use merkle_tree::{MerkleLeafValue, MerkleNode, MerkleTree};
pub use multiset_hashing::MultisetHashingCircuit;

/// Extension degree of EcGFp5 curve
const ECGFP5_EXT_DEGREE: usize = 5;

/// The trait of digest tree circuit
/// With this trait, both the arity circuit and multiset hashing circuit could
/// be reused in the same benchmark and testing functions.
pub trait DigestTreeCircuit<O> {
    /// Create a circuit instance for a leaf of Merkle tree.
    fn new_leaf(value: [u8; 32]) -> Self;

    /// Create a circuit instance for a branch of Merkle tree.
    fn new_branch(children: Vec<O>) -> Self;
}
