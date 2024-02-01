//! Digest tree circuit used to prove Merkle tree nodes recursively.

use plonky2::{field::extension::Extendable, hash::hash_types::RichField};

mod arity;
mod multiset_hashing;

pub use arity::DigestArityCircuit;
pub use multiset_hashing::MultisetHashingCircuit;

pub trait DigestTreeCircuit<F, const D: usize, const N: usize>
where
    F: RichField + Extendable<D>,
{
    /// Create a circuit instance for a leaf of Merkle tree.
    fn new_leaf(value: [u8; 32]) -> Self;

    /// Create a circuit instance for a branch of Merkle tree.
    fn new_branch(children: Vec<[F; N]>) -> Self;
}
