//! Digest tree circuit used to prove Merkle tree nodes recursively.

use plonky2::{field::extension::Extendable, hash::hash_types::RichField};

mod arity;
mod hash_to_curve;

pub use arity::DigestArityCircuit;

pub trait DigestTreeCircuit<F, const D: usize>
where
    F: RichField + Extendable<D>,
{
    /// Create a circuit instance for a leaf of Merkle tree.
    fn new_leaf(value: [u8; 32]) -> Self;

    /// Create a circuit instance for a branch of Merkle tree.
    fn new_branch(inputs: Vec<[F; 4]>) -> Self;
}
