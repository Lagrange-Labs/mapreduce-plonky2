//! Provides API to generate proofs for the table creation and query execution
//! steps of Lagrange Zk-SQL coprocessor.

// Add this to allow generic const expressions, e.g. `PAD_LEN(NODE_LEN)`.
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
// Add this to allow generic const items, e.g. `const IO_LEN<const MAX_NUM: usize>`
#![feature(generic_const_items)]
#![feature(variant_count)]

use git_version::git_version;
use plonky2::plonk::{
    circuit_builder::CircuitBuilder,
    config::{GenericConfig, Hasher},
};

pub mod api;
pub mod block_tree;
pub mod cells_tree;
pub mod extraction;
pub mod ivc;
/// Module for circuits for simple queries
pub mod query;
#[cfg(feature = "results_tree")]
pub mod results_tree;
/// Module for the query revelation circuits
pub mod revelation;
pub mod row_tree;
pub mod test_utils;

pub(crate) const D: usize = 2;
#[cfg(feature = "original_poseidon")]
pub(crate) type C = plonky2::plonk::config::PoseidonGoldilocksConfig;
#[cfg(not(feature = "original_poseidon"))]
pub(crate) type C = poseidon2_plonky2::poseidon2_goldilock::Poseidon2GoldilocksConfig;
pub(crate) type F = <C as GenericConfig<D>>::F;
pub(crate) type CHasher = <C as GenericConfig<D>>::Hasher;
pub(crate) type H = <C as GenericConfig<D>>::Hasher;
pub(crate) type CBuilder = CircuitBuilder<F, D>;
pub(crate) type HashPermutation = <H as Hasher<F>>::Permutation;

/// Return the current version of the library.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The full git version of mapreduce-plonky2
///
/// `git` is required when compiling. This is the string returned from the command
/// `git describe --abbrev=7 --always`, e.g. `v1.1.1-8-g77fa458`.
pub const GIT_VERSION: &str = git_version!(args = ["--abbrev=7", "--always"]);

/// Get the short git version of mapreduce-plonky2.
///
/// Return `77fa458` if the full git version is `v1.1.1-8-g77fa458`.
pub fn short_git_version() -> String {
    let commit_version = GIT_VERSION.split('-').next_back().unwrap();

    // Check if use commit object as fallback.
    if commit_version.len() < 8 {
        commit_version.to_string()
    } else {
        commit_version[1..8].to_string()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use mp2_common::{array::Array, keccak::PACKED_HASH_LEN};
    use plonky2_crypto::u32::arithmetic_u32::U32Target;

    use super::*;

    pub(crate) type OutputHash = Array<U32Target, PACKED_HASH_LEN>;

    #[test]
    fn test_short_git_version() {
        let v = short_git_version();

        assert_eq!(v.len(), 7);
        assert!(v.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
