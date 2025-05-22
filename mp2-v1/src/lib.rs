//! Provide the generic APIs to build proving parameters and generate proofs for
//! the Zk-SQL coprocessor by Lagrange.
//!
//! In a nutshell, Lagrange Zk-SQL coprocessor allows to run verifiable SQL queries
//! over tables in Lagrange verifiable DB. The verifiable DB allows to create
//! tables from blockchain data, altogether with a proof that the DB was constructed
//! with the same data extracted from the blockchain.
#![allow(incomplete_features)]
#![allow(clippy::large_enum_variant)]
// Add this to allow generic const expressions, e.g. `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]
// Add this so we don't need to always specify const generic in generic
// parameters (i.e. use "_")
#![feature(generic_arg_infer)]
use mp2_common::{array::Array, keccak::PACKED_HASH_LEN, mpt_sequential::PAD_LEN};
use plonky2::{
    field::extension::quintic::QuinticExtension,
    plonk::{circuit_builder::CircuitBuilder, config::GenericConfig},
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;

pub const MAX_BRANCH_NODE_LEN: usize = 532;
pub const MAX_BRANCH_NODE_LEN_PADDED: usize = PAD_LEN(532);
/// rlp( rlp(max key 32b) + rlp(max value 32b) ) + 1 for compact encoding
/// see test_len()
pub const MAX_EXTENSION_NODE_LEN: usize = 69;
pub const MAX_EXTENSION_NODE_LEN_PADDED: usize = PAD_LEN(69);
pub const MAX_LEAF_NODE_LEN: usize = MAX_EXTENSION_NODE_LEN;

pub mod api;
pub mod block_extraction;
pub mod contract_extraction;
pub mod final_extraction;
pub mod indexing;
pub mod length_extraction;
pub mod query;
pub mod values_extraction;

pub(crate) const D: usize = 2;
#[cfg(feature = "original_poseidon")]
pub(crate) type C = plonky2::plonk::config::PoseidonGoldilocksConfig;
#[cfg(not(feature = "original_poseidon"))]
pub(crate) type C = poseidon2_plonky2::poseidon2_goldilock::Poseidon2GoldilocksConfig;
pub(crate) type F = <C as GenericConfig<D>>::F;
pub(crate) type CHasher = <C as GenericConfig<D>>::Hasher;
pub(crate) type H = <C as GenericConfig<D>>::Hasher;
pub(crate) type CBuilder = CircuitBuilder<F, D>;
pub(crate) type GFp5 = QuinticExtension<F>;
pub(crate) type OutputHash = Array<U32Target, PACKED_HASH_LEN>;

#[cfg(test)]
pub(crate) mod tests {
    /// Testing maximum columns
    pub(crate) const TEST_MAX_COLUMNS: usize = 32;
    /// Testing maximum fields for each EVM word
    pub(crate) const TEST_MAX_FIELD_PER_EVM: usize = 32;
}
