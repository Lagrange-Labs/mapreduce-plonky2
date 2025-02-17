//! Provide the generic APIs to build proving parameters and generate proofs for 
//! the Zk-SQL coprocessor by Lagrange.
//! 
//! In a nutshell, Lagrange Zk-SQL coprocessor allows to run verifiable SQL queries 
//! over tables in Lagrange verifiable DB. The verifiable DB allows to create 
//! tables from blockchain data, altogether with a proof that the DB was constructed 
//! with the same data extracted from the blockchain.
//! 
//! The high-level flow to provably build a table in the verifiable DB is:
//! - An *extraction proof* is generated to compute a cryptographic accumulator of the data to 
//! be employed to create a table; in case of blockchain data, this requires to prove the accumulator 
//! was built from data found in on-chain data structures (e.g., storage MPT)
//! - A *table creation* proof is generated to actually build the tables in Lagrange verifiable DB; 
//! this proof is also checking that the data employed to build the table was the same data extracted 
//! by the extraction proof, hinging upon the cryptographic accumulator
//! 
//! The verifiable DB supporst also updates to the tables, and the *table creation* proof can be 
//! incrementally updated to prove the construction of the updated table. 
//! Note that the verifiable DB currently supports append-only updates: indeed, to allow querying 
//! over historical data, the DB is conceived as a time-series DB, and so each modification to the DB 
//! implies that a new row is added to the table with the current timestamp (e.g., the block number 
//! in case of blockchain data)
//! 
//! Once a table is created, queries can be provably run over the table. Running a query generates 
//! a proof of correct computation of the query results. This proof is then recursively composed with 
//! the *table creation proof*, generating the final proof of query execution. This final proof can 
//! then be wrapped in a Groth16 proof for cheap on-chain verification.
#![allow(incomplete_features)]
#![allow(clippy::large_enum_variant)]
// Add this to allow generic const expressions, e.g. `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]
// Add this so we don't need to always specify const generic in generic
// parameters (i.e. use "_")
#![feature(generic_arg_infer)]
// stylistic feature
#![feature(async_closure)]
use mp2_common::mpt_sequential::PAD_LEN;

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
