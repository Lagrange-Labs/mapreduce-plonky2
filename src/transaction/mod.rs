use anyhow::Result;
use ethers::types::{Transaction, TransactionReceipt};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{circuit_data::CircuitConfig, config::GenericConfig},
};

use crate::ProofTuple;

use self::mpt::{gas_offset_from_rlp_node, legacy_tx_leaf_node_proof, ExtractionMethod};

mod header;
mod mpt;
#[cfg(test)]
mod prover;

/// Length of a hash in bytes.
const HASH_LEN: usize = 32;
/// Length of a hash in U32
const PACKED_HASH_LEN: usize = 8;
