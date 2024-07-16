//! Utility structs and functions used for integration tests
mod bindings;
mod block_extraction;
mod cases;
mod celltree;
mod context;
mod contract_extraction;
mod final_extraction;
mod index_tree;
mod length_extraction;
mod nodes;
pub(crate) mod proof_storage;
mod rowtree;
mod storage_trie;
mod values_extraction;

pub(crate) use cases::TestCase;
pub(crate) use context::TestContext;

use mp2_common::{proof::ProofWithVK, F};
use mp2_test::cells_tree::CellTree;
use plonky2::hash::hash_types::HashOut;

fn cell_tree_proof_to_hash(proof: &[u8]) -> HashOut<F> {
    let root_pi = ProofWithVK::deserialize(&proof)
        .expect("while deserializing proof")
        .proof
        .public_inputs;
    verifiable_db::cells_tree::PublicInputs::from_slice(&root_pi).root_hash_hashout()
}

fn row_tree_proof_to_hash(proof: &[u8]) -> HashOut<F> {
    let root_pi = ProofWithVK::deserialize(&proof)
        .expect("while deserializing proof")
        .proof
        .public_inputs;
    verifiable_db::row_tree::PublicInputs::from_slice(&root_pi).root_hash_hashout()
}
