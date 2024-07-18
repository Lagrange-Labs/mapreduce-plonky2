//! Utility structs and functions used for integration tests
use anyhow::Result;
mod bindings;
mod block_extraction;
mod cases;
mod celltree;
pub mod context;
mod contract_extraction;
mod final_extraction;
mod index_tree;
pub mod ivc;
mod length_extraction;
pub(crate) mod proof_storage;
mod rowtree;
mod storage_trie;
mod table;
mod values_extraction;

use std::path::PathBuf;

use anyhow::Context;
pub(crate) use cases::TestCase;
pub(crate) use context::TestContext;

use mp2_common::{proof::ProofWithVK, F};
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

pub fn mkdir_all(params_path_str: &str) -> Result<()> {
    let params_path = PathBuf::from(params_path_str);
    if !params_path.exists() {
        std::fs::create_dir_all(&params_path).context("while creating parameters folder")?;
    }
    Ok(())
}
