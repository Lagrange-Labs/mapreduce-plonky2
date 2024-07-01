//! Main APIs and related structures

use crate::{cells_tree, index_tree, row_tree};
use anyhow::Result;
use ethers::prelude::U256;
use mp2_common::{C, D, F};
use plonky2::hash::hash_types::HashOut;
use recursion_framework::framework::RecursiveCircuits;
use serde::{Deserialize, Serialize};

/// Struct containing the expected input of the Cell Tree node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CellNode {
    pub identifier: F,
    pub value: U256,
}

/// Set of inputs necessary to generate proofs for each circuit employed in the verifiable DB stage of LPN
pub enum CircuitInput {
    /// Cells tree construction input
    CellsTree(cells_tree::CircuitInput),
    RowsTree(row_tree::CircuitInput),
    IndexTree(index_tree:CircuitInput),
}

/// Parameters defining all the circuits employed for the verifiable DB stage of LPN
#[derive(Serialize, Deserialize)]
pub struct PublicParameters {
    cells_tree: cells_tree::PublicParameters,
    rows_tree: row_tree::PublicParameters,
    index_tree: index_tree::PublicParameters,
}

/// Instantiate the circuits employed for the verifiable DB stage of LPN, and return their corresponding parameters.
pub fn build_circuits_params(extraction_set: RecursiveCircuits<F, C, D>) -> PublicParameters {
    log::info!("Building cells_tree parameters...");
    let cells_tree = cells_tree::build_circuits_params();
    log::info!("Building row tree parameters...");
    let rows_tree = row_tree::PublicParameters::build(cells_tree.vk_set());
    log::info!("Building index tree parameters...");
    let index_tree = index_tree::PublicParameters::build(&extraction_set, rows_tree.set_vk());
    log::info!("All parameters built!");

    PublicParameters {
        cells_tree,
        rows_tree,
        index_tree,
    }
}

/// Generate a proof for a circuit in the set of circuits employed in the
/// verifiable DB stage of LPN, employing `CircuitInput` to specify for which
/// circuit the proof should be generated.
pub fn generate_proof(params: &PublicParameters, input: CircuitInput) -> Result<Vec<u8>> {
    match input {
        CircuitInput::CellsTree(input) => params.cells_tree.generate_proof(input),
        CircuitInput::RowsTree(input) => params
            .rows_tree
            .generate_proof(input, params.cells_tree.vk_set().clone()),
        CircuitInput::IndexTree(input) => params.index_tree.generate_proof(input),
    }
}
