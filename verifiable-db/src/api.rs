//! Main APIs and related structures

use crate::{
    block_tree, cells_tree,
    extraction::{ExtractionPI, ExtractionPIWrap},
    ivc, row_tree,
};
use anyhow::Result;
use ethers::prelude::U256;
use mp2_common::{C, D, F};
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
    BlockTree(block_tree::CircuitInput),
    IVC(ivc::CircuitInput),
}

/// Parameters defining all the circuits employed for the verifiable DB stage of LPN
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PublicParameters<E: ExtractionPIWrap>
where
    [(); E::PI::TOTAL_LEN]:,
{
    cells_tree: cells_tree::PublicParameters,
    rows_tree: row_tree::PublicParameters,
    block_tree: block_tree::PublicParameters<E>,
    ivc: ivc::PublicParameters,
}

/// Instantiate the circuits employed for the verifiable DB stage of LPN, and return their corresponding parameters.
pub fn build_circuits_params<E: ExtractionPIWrap>(
    extraction_set: &RecursiveCircuits<F, C, D>,
) -> PublicParameters<E>
where
    [(); E::PI::TOTAL_LEN]:,
{
    log::info!("Building cells_tree parameters...");
    let cells_tree = cells_tree::build_circuits_params();
    log::info!("Building row tree parameters...");
    let rows_tree = row_tree::PublicParameters::build(cells_tree.vk_set());
    log::info!("Building block tree parameters...");
    let block_tree = block_tree::PublicParameters::build(extraction_set, rows_tree.set_vk());
    log::info!("Building IVC parameters...");
    let ivc = ivc::PublicParameters::build(block_tree.set_vk());
    log::info!("All parameters built!");

    PublicParameters {
        cells_tree,
        rows_tree,
        block_tree,
        ivc,
    }
}

/// Generate a proof for a circuit in the set of circuits employed in the
/// verifiable DB stage of LPN, employing `CircuitInput` to specify for which
/// circuit the proof should be generated.
pub fn generate_proof<E: ExtractionPIWrap>(
    params: &PublicParameters<E>,
    input: CircuitInput,
    extraction_set: &RecursiveCircuits<F, C, D>,
) -> Result<Vec<u8>>
where
    [(); E::PI::TOTAL_LEN]:,
{
    match input {
        CircuitInput::CellsTree(input) => params.cells_tree.generate_proof(input),
        CircuitInput::RowsTree(input) => params
            .rows_tree
            .generate_proof(input, params.cells_tree.vk_set().clone()),
        CircuitInput::BlockTree(input) => {
            params
                .block_tree
                .generate_proof(input, extraction_set, params.rows_tree.set_vk())
        }
        CircuitInput::IVC(input) => params.ivc.generate_proof(input, params.block_tree.set_vk()),
    }
}
