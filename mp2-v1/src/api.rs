//! Main APIs and related structures

use std::{iter::once, slice};

use crate::{
    block_extraction,
    contract_extraction::{self, compute_metadata_digest as contract_metadata_digest},
    final_extraction,
    length_extraction::{
        self, compute_metadata_digest as length_metadata_digest, LengthCircuitInput,
    },
    values_extraction::{
        self, compute_leaf_mapping_metadata_digest, compute_leaf_single_metadata_digest,
        gadgets::column_info::ColumnInfo, identifier_block_column,
        identifier_for_mapping_key_column, identifier_single_var_column,
    },
    MAX_LEAF_NODE_LEN,
};
use alloy::primitives::Address;
use anyhow::Result;
use itertools::Itertools;
use mp2_common::{
    poseidon::H,
    types::{HashOutput, MAPPING_LEAF_VALUE_LEN},
    utils::{Fieldable, ToFields},
    F,
};
use plonky2::{
    field::types::Field,
    iop::target::Target,
    plonk::config::{GenericHashOut, Hasher},
};
use plonky2_ecgfp5::curve::curve::Point;
use serde::{Deserialize, Serialize};

/// Struct containing the expected input MPT Extension/Branch node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputNode {
    pub node: Vec<u8>,
}

// TODO: Specify `NODE_LEN = MAX_LEAF_NODE_LEN` in the generic parameter,
// but it could not work for using `MAPPING_LEAF_NODE_LEN` constant directly.
type ValuesExtractionInput<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize> =
    values_extraction::CircuitInput<69, MAX_COLUMNS, MAX_FIELD_PER_EVM>;
type ValuesExtractionParameters<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize> =
    values_extraction::PublicParameters<69, MAX_COLUMNS, MAX_FIELD_PER_EVM>;
fn sanity_check() {
    assert_eq!(MAX_LEAF_NODE_LEN, 69);
}

/// Set of inputs necessary to generate proofs for each circuit employed in the
/// pre-processing stage of LPN
pub enum CircuitInput<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize> {
    /// Contract extraction input
    ContractExtraction(contract_extraction::CircuitInput),
    /// Length extraction input
    LengthExtraction(LengthCircuitInput),
    /// Values extraction input
    ValuesExtraction(ValuesExtractionInput<MAX_COLUMNS, MAX_FIELD_PER_EVM>),
    /// Block extraction necessary input
    BlockExtraction(block_extraction::CircuitInput),
    /// Final extraction input
    FinalExtraction(final_extraction::CircuitInput),
    /// Cells tree creation input
    CellsTree(verifiable_db::cells_tree::CircuitInput),
    /// Rows tree creation input
    RowsTree(verifiable_db::row_tree::CircuitInput),
    /// Block tree creation input
    BlockTree(verifiable_db::block_tree::CircuitInput),
    /// recursive IVC proof to prove updates of a table
    IVC(verifiable_db::ivc::CircuitInput),
}

#[derive(Serialize, Deserialize)]
/// Parameters defining all the circuits employed for the pre-processing stage of LPN
pub struct PublicParameters<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize> {
    contract_extraction: contract_extraction::PublicParameters,
    length_extraction: length_extraction::PublicParameters,
    values_extraction: ValuesExtractionParameters<MAX_COLUMNS, MAX_FIELD_PER_EVM>,
    block_extraction: block_extraction::PublicParameters,
    final_extraction: final_extraction::PublicParameters,
    tree_creation:
        verifiable_db::api::PublicParameters<final_extraction::PublicInputs<'static, Target>>,
}
impl<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>
    PublicParameters<MAX_COLUMNS, MAX_FIELD_PER_EVM>
{
    pub fn get_params_info(&self) -> Result<Vec<u8>> {
        self.tree_creation.get_params_info()
    }
}

/// Instantiate the circuits employed for the pre-processing stage of LPN,
/// returning their corresponding parameters
pub fn build_circuits_params<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>(
) -> PublicParameters<MAX_COLUMNS, MAX_FIELD_PER_EVM> {
    sanity_check();

    log::info!("Building contract_extraction parameters...");
    let contract_extraction = contract_extraction::build_circuits_params();
    log::info!("Building length_extraction parameters...");
    let length_extraction = length_extraction::PublicParameters::build();
    log::info!("Building values_extraction parameters...");
    let values_extraction = values_extraction::build_circuits_params();
    log::info!("Building block_extraction parameters...");
    let block_extraction = block_extraction::build_circuits_params();
    log::info!("Building final_extraction parameters...");
    let final_extraction = final_extraction::PublicParameters::build(
        block_extraction.circuit_data().verifier_data(),
        contract_extraction.get_circuit_set(),
        values_extraction.get_circuit_set(),
        length_extraction.get_circuit_set(),
    );
    let tree_creation =
        verifiable_db::api::build_circuits_params(final_extraction.get_circuit_set());
    log::info!("All parameters built!");

    PublicParameters {
        contract_extraction,
        values_extraction,
        length_extraction,
        block_extraction,
        final_extraction,
        tree_creation,
    }
}

/// Generate a proof for a circuit in the set of circuits employed in the
/// pre-processing stage of LPN, employing `CircuitInput` to specify for which
/// circuit the proof should be generated
pub fn generate_proof<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>(
    params: &PublicParameters<MAX_COLUMNS, MAX_FIELD_PER_EVM>,
    input: CircuitInput<MAX_COLUMNS, MAX_FIELD_PER_EVM>,
) -> Result<Vec<u8>> {
    match input {
        CircuitInput::ContractExtraction(input) => {
            contract_extraction::generate_proof(&params.contract_extraction, input)
        }
        CircuitInput::LengthExtraction(input) => params.length_extraction.generate_proof(input),
        CircuitInput::ValuesExtraction(input) => {
            values_extraction::generate_proof(&params.values_extraction, input)
        }
        CircuitInput::BlockExtraction(input) => params.block_extraction.generate_proof(input),
        CircuitInput::FinalExtraction(input) => {
            let contract_circuit_set = params.contract_extraction.get_circuit_set();
            let value_circuit_set = params.values_extraction.get_circuit_set();
            match input {
                final_extraction::CircuitInput::Simple(input) => params
                    .final_extraction
                    .generate_simple_proof(input, contract_circuit_set, value_circuit_set),
                final_extraction::CircuitInput::Lengthed(input) => {
                    let length_circuit_set = params.length_extraction.get_circuit_set();
                    params.final_extraction.generate_lengthed_proof(
                        input,
                        contract_circuit_set,
                        value_circuit_set,
                        length_circuit_set,
                    )
                }
            }
        }
        CircuitInput::CellsTree(input) => verifiable_db::api::generate_proof(
            &params.tree_creation,
            verifiable_db::api::CircuitInput::CellsTree(input),
            params.final_extraction.get_circuit_set(),
        ),
        CircuitInput::RowsTree(input) => verifiable_db::api::generate_proof(
            &params.tree_creation,
            verifiable_db::api::CircuitInput::RowsTree(input),
            params.final_extraction.get_circuit_set(),
        ),
        CircuitInput::BlockTree(input) => verifiable_db::api::generate_proof(
            &params.tree_creation,
            verifiable_db::api::CircuitInput::BlockTree(input),
            params.final_extraction.get_circuit_set(),
        ),
        CircuitInput::IVC(input) => verifiable_db::api::generate_proof(
            &params.tree_creation,
            verifiable_db::api::CircuitInput::IVC(input),
            params.final_extraction.get_circuit_set(),
        ),
    }
}

pub type MetadataHash = HashOutput;

/// Enumeration to be employed to provide input slots for metadata hash computation
pub enum SlotInputs {
    /// slots of a set of simple variables
    Simple(Vec<u8>),
    /// slot of a mapping variable without an associated length slot to determine the number of entries
    Mapping(u8),
    /// slots of a mapping variable and of a slot containing the length of the mapping
    MappingWithLength(u8, u8),
}

/// Compute metadata hash for a table related to the provided inputs slots of the contract with
/// address `contract_address`
pub fn metadata_hash<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>(
    slot_input: SlotInputs,
    contract_address: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> MetadataHash {
    // closure to compute the metadata digest associated to a mapping variable
    let metadata_digest_mapping = |slot| {
        // TODO: Need to check. We use length of `32` to compute the table metadata hash for now.
        let length = F::from_canonical_usize(MAPPING_LEAF_VALUE_LEN);
        let key_id = F::from_canonical_u64(identifier_for_mapping_key_column(
            slot,
            contract_address,
            chain_id,
            extra.clone(),
        ));
        // TODO: Need to check. We use `key_id` also as the column identifier.
        let column_info = ColumnInfo::new(
            F::from_canonical_u8(slot),
            key_id,
            F::ZERO,
            F::ZERO,
            length,
            F::ZERO,
        );
        let column_identifier = column_info.identifier;
        compute_leaf_mapping_metadata_digest::<MAX_COLUMNS, MAX_FIELD_PER_EVM>(
            vec![column_info],
            slice::from_ref(&column_identifier),
            1,
            0,
            slot,
            key_id,
        )
    };
    let digest = match slot_input {
        SlotInputs::Simple(slots) => {
            let table_info = slots
                .into_iter()
                .map(|slot| {
                    let identifier = F::from_canonical_u64(identifier_single_var_column(
                        slot,
                        0,
                        contract_address,
                        chain_id,
                        vec![],
                    ));

                    let slot = F::from_canonical_u8(slot);
                    // TODO: We use length of `32` to compute the table metadata hash here.
                    let length = F::from_canonical_usize(MAPPING_LEAF_VALUE_LEN);

                    ColumnInfo::new(slot, identifier, F::ZERO, F::ZERO, length, F::ZERO)
                })
                .collect_vec();
            let num_actual_columns = table_info.len();
            table_info.iter().fold(Point::NEUTRAL, |acc, column_info| {
                let digest = compute_leaf_single_metadata_digest::<MAX_COLUMNS, MAX_FIELD_PER_EVM>(
                    table_info.clone(),
                    slice::from_ref(&column_info.identifier),
                    num_actual_columns,
                    0,
                );
                acc + digest
            })
        }
        SlotInputs::Mapping(slot) => metadata_digest_mapping(slot),
        SlotInputs::MappingWithLength(mapping_slot, length_slot) => {
            let mapping_digest = metadata_digest_mapping(mapping_slot);
            let length_digest = length_metadata_digest(length_slot, mapping_slot);
            mapping_digest + length_digest
        }
    };
    // add contract digest
    let contract_digest = contract_metadata_digest(contract_address);
    let final_digest = contract_digest + digest;
    // compute final hash
    let block_id = identifier_block_column();
    let inputs = final_digest
        .to_fields()
        .into_iter()
        .chain(once(block_id.to_field()))
        .collect_vec();
    HashOutput::try_from(H::hash_no_pad(&inputs).to_bytes()).unwrap()
}
