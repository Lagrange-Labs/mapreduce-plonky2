//! Main APIs and related structures

use std::iter::once;

use crate::{
    block_extraction,
    contract_extraction::{self, compute_metadata_digest as contract_metadata_digest},
    final_extraction,
    length_extraction::{
        self, compute_metadata_digest as length_metadata_digest, LengthCircuitInput,
    },
    values_extraction::{
        self, compute_leaf_mapping_metadata_digest, compute_leaf_single_metadata_digest,
        identifier_block_column, identifier_for_mapping_key_column,
        identifier_for_mapping_value_column, identifier_single_var_column,
    },
};
use alloy::primitives::Address;
use anyhow::Result;
use itertools::Itertools;
use mp2_common::{
    digest::Digest,
    group_hashing::map_to_curve_point,
    poseidon::H,
    types::HashOutput,
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
use verifiable_db::query::computational_hash_ids::ColumnIDs;

/// Struct containing the expected input MPT Extension/Branch node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputNode {
    pub node: Vec<u8>,
}

/// Set of inputs necessary to generate proofs for each circuit employed in the
/// pre-processing stage of LPN
pub enum CircuitInput {
    /// Contract extraction input
    ContractExtraction(contract_extraction::CircuitInput),
    /// Length extraction input
    LengthExtraction(LengthCircuitInput),
    /// Values extraction input
    ValuesExtraction(values_extraction::CircuitInput),
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
pub struct PublicParameters {
    contract_extraction: contract_extraction::PublicParameters,
    length_extraction: length_extraction::PublicParameters,
    values_extraction: values_extraction::PublicParameters,
    block_extraction: block_extraction::PublicParameters,
    final_extraction: final_extraction::PublicParameters,
    tree_creation:
        verifiable_db::api::PublicParameters<final_extraction::PublicInputs<'static, Target>>,
}
impl PublicParameters {
    pub fn get_params_info(&self) -> Result<Vec<u8>> {
        self.tree_creation.get_params_info()
    }
}

/// Instantiate the circuits employed for the pre-processing stage of LPN,
/// returning their corresponding parameters
pub fn build_circuits_params() -> PublicParameters {
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
pub fn generate_proof(params: &PublicParameters, input: CircuitInput) -> Result<Vec<u8>> {
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
                final_extraction::CircuitInput::MergeTable(input) => params
                    .final_extraction
                    .generate_merge_proof(input, contract_circuit_set, value_circuit_set),
                final_extraction::CircuitInput::Lengthed(input) => {
                    let length_circuit_set = params.length_extraction.get_circuit_set();
                    params.final_extraction.generate_lengthed_proof(
                        input,
                        contract_circuit_set,
                        value_circuit_set,
                        length_circuit_set,
                    )
                }
                final_extraction::CircuitInput::NoProvable(input) => {
                    params.final_extraction.generate_no_provable_proof(input)
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

/// Compute metadata hash for a "merge" table. Right now it supports only merging tables from the
/// same address.
pub fn merge_metadata_hash(
    contract: Address,
    chain_id: u64,
    extra: Vec<u8>,
    table_a: SlotInputs,
    table_b: SlotInputs,
) -> MetadataHash {
    let md_a = value_metadata(table_a, &contract, chain_id, extra.clone());
    let md_b = value_metadata(table_b, &contract, chain_id, extra);
    let combined = md_a + md_b;
    let contract_digest = contract_metadata_digest(&contract);
    // the block id is only added at the index tree level, the rest is combined at the final
    // extraction level.
    combine_digest_and_block(combined + contract_digest)
}

// NOTE: the block id is added at the end of the digest computation only once - this returns only
// the part without the block id
fn value_metadata(inputs: SlotInputs, contract: &Address, chain_id: u64, extra: Vec<u8>) -> Digest {
    match inputs {
        SlotInputs::Simple(slots) => slots.iter().fold(Point::NEUTRAL, |acc, &slot| {
            let id = identifier_single_var_column(slot, contract, chain_id, extra.clone());
            let digest = compute_leaf_single_metadata_digest(id, slot);
            acc + digest
        }),
        SlotInputs::Mapping(slot) => metadata_digest_mapping(contract, chain_id, extra, slot),
        SlotInputs::MappingWithLength(mapping_slot, length_slot) => {
            let mapping_digest = metadata_digest_mapping(contract, chain_id, extra, mapping_slot);
            let length_digest = length_metadata_digest(length_slot, mapping_slot);
            mapping_digest + length_digest
        }
    }
}
fn metadata_digest_mapping(address: &Address, chain_id: u64, extra: Vec<u8>, slot: u8) -> Digest {
    let key_id = identifier_for_mapping_key_column(slot, address, chain_id, extra.clone());
    let value_id = identifier_for_mapping_value_column(slot, address, chain_id, extra.clone());
    compute_leaf_mapping_metadata_digest(key_id, value_id, slot)
}

fn combine_digest_and_block(digest: Digest) -> HashOutput {
    let block_id = identifier_block_column();
    let inputs = digest
        .to_fields()
        .into_iter()
        .chain(once(block_id.to_field()))
        .collect_vec();
    HashOutput::try_from(H::hash_no_pad(&inputs).to_bytes()).unwrap()
}
/// Compute metadata hash for a table related to the provided inputs slots of the contract with
/// address `contract_address`
pub fn metadata_hash(
    slot_input: SlotInputs,
    contract_address: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> MetadataHash {
    // closure to compute the metadata digest associated to a mapping variable
    let value_digest = value_metadata(slot_input, contract_address, chain_id, extra);
    // add contract digest
    let contract_digest = contract_metadata_digest(contract_address);
    // compute final hash
    combine_digest_and_block(contract_digest + value_digest)
}

// compute metadata digest for a table including no provable extraction data:
// it corresponds to the digest of the column identifiers
pub(crate) fn no_provable_metadata_digest(column_ids: &ColumnIDs) -> Digest {
    map_to_curve_point(
        &vec![column_ids.primary_column(), column_ids.secondary_column()]
            .into_iter()
            .chain(column_ids.non_indexed_columns())
            .map(|id| F::from_canonical_u64(id))
            .collect_vec(),
    )
}

/// Compute the metadata hash for a table including no provable extraction data.
/// The input is the set of the column identifiers of the table
pub fn no_provable_metadata_hash(column_ids: &ColumnIDs) -> MetadataHash {
    let metadata_digest = no_provable_metadata_digest(column_ids);
    // Add the prefix to the metadata digest to ensure the metadata digest
    // will keep track of whether we use this dummy circuit or not.
    // It's similar logic as the dummy circuit of final extraction.
    let prefix = final_extraction::DUMMY_METADATA_DIGEST_PREFIX.to_fields();
    let inputs = prefix
        .into_iter()
        .chain(metadata_digest.to_fields())
        .collect_vec();
    let digest = map_to_curve_point(&inputs);

    combine_digest_and_block(digest)
}
