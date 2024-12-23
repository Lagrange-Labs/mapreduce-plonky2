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
        self, compute_id_with_prefix,
        gadgets::column_info::{ExtractedColumnInfo, InputColumnInfo},
        identifier_block_column, identifier_for_inner_mapping_key_column,
        identifier_for_mapping_key_column, identifier_for_outer_mapping_key_column,
        identifier_for_value_column, ColumnMetadata, INNER_KEY_ID_PREFIX, KEY_ID_PREFIX,
        OUTER_KEY_ID_PREFIX,
    },
    MAX_LEAF_VALUE_LEN, MAX_RECEIPT_LEAF_NODE_LEN,
};
use alloy::primitives::Address;
use anyhow::Result;
use itertools::Itertools;
use log::debug;
use mp2_common::{
    digest::Digest,
    poseidon::H,
    types::HashOutput,
    utils::{Fieldable, ToFields},
};
use plonky2::{
    iop::target::Target,
    plonk::config::{GenericHashOut, Hasher},
};
use serde::{Deserialize, Serialize};

/// Struct containing the expected input MPT Extension/Branch node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputNode {
    pub node: Vec<u8>,
}

// TODO: Specify `NODE_LEN = MAX_LEAF_NODE_LEN` in the generic parameter,
// but it could not work for using `MAPPING_LEAF_NODE_LEN` constant directly.
type ValuesExtractionInput<const MAX_COLUMNS: usize> =
    values_extraction::CircuitInput<512, MAX_COLUMNS>;
type ValuesExtractionParameters<const MAX_COLUMNS: usize> =
    values_extraction::PublicParameters<512, MAX_COLUMNS>;
fn sanity_check() {
    assert_eq!(MAX_RECEIPT_LEAF_NODE_LEN, 512);
}

/// Set of inputs necessary to generate proofs for each circuit employed in the
/// pre-processing stage of LPN
pub enum CircuitInput<const MAX_COLUMNS: usize>
where
    [(); MAX_COLUMNS - 2]:,
    [(); MAX_COLUMNS - 1]:,
    [(); MAX_COLUMNS - 0]:,
{
    /// Contract extraction input
    ContractExtraction(contract_extraction::CircuitInput),
    /// Length extraction input
    LengthExtraction(LengthCircuitInput),
    /// Values extraction input
    ValuesExtraction(ValuesExtractionInput<MAX_COLUMNS>),
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
pub struct PublicParameters<const MAX_COLUMNS: usize>
where
    [(); MAX_COLUMNS - 2]:,
    [(); MAX_COLUMNS - 1]:,
    [(); MAX_COLUMNS - 0]:,
{
    contract_extraction: contract_extraction::PublicParameters,
    length_extraction: length_extraction::PublicParameters,
    values_extraction: ValuesExtractionParameters<MAX_COLUMNS>,
    block_extraction: block_extraction::PublicParameters,
    final_extraction: final_extraction::PublicParameters,
    tree_creation:
        verifiable_db::api::PublicParameters<final_extraction::PublicInputs<'static, Target>>,
}
impl<const MAX_COLUMNS: usize> PublicParameters<MAX_COLUMNS>
where
    [(); MAX_COLUMNS - 2]:,
    [(); MAX_COLUMNS - 1]:,
    [(); MAX_COLUMNS - 0]:,
{
    pub fn get_params_info(&self) -> Result<Vec<u8>> {
        self.tree_creation.get_params_info()
    }
}

/// Instantiate the circuits employed for the pre-processing stage of LPN,
/// returning their corresponding parameters
pub fn build_circuits_params<const MAX_COLUMNS: usize>() -> PublicParameters<MAX_COLUMNS>
where
    [(); MAX_COLUMNS - 2]:,
    [(); MAX_COLUMNS - 1]:,
    [(); MAX_COLUMNS - 0]:,
{
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
pub fn generate_proof<const MAX_COLUMNS: usize>(
    params: &PublicParameters<MAX_COLUMNS>,
    input: CircuitInput<MAX_COLUMNS>,
) -> Result<Vec<u8>>
where
    [(); MAX_COLUMNS - 2]:,
    [(); MAX_COLUMNS - 1]:,
    [(); MAX_COLUMNS - 0]:,
{
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
                final_extraction::CircuitInput::Receipt(input) => params
                    .final_extraction
                    .generate_receipt_proof(input, value_circuit_set),
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
#[derive(Debug, Clone)]
pub enum SlotInputs {
    /// Slots of a set of simple variables or Struct
    /// The slot number should be same for the fields of one Struct.
    Simple(Vec<SlotInput>),
    /// Slot of a mapping variable or Struct
    /// It should be only one input for mapping to simple value, and multiple inputs
    /// for the fields of a Struct. The slot number should be always same for both
    /// mapping to simple value or a Struct.
    Mapping(Vec<SlotInput>),
    /// Slot of a mapping of mappings variable or Struct
    /// It's similiar as mapping type, the mapping value could be simple value or a Struct.
    /// The slot number should be always same.
    MappingOfMappings(Vec<SlotInput>),
    /// Slots of a mapping variable and of a slot containing the length of the mapping
    MappingWithLength(Vec<SlotInput>, u8),
}

impl SlotInputs {
    pub fn to_column_metadata(
        &self,
        contract_address: &Address,
        chain_id: u64,
        extra: Vec<u8>,
    ) -> ColumnMetadata {
        let (slot, extracted_columns) = match self {
            SlotInputs::Simple(ref inner)
            | SlotInputs::Mapping(ref inner)
            | SlotInputs::MappingOfMappings(ref inner)
            | SlotInputs::MappingWithLength(ref inner, ..) => (
                inner[0].slot,
                compute_table_info(inner.to_vec(), contract_address, chain_id, extra.clone()),
            ),
        };

        let num_mapping_keys = match self {
            SlotInputs::Simple(..) => 0usize,
            SlotInputs::Mapping(..) | SlotInputs::MappingWithLength(..) => 1,
            SlotInputs::MappingOfMappings(..) => 2,
        };

        let input_columns = match num_mapping_keys {
            0 => vec![],
            1 => {
                let identifier = compute_id_with_prefix(
                    KEY_ID_PREFIX,
                    slot,
                    contract_address,
                    chain_id,
                    extra.clone(),
                );
                let input_column = InputColumnInfo::new(&[slot], identifier, KEY_ID_PREFIX, 32);
                vec![input_column]
            }
            2 => {
                let outer_identifier = compute_id_with_prefix(
                    OUTER_KEY_ID_PREFIX,
                    slot,
                    contract_address,
                    chain_id,
                    extra.clone(),
                );
                let inner_identifier = compute_id_with_prefix(
                    INNER_KEY_ID_PREFIX,
                    slot,
                    contract_address,
                    chain_id,
                    extra.clone(),
                );
                vec![
                    InputColumnInfo::new(&[slot], outer_identifier, OUTER_KEY_ID_PREFIX, 32),
                    InputColumnInfo::new(&[slot], inner_identifier, INNER_KEY_ID_PREFIX, 32),
                ]
            }
            _ => vec![],
        };

        ColumnMetadata::new(input_columns, extracted_columns)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize, Copy)]
pub struct SlotInput {
    /// Slot information of the variable
    pub(crate) slot: u8,
    /// The offset in bytes where to extract this column in a given EVM word
    pub(crate) byte_offset: usize,
    /// The length (in bits) of the field to extract in the EVM word
    pub(crate) length: usize,
    /// At which EVM word is this column extracted from. For simple variables,
    /// this value should always be 0. For structs that spans more than one EVM word
    // that value should be depending on which section of the struct we are in.
    pub(crate) evm_word: u32,
}

impl From<ExtractedColumnInfo> for SlotInput {
    fn from(value: ExtractedColumnInfo) -> Self {
        let extraction_id = value.extraction_id();
        let slot = extraction_id[0].0 as u8;

        SlotInput {
            slot,
            byte_offset: value.byte_offset().0 as usize,
            length: value.length().0 as usize,
            evm_word: value.location_offset().0 as u32,
        }
    }
}

impl From<&ExtractedColumnInfo> for SlotInput {
    fn from(value: &ExtractedColumnInfo) -> Self {
        let extraction_id = value.extraction_id();
        let slot = extraction_id[0].0 as u8;

        SlotInput {
            slot,
            byte_offset: value.byte_offset().0 as usize,
            length: value.length().0 as usize,
            evm_word: value.location_offset().0 as u32,
        }
    }
}

impl SlotInput {
    pub fn new(slot: u8, byte_offset: usize, length: usize, evm_word: u32) -> Self {
        Self {
            slot,
            byte_offset,
            length,
            evm_word,
        }
    }

    pub fn slot(&self) -> u8 {
        self.slot
    }

    pub fn byte_offset(&self) -> usize {
        self.byte_offset
    }

    pub fn length(&self) -> usize {
        self.length
    }

    pub fn evm_word(&self) -> u32 {
        self.evm_word
    }
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
    let combined = map_to_curve_point(&md_a.to_fields()) + map_to_curve_point(&md_b.to_fields());
    let contract_digest = contract_metadata_digest(&contract);
    // the block id is only added at the index tree level, the rest is combined at the final
    // extraction level.
    combine_digest_and_block(combined + contract_digest)
}

// NOTE: the block id is added at the end of the digest computation only once - this returns only
// the part without the block id
fn value_metadata(inputs: SlotInputs, contract: &Address, chain_id: u64, extra: Vec<u8>) -> Digest {
    let column_metadata = inputs.to_column_metadata(contract, chain_id, extra.clone());

    let md = column_metadata.digest();

    let length_digest = match inputs {
        SlotInputs::Simple(..) | SlotInputs::Mapping(..) | SlotInputs::MappingOfMappings(..) => {
            Digest::NEUTRAL
        }
        SlotInputs::MappingWithLength(mapping_inputs, length_slot) => {
            assert!(!mapping_inputs.is_empty());
            let mapping_slot = mapping_inputs[0].slot;
            length_metadata_digest(length_slot, mapping_slot)
        }
    };
    md + length_digest
}

/// Compute the table information for the value columns.
pub fn compute_table_info(
    inputs: Vec<SlotInput>,
    address: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> Vec<ExtractedColumnInfo> {
    inputs
        .into_iter()
        .map(|input| {
            let id = identifier_for_value_column(&input, address, chain_id, extra.clone());

            ExtractedColumnInfo::new(
                &[input.slot],
                id,
                input.byte_offset,
                input.length,
                input.evm_word,
            )
        })
        .collect_vec()
}

pub fn combine_digest_and_block(digest: Digest) -> HashOutput {
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
    // Correspond to the computation of final extraction base circuit.
    let value_digest = map_to_curve_point(&value_digest.to_fields());
    // add contract digest
    let contract_digest = contract_metadata_digest(contract_address);
    debug!(
        "METADATA_HASH ->\n\tvalues_ext_md = {:?}\n\tcontract_md = {:?}\n\tfinal_ex_md(contract + values_ex) = {:?}",
        value_digest.to_weierstrass(),
        contract_digest.to_weierstrass(),
        (contract_digest + value_digest).to_weierstrass(),
    );
    // compute final hash
    combine_digest_and_block(contract_digest + value_digest)
}
