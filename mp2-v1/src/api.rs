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
        self, compute_leaf_mapping_metadata_digest,
        compute_leaf_mapping_of_mappings_metadata_digest, compute_leaf_single_metadata_digest,
        gadgets::column_info::ColumnInfo, identifier_block_column,
        identifier_for_inner_mapping_key_column, identifier_for_mapping_key_column,
        identifier_for_outer_mapping_key_column, identifier_for_value_column,
    },
    MAX_LEAF_NODE_LEN,
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
};
use plonky2::{
    field::types::PrimeField64,
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
#[derive(Debug)]
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

#[derive(Debug)]
pub struct SlotInput {
    /// Slot information of the variable
    pub(crate) slot: u8,
    /// The offset in bytes where to extract this column in a given EVM word
    pub(crate) byte_offset: usize,
    /// The starting offset in `byte_offset` of the bits to be extracted for this column.
    /// The column bits will start at `byte_offset * 8 + bit_offset`.
    pub(crate) bit_offset: usize,
    /// The length (in bits) of the field to extract in the EVM word
    pub(crate) length: usize,
    /// At which EVM word is this column extracted from. For simple variables,
    /// this value should always be 0. For structs that spans more than one EVM word
    // that value should be depending on which section of the struct we are in.
    pub(crate) evm_word: u32,
}

impl From<&ColumnInfo> for SlotInput {
    fn from(column_info: &ColumnInfo) -> Self {
        let slot = u8::try_from(column_info.slot.to_canonical_u64()).unwrap();
        let [byte_offset, bit_offset, length] = [
            column_info.byte_offset,
            column_info.bit_offset,
            column_info.length,
        ]
        .map(|f| usize::try_from(f.to_canonical_u64()).unwrap());
        let evm_word = u32::try_from(column_info.evm_word.to_canonical_u64()).unwrap();

        SlotInput::new(slot, byte_offset, bit_offset, length, evm_word)
    }
}

impl SlotInput {
    pub fn new(
        slot: u8,
        byte_offset: usize,
        bit_offset: usize,
        length: usize,
        evm_word: u32,
    ) -> Self {
        Self {
            slot,
            byte_offset,
            bit_offset,
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

    pub fn bit_offset(&self) -> usize {
        self.bit_offset
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
pub fn merge_metadata_hash<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>(
    contract: Address,
    chain_id: u64,
    extra: Vec<u8>,
    table_a: SlotInputs,
    table_b: SlotInputs,
) -> MetadataHash {
    let md_a = value_metadata::<MAX_COLUMNS, MAX_FIELD_PER_EVM>(
        table_a,
        &contract,
        chain_id,
        extra.clone(),
    );
    let md_b =
        value_metadata::<MAX_COLUMNS, MAX_FIELD_PER_EVM>(table_b, &contract, chain_id, extra);
    let combined = map_to_curve_point(&md_a.to_fields()) + map_to_curve_point(&md_b.to_fields());
    let contract_digest = contract_metadata_digest(&contract);
    // the block id is only added at the index tree level, the rest is combined at the final
    // extraction level.
    combine_digest_and_block(combined + contract_digest)
}

// NOTE: the block id is added at the end of the digest computation only once - this returns only
// the part without the block id
fn value_metadata<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>(
    inputs: SlotInputs,
    contract: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> Digest {
    match inputs {
        SlotInputs::Simple(inputs) => metadata_digest_simple::<MAX_COLUMNS, MAX_FIELD_PER_EVM>(
            inputs, contract, chain_id, extra,
        ),
        SlotInputs::Mapping(inputs) => metadata_digest_mapping::<MAX_COLUMNS, MAX_FIELD_PER_EVM>(
            inputs, contract, chain_id, extra,
        ),
        SlotInputs::MappingOfMappings(inputs) => metadata_digest_mapping_of_mappings::<
            MAX_COLUMNS,
            MAX_FIELD_PER_EVM,
        >(inputs, contract, chain_id, extra),
        SlotInputs::MappingWithLength(mapping_inputs, length_slot) => {
            assert!(!mapping_inputs.is_empty());
            let mapping_slot = mapping_inputs[0].slot;
            let mapping_digest = metadata_digest_mapping::<MAX_COLUMNS, MAX_FIELD_PER_EVM>(
                mapping_inputs,
                contract,
                chain_id,
                extra,
            );
            let length_digest = length_metadata_digest(length_slot, mapping_slot);
            mapping_digest + length_digest
        }
    }
}

/// Compute the table information for the value columns.
fn compute_table_info(
    inputs: Vec<SlotInput>,
    address: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> Vec<ColumnInfo> {
    inputs
        .into_iter()
        .map(|input| {
            let id = identifier_for_value_column(&input, address, chain_id, extra.clone());

            ColumnInfo::new(
                input.slot,
                id,
                input.byte_offset,
                input.bit_offset,
                input.length,
                input.evm_word,
            )
        })
        .collect_vec()
}

fn metadata_digest_simple<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>(
    inputs: Vec<SlotInput>,
    contract: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> Digest {
    let table_info = compute_table_info(inputs, contract, chain_id, extra);
    compute_leaf_single_metadata_digest::<MAX_COLUMNS, MAX_FIELD_PER_EVM>(table_info)
}

fn metadata_digest_mapping<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>(
    inputs: Vec<SlotInput>,
    contract: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> Digest {
    assert!(!inputs.is_empty());
    let slot = inputs[0].slot;

    // Ensure the slot numbers must be same for mapping type.
    let slots_equal = inputs[1..].iter().all(|input| input.slot == slot);
    assert!(slots_equal);

    let table_info = compute_table_info(inputs, contract, chain_id, extra.clone());
    let key_id = identifier_for_mapping_key_column(slot, contract, chain_id, extra);
    compute_leaf_mapping_metadata_digest::<MAX_COLUMNS, MAX_FIELD_PER_EVM>(table_info, slot, key_id)
}

fn metadata_digest_mapping_of_mappings<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>(
    inputs: Vec<SlotInput>,
    contract: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> Digest {
    assert!(!inputs.is_empty());
    let slot = inputs[0].slot;

    // Ensure the slot numbers must be same for mapping type.
    let slots_equal = inputs[1..].iter().all(|input| input.slot == slot);
    assert!(slots_equal);

    let table_info = compute_table_info(inputs, contract, chain_id, extra.clone());
    let outer_key_id =
        identifier_for_outer_mapping_key_column(slot, contract, chain_id, extra.clone());
    let inner_key_id = identifier_for_inner_mapping_key_column(slot, contract, chain_id, extra);
    compute_leaf_mapping_of_mappings_metadata_digest::<MAX_COLUMNS, MAX_FIELD_PER_EVM>(
        table_info,
        slot,
        outer_key_id,
        inner_key_id,
    )
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
pub fn metadata_hash<const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>(
    slot_input: SlotInputs,
    contract_address: &Address,
    chain_id: u64,
    extra: Vec<u8>,
) -> MetadataHash {
    // closure to compute the metadata digest associated to a mapping variable
    let value_digest = value_metadata::<MAX_COLUMNS, MAX_FIELD_PER_EVM>(
        slot_input,
        contract_address,
        chain_id,
        extra,
    );
    // add contract digest
    let contract_digest = contract_metadata_digest(contract_address);
    // compute final hash
    combine_digest_and_block(contract_digest + value_digest)
}
