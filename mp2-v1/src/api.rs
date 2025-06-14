//! Main APIs and related structures

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    hash::Hash,
    iter::once,
};

use crate::{
    block_extraction,
    contract_extraction::{self, compute_metadata_digest as contract_metadata_digest},
    final_extraction,
    indexing::{cell::Cell, ColumnID},
    length_extraction::{
        self, compute_metadata_digest as length_metadata_digest, LengthCircuitInput,
    },
    values_extraction::{
        self, compute_leaf_mapping_metadata_digest,
        compute_leaf_mapping_of_mappings_metadata_digest, compute_leaf_single_metadata_digest,
        compute_table_row_digest, gadgets::column_info::ColumnInfo, identifier_block_column,
        identifier_for_inner_mapping_key_column, identifier_for_mapping_key_column,
        identifier_for_outer_mapping_key_column, identifier_for_value_column, ColumnId,
    },
    F, H, MAX_LEAF_NODE_LEN,
};
use alloy::primitives::{Address, U256};
use anyhow::Result;
use itertools::Itertools;
use log::debug;
use mp2_common::{
    digest::Digest,
    group_hashing::map_to_curve_point,
    poseidon::{flatten_poseidon_hash_value, FLATTEN_POSEIDON_LEN},
    types::HashOutput,
    utils::{Endianness, Fieldable, Packer, ToFields},
};
use plonky2::{
    field::types::{Field, PrimeField64},
    iop::target::Target,
    plonk::config::{GenericHashOut, Hasher},
};
use serde::{Deserialize, Serialize};
use verifiable_db::{
    block_tree::add_primary_index_to_digest, ivc::add_provable_data_commitment_prefix,
};

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
#[derive(Serialize, Deserialize)]
pub enum CircuitInput<const MAX_COLUMNS: usize> {
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

pub const MAX_FIELD_PER_EVM: usize = 16;

#[derive(Serialize, Deserialize)]
/// Parameters defining all the circuits employed for the pre-processing stage of LPN
pub struct PublicParameters<const MAX_COLUMNS: usize> {
    contract_extraction: contract_extraction::PublicParameters,
    length_extraction: length_extraction::PublicParameters,
    values_extraction: ValuesExtractionParameters<MAX_COLUMNS, MAX_FIELD_PER_EVM>,
    block_extraction: block_extraction::PublicParameters,
    final_extraction: final_extraction::PublicParameters,
    tree_creation:
        verifiable_db::api::PublicParameters<final_extraction::PublicInputs<'static, Target>>,
}
impl<const MAX_COLUMNS: usize> PublicParameters<MAX_COLUMNS> {
    pub fn get_params_info(&self) -> Result<Vec<u8>> {
        self.tree_creation.get_params_info()
    }

    /// Get the a proof of for an empty cell tree.
    pub fn empty_cell_tree_proof(&self) -> Result<Vec<u8>> {
        self.tree_creation.empty_cell_tree_proof()
    }
}

/// Instantiate the circuits employed for the pre-processing stage of LPN,
/// returning their corresponding parameters
pub fn build_circuits_params<const MAX_COLUMNS: usize>() -> PublicParameters<MAX_COLUMNS> {
    sanity_check();

    assert!(MAX_COLUMNS >= MAX_FIELD_PER_EVM,
        "MAX_COLUMNS must be greater than the maximum number of fields extarcted per evm word, which is 
        {MAX_FIELD_PER_EVM}; please, instantiate the `PublicParameters` with a big enough value"
    );

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

#[derive(Clone, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
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

impl From<&ColumnInfo> for SlotInput {
    fn from(column_info: &ColumnInfo) -> Self {
        let slot = u8::try_from(column_info.slot.to_canonical_u64()).unwrap();
        let [byte_offset, length] = [column_info.byte_offset, column_info.length]
            .map(|f| usize::try_from(f.to_canonical_u64()).unwrap());
        let evm_word = u32::try_from(column_info.evm_word.to_canonical_u64()).unwrap();

        SlotInput::new(slot, byte_offset, length, evm_word)
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
pub fn merge_metadata_hash<const MAX_COLUMNS: usize>(
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
pub fn compute_table_info(
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
                0, // bit_offset
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
pub fn metadata_hash<const MAX_COLUMNS: usize>(
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

// compute metadata digest for a table including no provable extraction data:
// it corresponds to the digest of the column identifiers
pub(crate) fn no_provable_metadata_digest<I: IntoIterator<Item = ColumnID>>(
    column_ids: I,
) -> Digest {
    map_to_curve_point(
        &column_ids
            .into_iter()
            .collect::<BTreeSet<_>>() // collect into a BTreeSet to ensure they are hashed
            // in a deterministic order
            .into_iter()
            .map(F::from_canonical_u64)
            .collect_vec(),
    )
}

/// Compute the metadata hash for a table including no provable extraction data.
/// The input is the set of the column identifiers of the table.
/// The input flag `provable_data_commitment` must be true if the root of trust being
/// used to verify proofs over the table must be a commitment provably computed from the data
/// inserted in the table, false when the root of trust is instead an existing
/// commitment computed elsewhere (e.g., a block hash).
pub fn no_provable_metadata_hash<I: IntoIterator<Item = ColumnID>>(
    column_ids: I,
    provable_data_commitment: bool,
) -> MetadataHash {
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

    let metadata_hash = combine_digest_and_block(digest);
    if provable_data_commitment {
        // add the data commitment prefix to the metadata hash, to keep track
        // of whether a commitment to the data of the table is used as root of trust
        add_provable_data_commitment_prefix(metadata_hash)
    } else {
        metadata_hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
/// Data about a row for a table provided as input to APIs
pub struct TableRow {
    pub(crate) primary_index_column: Cell,
    pub(crate) other_columns: BTreeMap<ColumnID, U256>,
}

impl TableRow {
    pub fn new(primary_index_column: Cell, other_columns: Vec<Cell>) -> Self {
        Self {
            primary_index_column,
            other_columns: other_columns
                .into_iter()
                .map(|c| (c.identifier(), c.value()))
                .collect(),
        }
    }

    pub(crate) fn column_ids(&self) -> Vec<ColumnID> {
        self.other_columns.keys().copied().collect()
    }

    pub(crate) fn find_by_column_id(&self, id: ColumnID) -> Option<U256> {
        once((
            &self.primary_index_column.identifier(),
            &self.primary_index_column.value(),
        ))
        .chain(&self.other_columns)
        .find_map(
            |(column_id, value)| {
                if *column_id == id {
                    Some(*value)
                } else {
                    None
                }
            },
        )
    }
}

impl AsRef<TableRow> for TableRow {
    fn as_ref(&self) -> &TableRow {
        self
    }
}

/// Incrementally update the provable commitment for the data of an off-chain table.
/// It computes an updated commitment taking as input the new rows and the previously
/// computed commitment, if any.  
pub fn update_off_chain_data_commitment(
    new_rows: &[TableRow],
    old_commitment: Option<HashOutput>,
    row_unique_columns: &[ColumnId],
) -> Result<HashOutput> {
    // first, group rows by increasing values of primary index values
    let mut grouped_rows = BTreeMap::new();
    for row in new_rows {
        let primary = row.primary_index_column.value();
        grouped_rows
            .entry(primary)
            .and_modify(|rows: &mut Vec<_>| rows.push(row))
            .or_insert(vec![row]);
    }

    let old_commitment: [F; FLATTEN_POSEIDON_LEN] = old_commitment
        .unwrap_or_default()
        .as_ref()
        .pack(Endianness::Little)
        .into_iter()
        .map(F::from_canonical_u32)
        .collect_vec()
        .try_into()
        .unwrap();
    // then, for each group of rows with the same primary index, update the commitment
    let new_commitment =
        grouped_rows
            .into_iter()
            .try_fold(old_commitment, |commitment, (primary, rows)| {
                let row_digest = compute_table_row_digest(&rows, row_unique_columns)?;
                let primary_index_column = rows[0].primary_index_column.identifier();
                // add primary index value to digest
                let digest = add_primary_index_to_digest(primary_index_column, primary, row_digest);
                // compute the new commitment
                let payload = commitment
                    .into_iter()
                    .chain(digest.to_fields())
                    .collect_vec();
                anyhow::Ok(flatten_poseidon_hash_value(H::hash_no_pad(&payload)))
            })?;
    // convert to bytes
    // hash the digest
    let hash_bytes = new_commitment
        .into_iter()
        .flat_map(|f| (f.to_canonical_u64() as u32).to_le_bytes())
        .collect_vec();
    Ok(HashOutput::try_from(hash_bytes).unwrap())
}

/// Compute the provable commitment to the data found in an off-chain table
pub fn off_chain_data_commitment(
    table_rows: &[TableRow],
    row_unique_columns: &[ColumnId],
) -> Result<HashOutput> {
    update_off_chain_data_commitment(table_rows, None, row_unique_columns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_serialisation() {
        const MAX_COLUMNS: usize = 20;
        let params_1 = build_circuits_params::<MAX_COLUMNS>();
        let serialised_1 = bincode::serialize(&params_1).unwrap();

        let params_2 = build_circuits_params::<MAX_COLUMNS>();
        let serialised_2 = bincode::serialize(&params_2).unwrap();

        serialised_1
            .iter()
            .zip(serialised_2.iter())
            .enumerate()
            .for_each(|(index, (&byte_1, &byte_2))| {
                assert_eq!(
                    byte_1, byte_2,
                    "Parameter serialisations not the same, discrepancy occurs at index: {index}"
                )
            })
    }
}
