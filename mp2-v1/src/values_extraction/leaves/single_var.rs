//! Module handling the single variable inside a storage trie

use crate::values_extraction::{
    gadgets::{
        column_gadget::ColumnGadget,
        column_info::{
            CircuitBuilderColumnInfo, ColumnInfo, ColumnInfoTarget, WitnessWriteColumnInfo,
        },
        metadata_gadget::MetadataGadget,
    },
    public_inputs::{PublicInputs, PublicInputsArgs},
};
use mp2_common::{
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires},
    mpt_sequential::{
        utils::left_pad_leaf_value, MPTLeafOrExtensionNode, MAX_LEAF_VALUE_LEN, PAD_LEN,
    },
    poseidon::{empty_poseidon_hash, hash_to_int_target},
    public_inputs::PublicInputCommon,
    serialization::{
        deserialize_array, deserialize_long_array, serialize_array, serialize_long_array,
    },
    storage_key::{SimpleSlot, SimpleSlotWires},
    types::{CBuilder, GFp, MAPPING_LEAF_VALUE_LEN},
    utils::{Endianness, PackerTarget, ToTargets},
    CHasher, D, F,
};
use plonky2::{
    field::types::Field,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use serde::{Deserialize, Serialize};
use std::{array, iter::once};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LeafSingleVarWires<
    const NODE_LEN: usize,
    const MAX_COLUMNS: usize,
    const MAX_FIELD_PER_EVM: usize,
> where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// Full node from the MPT proof
    node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    /// Leaf value
    value: Array<Target, MAPPING_LEAF_VALUE_LEN>,
    /// MPT root
    root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
    /// Storage single variable slot
    slot: SimpleSlotWires,
    /// Index denoting which EVM word are we looking at for the given variable
    pub(crate) evm_word: Target,
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    /// Boolean flags specifying whether the i-th column is a column of the table or not
    pub(crate) is_actual_columns: [BoolTarget; MAX_COLUMNS],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    /// Boolean flags specifying whether the i-th field being processed has to be extracted into a column or not
    pub(crate) is_extracted_columns: [BoolTarget; MAX_COLUMNS],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    /// Information about all columns of the table
    pub(crate) table_info: [ColumnInfoTarget; MAX_COLUMNS],
}

/// Circuit to prove the correct derivation of the MPT key from a simple slot
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafSingleVarCircuit<
    const NODE_LEN: usize,
    const MAX_COLUMNS: usize,
    const MAX_FIELD_PER_EVM: usize,
> {
    pub(crate) node: Vec<u8>,
    pub(crate) slot: SimpleSlot,
    pub(crate) evm_word: F,
    pub(crate) num_actual_columns: usize,
    pub(crate) num_extracted_columns: usize,
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) table_info: [ColumnInfo; MAX_COLUMNS],
}

impl<const NODE_LEN: usize, const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>
    LeafSingleVarCircuit<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub fn build(b: &mut CBuilder) -> LeafSingleVarWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM> {
        let evm_word = b.add_virtual_target();
        let table_info = array::from_fn(|_| b.add_virtual_column_info());
        let [is_actual_columns, is_extracted_columns] =
            array::from_fn(|_| array::from_fn(|_| b.add_virtual_bool_target_safe()));

        let slot = SimpleSlot::build_with_offset(b, evm_word);

        // Range check for the slot to restrict it's an Uint8.
        b.range_check(slot.slot, 8);
        // Range check for the EVM word to restrict it's an Uint32.
        b.range_check(evm_word, 32);

        // Build the node wires.
        let wires =
            MPTLeafOrExtensionNode::build_and_advance_key::<_, D, NODE_LEN, MAX_LEAF_VALUE_LEN>(
                b,
                &slot.mpt_key,
            );
        let node = wires.node;
        let root = wires.root;

        // Left pad the leaf value.
        let value: Array<Target, MAPPING_LEAF_VALUE_LEN> = left_pad_leaf_value(b, &wires.value);

        // Compute the metadata digest.
        let metadata_digest = MetadataGadget::<_, MAX_FIELD_PER_EVM>::new(
            &table_info,
            &is_actual_columns,
            &is_extracted_columns,
            evm_word,
            slot.slot,
        )
        .build(b);

        // Compute the values digest.
        let values_digest = ColumnGadget::<MAX_FIELD_PER_EVM>::new(
            &value.arr,
            &table_info[..MAX_FIELD_PER_EVM],
            &is_extracted_columns[..MAX_FIELD_PER_EVM],
        )
        .build(b);

        // row_id = H2int(H("") || metadata_digest)
        let empty_hash = b.constant_hash(*empty_poseidon_hash());
        let inputs = empty_hash
            .to_targets()
            .into_iter()
            .chain(metadata_digest.to_targets())
            .collect();
        let hash = b.hash_n_to_hash_no_pad::<CHasher>(inputs);
        let row_id = hash_to_int_target(b, hash);

        // value_digest = value_digest * row_id
        let row_id = b.biguint_to_nonnative(&row_id);
        let values_digest = b.curve_scalar_mul(values_digest, &row_id);

        // Only one leaf in this node.
        let n = b.one();

        // Register the public inputs.
        PublicInputsArgs {
            h: &root.output_array,
            k: &wires.key,
            dv: values_digest,
            dm: metadata_digest,
            n,
        }
        .register(b);

        LeafSingleVarWires {
            node,
            value,
            root,
            slot,
            table_info,
            is_actual_columns,
            is_extracted_columns,
            evm_word,
        }
    }

    pub fn assign(
        &self,
        pw: &mut PartialWitness<GFp>,
        wires: &LeafSingleVarWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>,
    ) {
        let padded_node =
            Vector::<u8, { PAD_LEN(NODE_LEN) }>::from_vec(&self.node).expect("Invalid node");
        wires.node.assign(pw, &padded_node);
        KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&padded_node),
        );
        self.slot.assign(pw, &wires.slot);
        pw.set_target(wires.evm_word, self.evm_word);
        wires
            .is_actual_columns
            .iter()
            .enumerate()
            .for_each(|(i, t)| pw.set_bool_target(*t, i < self.num_actual_columns));
        wires
            .is_extracted_columns
            .iter()
            .enumerate()
            .for_each(|(i, t)| pw.set_bool_target(*t, i < self.num_extracted_columns));
        pw.set_column_info_target_arr(&wires.table_info, &self.table_info);
    }
}
