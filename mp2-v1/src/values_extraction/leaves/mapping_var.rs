//! Module handling the mapping entries inside a storage trie

use crate::{
    values_extraction::{
        gadgets::{
            column_gadget::ColumnGadget,
            column_info::{
                CircuitBuilderColumnInfo, ColumnInfo, ColumnInfoTarget, WitnessWriteColumnInfo,
            },
            metadata_gadget::MetadataGadget,
        },
        public_inputs::{PublicInputs, PublicInputsArgs},
        KEY_ID_PREFIX,
    },
    MAX_LEAF_NODE_LEN,
};
use itertools::Itertools;
use mp2_common::{
    array::{Array, Vector, VectorWire},
    group_hashing::CircuitBuilderGroupHashing,
    keccak::{InputData, KeccakCircuit, KeccakWires},
    mpt_sequential::{
        utils::left_pad_leaf_value, MPTLeafOrExtensionNode, MAX_LEAF_VALUE_LEN, PAD_LEN,
    },
    poseidon::hash_to_int_target,
    public_inputs::PublicInputCommon,
    serialization::{
        deserialize_array, deserialize_long_array, serialize_array, serialize_long_array,
    },
    storage_key::{MappingSlot, MappingSlotWires, SimpleSlot, SimpleSlotWires},
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
use std::{
    array, iter,
    iter::{once, repeat},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LeafMappingVarWires<
    const NODE_LEN: usize,
    const MAX_COLUMNS: usize,
    const MAX_FIELD_PER_EVM: usize,
> where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// Full node from the MPT proof
    pub(crate) node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    /// Leaf value
    pub(crate) value: Array<Target, MAPPING_LEAF_VALUE_LEN>,
    /// MPT root
    pub(crate) root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
    /// Storage mapping variable slot
    pub(crate) slot: MappingSlotWires,
    /// Identifier of the column of the table storing the key of the current mapping entry
    pub(crate) key_id: Target,
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

/// Circuit to prove the correct derivation of the MPT key from a mapping slot
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafMappingVarCircuit<
    const NODE_LEN: usize,
    const MAX_COLUMNS: usize,
    const MAX_FIELD_PER_EVM: usize,
> where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub(crate) node: Vec<u8>,
    pub(crate) slot: MappingSlot,
    pub(crate) key_id: F,
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
    LeafMappingVarCircuit<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub fn build(
        b: &mut CBuilder,
    ) -> LeafMappingVarWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM> {
        let zero = b.zero();

        let key_id = b.add_virtual_target();
        let evm_word = b.add_virtual_target();
        let table_info = array::from_fn(|_| b.add_virtual_column_info());
        let [is_actual_columns, is_extracted_columns] =
            array::from_fn(|_| array::from_fn(|_| b.add_virtual_bool_target_safe()));

        let slot = MappingSlot::mpt_key_with_offset(b, evm_word);

        // Build the node wires.
        let wires =
            MPTLeafOrExtensionNode::build_and_advance_key::<_, D, NODE_LEN, MAX_LEAF_VALUE_LEN>(
                b,
                &slot.keccak_mpt.mpt_key,
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
            slot.mapping_slot,
        )
        .build(b);

        // key_column_md = H( "KEY" || slot)
        let key_id_prefix = b.constant(F::from_canonical_u32(u32::from_be_bytes(
            once(0_u8)
                .chain(KEY_ID_PREFIX.iter().cloned())
                .collect_vec()
                .try_into()
                .unwrap(),
        )));
        let inputs = vec![key_id_prefix, slot.mapping_slot];
        let key_column_md = b.hash_n_to_hash_no_pad::<CHasher>(inputs);
        // Add the information related to the key to the metadata.
        // metadata_digest += D(key_column_md || key_id)
        let inputs = key_column_md
            .to_targets()
            .into_iter()
            .chain(once(key_id))
            .collect_vec();
        let metadata_key_digest = b.map_to_curve_point(&inputs);
        let metadata_digest = b.add_curve_point(&[metadata_digest, metadata_key_digest]);

        // Compute the values digest.
        let values_digest = ColumnGadget::<MAX_FIELD_PER_EVM>::new(
            &value.arr,
            &table_info[..MAX_FIELD_PER_EVM],
            &is_extracted_columns[..MAX_FIELD_PER_EVM],
        )
        .build(b);

        // values_digest += evm_word == 0 ? D(key_id || pack(left_pad32(key))) : CURVE_ZERO
        let inputs: Vec<_> = iter::once(key_id)
            .chain(slot.mapping_key.arr.pack(b, Endianness::Big))
            .collect();
        let values_key_digest = b.map_to_curve_point(&inputs);
        let is_evm_word_zero = b.is_equal(evm_word, zero);
        let curve_zero = b.curve_zero();
        let values_key_digest = b.curve_select(is_evm_word_zero, values_key_digest, curve_zero);
        let new_values_digest = b.add_curve_point(&[values_digest, values_key_digest]);

        // Compute the unique data to identify a row is the mapping key.
        // row_unique_data = H(key)
        let row_unique_data = b.hash_n_to_hash_no_pad::<CHasher>(slot.mapping_key.arr.to_vec());
        // row_id = H2int(row_unique_data || metadata_digest)
        let inputs = slot
            .mapping_key
            .arr
            .into_iter()
            .chain(metadata_digest.to_targets())
            .collect();
        let hash = b.hash_n_to_hash_no_pad::<CHasher>(inputs);
        let row_id = hash_to_int_target(b, hash);
        let row_id = b.biguint_to_nonnative(&row_id);

        // values_digest = values_digest * row_id
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

        LeafMappingVarWires {
            node,
            value,
            root,
            slot,
            key_id,
            evm_word,
            is_actual_columns,
            is_extracted_columns,
            table_info,
        }
    }

    pub fn assign(
        &self,
        pw: &mut PartialWitness<GFp>,
        wires: &LeafMappingVarWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>,
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
        pw.set_target(wires.key_id, self.key_id);
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
