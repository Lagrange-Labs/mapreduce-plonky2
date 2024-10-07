//! This circuit allows to extract data from mappings where the value stored in each mapping entry
//! is another mapping. In this case, we refer to the key for the first-layer mapping entry as the
//! outer key, while the key for the mapping stored in the entry mapping is referred to as inner key.

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
        INNER_KEY_ID_PREFIX, OUTER_KEY_ID_PREFIX,
    },
    DEFAULT_MAX_COLUMNS, DEFAULT_MAX_FIELD_PER_EVM, MAX_LEAF_NODE_LEN,
};
use anyhow::Result;
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
    storage_key::{MappingOfMappingsSlotWires, MappingSlot},
    types::{CBuilder, GFp, MAPPING_LEAF_VALUE_LEN},
    utils::{Endianness, ToTargets},
    CHasher, D, F,
};
use plonky2::{
    field::types::Field,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::{
    array, iter,
    iter::{once, repeat},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LeafMappingOfMappingsWires<
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
    /// Mapping slot associating wires including outer and inner mapping keys
    pub(crate) slot: MappingOfMappingsSlotWires,
    /// Identifier of the column of the table storing the outer key of the current mapping entry
    pub(crate) outer_key_id: Target,
    /// Identifier of the column of the table storing the inner key of the indexed mapping entry
    pub(crate) inner_key_id: Target,
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
    /// Boolean flags specifying whether the i-th field being processed has to be
    /// extracted into a column or not
    pub(crate) is_extracted_columns: [BoolTarget; MAX_COLUMNS],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    /// Information about all columns of the table
    pub(crate) table_info: [ColumnInfoTarget; MAX_COLUMNS],
}

/// Circuit to prove the correct derivation of the MPT key from mappings where
/// the value stored in each mapping entry is another mapping
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafMappingOfMappingsCircuit<
    const NODE_LEN: usize,
    const MAX_COLUMNS: usize,
    const MAX_FIELD_PER_EVM: usize,
> where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub(crate) node: Vec<u8>,
    pub(crate) slot: MappingSlot,
    pub(crate) inner_key: Vec<u8>,
    pub(crate) outer_key_id: F,
    pub(crate) inner_key_id: F,
    pub(crate) evm_word: u32,
    pub(crate) num_actual_columns: usize,
    pub(crate) num_extracted_columns: usize,
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) table_info: [ColumnInfo; MAX_COLUMNS],
}

impl<const NODE_LEN: usize, const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>
    LeafMappingOfMappingsCircuit<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub fn build(
        b: &mut CBuilder,
    ) -> LeafMappingOfMappingsWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM> {
        let zero = b.zero();

        let [outer_key_id, inner_key_id] = b.add_virtual_target_arr();
        let evm_word = b.add_virtual_target();
        let table_info = array::from_fn(|_| b.add_virtual_column_info());
        let [is_actual_columns, is_extracted_columns] =
            array::from_fn(|_| array::from_fn(|_| b.add_virtual_bool_target_safe()));

        let slot = MappingSlot::mpt_key_with_inner_offset(b, evm_word);

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

        // Compute the outer and inner key metadata digests.
        let [outer_key_digest, inner_key_digest] = [
            (OUTER_KEY_ID_PREFIX, outer_key_id),
            (INNER_KEY_ID_PREFIX, inner_key_id),
        ]
        .map(|(prefix, key_id)| {
            let prefix = b.constant(F::from_canonical_u64(u64::from_be_bytes(
                repeat(0_u8)
                    .take(8 - prefix.len())
                    .chain(prefix.iter().cloned())
                    .collect_vec()
                    .try_into()
                    .unwrap(),
            )));

            // key_column_md = H(KEY_ID_PREFIX || slot)
            let inputs = vec![prefix, slot.mapping_slot];
            let key_column_md = b.hash_n_to_hash_no_pad::<CHasher>(inputs);

            // key_digest = D(key_column_md || key_id)
            let inputs = key_column_md
                .to_targets()
                .into_iter()
                .chain(once(key_id))
                .collect_vec();
            b.map_to_curve_point(&inputs)
        });

        // Add the outer and inner key digests into the metadata digest.
        // metadata_digest += outer_key_digest + inner_key_digest
        let metadata_digest =
            b.add_curve_point(&[metadata_digest, inner_key_digest, outer_key_digest]);

        // Compute the values digest.
        let values_digest = ColumnGadget::<MAX_FIELD_PER_EVM>::new(
            &value.arr,
            &table_info[..MAX_FIELD_PER_EVM],
            &is_extracted_columns[..MAX_FIELD_PER_EVM],
        )
        .build(b);

        // Compute the outer and inner key values digests.
        let curve_zero = b.curve_zero();
        let [packed_outer_key, packed_inner_key] =
            [&slot.outer_key, &slot.inner_key].map(|key| key.pack(b, Endianness::Big).to_targets());
        let is_evm_word_zero = b.is_equal(evm_word, zero);
        let [outer_key_digest, inner_key_digest] = [
            (outer_key_id, packed_outer_key.clone()),
            (inner_key_id, packed_inner_key.clone()),
        ]
        .map(|(key_id, packed_key)| {
            // D(key_id || pack(key))
            let inputs = iter::once(key_id).chain(packed_key).collect_vec();
            let key_digest = b.map_to_curve_point(&inputs);
            // key_digest = evm_word == 0 ? key_digset : CURVE_ZERO
            b.curve_select(is_evm_word_zero, key_digest, curve_zero)
        });
        // values_digest += outer_key_digest + inner_key_digest
        let values_digest = b.add_curve_point(&[values_digest, inner_key_digest, outer_key_digest]);

        // Compute the unique data to identify a row is the mapping key:
        // row_unique_data = H(outer_key || inner_key)
        let inputs = packed_outer_key
            .into_iter()
            .chain(packed_inner_key.into_iter())
            .collect();
        let row_unique_data = b.hash_n_to_hash_no_pad::<CHasher>(inputs);
        // row_id = H2int(row_unique_data || metadata_digest)
        let inputs = row_unique_data
            .to_targets()
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

        LeafMappingOfMappingsWires {
            node,
            value,
            root,
            slot,
            outer_key_id,
            inner_key_id,
            evm_word,
            is_actual_columns,
            is_extracted_columns,
            table_info,
        }
    }

    pub fn assign(
        &self,
        pw: &mut PartialWitness<GFp>,
        wires: &LeafMappingOfMappingsWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>,
    ) {
        let padded_node =
            Vector::<u8, { PAD_LEN(NODE_LEN) }>::from_vec(&self.node).expect("Invalid node");
        wires.node.assign(pw, &padded_node);
        KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&padded_node),
        );
        self.slot
            .assign_mapping_of_mappings(pw, &wires.slot, &self.inner_key, self.evm_word);
        pw.set_target(wires.outer_key_id, self.outer_key_id);
        pw.set_target(wires.inner_key_id, self.inner_key_id);
        pw.set_target(wires.evm_word, F::from_canonical_u32(self.evm_word));
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

/// Num of children = 0
impl CircuitLogicWires<F, D, 0>
    for LeafMappingOfMappingsWires<
        MAX_LEAF_NODE_LEN,
        DEFAULT_MAX_COLUMNS,
        DEFAULT_MAX_FIELD_PER_EVM,
    >
{
    type CircuitBuilderParams = ();
    type Inputs = LeafMappingOfMappingsCircuit<
        MAX_LEAF_NODE_LEN,
        DEFAULT_MAX_COLUMNS,
        DEFAULT_MAX_FIELD_PER_EVM,
    >;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CBuilder,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        LeafMappingOfMappingsCircuit::build(builder)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}
