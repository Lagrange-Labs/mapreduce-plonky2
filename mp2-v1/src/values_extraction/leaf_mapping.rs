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
    storage_key::{MappingSlot, MappingSlotWires},
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
    plonk::proof::ProofWithPublicInputsTarget,
};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::{array, iter, iter::once};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LeafMappingWires<
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
pub struct LeafMappingCircuit<
    const NODE_LEN: usize,
    const MAX_COLUMNS: usize,
    const MAX_FIELD_PER_EVM: usize,
> where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub(crate) node: Vec<u8>,
    pub(crate) slot: MappingSlot,
    pub(crate) key_id: F,
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
    LeafMappingCircuit<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub fn build(b: &mut CBuilder) -> LeafMappingWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM> {
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
        let packed_mapping_key = slot.mapping_key.arr.pack(b, Endianness::Big);
        let inputs = iter::once(key_id)
            .chain(packed_mapping_key.clone())
            .collect_vec();
        let values_key_digest = b.map_to_curve_point(&inputs);
        let is_evm_word_zero = b.is_equal(evm_word, zero);
        let curve_zero = b.curve_zero();
        let values_key_digest = b.curve_select(is_evm_word_zero, values_key_digest, curve_zero);
        let values_digest = b.add_curve_point(&[values_digest, values_key_digest]);
        // Compute the unique data to identify a row is the mapping key.
        // row_unique_data = H(pack(left_pad32(key))
        let row_unique_data = b.hash_n_to_hash_no_pad::<CHasher>(packed_mapping_key);
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

        LeafMappingWires {
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
        wires: &LeafMappingWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>,
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
            .assign_mapping_slot(pw, &wires.slot, self.evm_word);
        pw.set_target(wires.key_id, self.key_id);
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
    for LeafMappingWires<MAX_LEAF_NODE_LEN, DEFAULT_MAX_COLUMNS, DEFAULT_MAX_FIELD_PER_EVM>
{
    type CircuitBuilderParams = ();
    type Inputs =
        LeafMappingCircuit<MAX_LEAF_NODE_LEN, DEFAULT_MAX_COLUMNS, DEFAULT_MAX_FIELD_PER_EVM>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CBuilder,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        LeafMappingCircuit::build(builder)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            gadgets::{column_gadget::ColumnGadgetData, metadata_gadget::MetadataGadgetData},
            left_pad32,
        },
        *,
    };
    use eth_trie::{Nibbles, Trie};
    use itertools::Itertools;
    use mp2_common::{
        array::Array,
        eth::{StorageSlot, StorageSlotNode},
        group_hashing::map_to_curve_point,
        mpt_sequential::utils::bytes_to_nibbles,
        poseidon::{hash_to_int_value, H},
        rlp::MAX_KEY_NIBBLE_LEN,
        utils::{keccak256, Endianness, Packer, ToFields},
        C, D, F,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        mpt_sequential::generate_random_storage_mpt,
        utils::random_vector,
    };
    use plonky2::{
        field::types::{Field, Sample},
        iop::{target::Target, witness::PartialWitness},
        plonk::config::Hasher,
    };
    use plonky2_ecgfp5::curve::scalar_field::Scalar;

    type LeafCircuit =
        LeafMappingCircuit<MAX_LEAF_NODE_LEN, DEFAULT_MAX_COLUMNS, DEFAULT_MAX_FIELD_PER_EVM>;
    type LeafWires =
        LeafMappingWires<MAX_LEAF_NODE_LEN, DEFAULT_MAX_COLUMNS, DEFAULT_MAX_FIELD_PER_EVM>;

    #[derive(Clone, Debug)]
    struct TestLeafMappingCircuit {
        c: LeafCircuit,
        exp_value: Vec<u8>,
    }

    impl UserCircuit<F, D> for TestLeafMappingCircuit {
        // Leaf wires + expected extracted value
        type Wires = (LeafWires, Array<Target, MAPPING_LEAF_VALUE_LEN>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let leaf_wires = LeafCircuit::build(b);
            let exp_value = Array::<Target, MAPPING_LEAF_VALUE_LEN>::new(b);
            leaf_wires.value.enforce_equal(b, &exp_value);

            (leaf_wires, exp_value)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);
            wires
                .1
                .assign_bytes(pw, &self.exp_value.clone().try_into().unwrap());
        }
    }

    fn test_circuit_for_storage_slot(mapping_key: Vec<u8>, storage_slot: StorageSlot) {
        let (mut trie, _) = generate_random_storage_mpt::<3, MAPPING_LEAF_VALUE_LEN>();
        let value = random_vector(MAPPING_LEAF_VALUE_LEN);
        let encoded_value: Vec<u8> = rlp::encode(&value).to_vec();
        // Ensure we added one byte of RLP header.
        assert_eq!(encoded_value.len(), MAPPING_LEAF_VALUE_LEN + 1);
        trie.insert(&storage_slot.mpt_key(), &encoded_value)
            .unwrap();
        trie.root_hash().unwrap();
        let proof = trie.get_proof(&storage_slot.mpt_key_vec()).unwrap();
        let node = proof.last().unwrap().clone();

        let slot = storage_slot.slot();
        let evm_word = storage_slot.evm_offset();
        let metadata = MetadataGadgetData::<DEFAULT_MAX_COLUMNS, DEFAULT_MAX_FIELD_PER_EVM>::sample(
            slot, evm_word,
        );
        // Compute the metadata digest.
        let mut metadata_digest = metadata.digest();
        // Compute the values digest.
        let mut values_digest = ColumnGadgetData::<DEFAULT_MAX_FIELD_PER_EVM>::new(
            value
                .clone()
                .into_iter()
                .map(F::from_canonical_u8)
                .collect_vec()
                .try_into()
                .unwrap(),
            array::from_fn(|i| metadata.table_info[i].clone()),
            metadata.num_extracted_columns,
        )
        .digest();
        let slot = MappingSlot::new(slot, mapping_key.clone());
        let key_id = F::rand();
        let c = LeafCircuit {
            node: node.clone(),
            slot,
            key_id,
            evm_word,
            num_actual_columns: metadata.num_actual_columns,
            num_extracted_columns: metadata.num_extracted_columns,
            table_info: metadata.table_info,
        };
        let test_circuit = TestLeafMappingCircuit {
            c,
            exp_value: value.clone(),
        };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::new(&proof.public_inputs);
        // Check root hash
        {
            let exp_hash = keccak256(&node).pack(Endianness::Little);
            assert_eq!(pi.root_hash(), exp_hash);
        }
        // Check MPT key
        {
            let (key, ptr) = pi.mpt_key_info();

            let exp_key = storage_slot.mpt_key_vec();
            let exp_key: Vec<_> = bytes_to_nibbles(&exp_key)
                .into_iter()
                .map(F::from_canonical_u8)
                .collect();
            assert_eq!(key, exp_key);

            let leaf_key: Vec<Vec<u8>> = rlp::decode_list(&node);
            let nib = Nibbles::from_compact(&leaf_key[0]);
            let exp_ptr = F::from_canonical_usize(MAX_KEY_NIBBLE_LEN - 1 - nib.nibbles().len());
            assert_eq!(exp_ptr, ptr);
        }
        assert_eq!(pi.n(), F::ONE);
        // Check metadata digest
        {
            // TODO: Move to a common function.
            // key_column_md = H( "KEY" || slot)
            let key_id_prefix = u32::from_be_bytes(
                once(0_u8)
                    .chain(KEY_ID_PREFIX.iter().cloned())
                    .collect_vec()
                    .try_into()
                    .unwrap(),
            );
            let inputs = vec![
                F::from_canonical_u32(key_id_prefix),
                F::from_canonical_u8(storage_slot.slot()),
            ];
            let key_column_md = H::hash_no_pad(&inputs);
            // metadata_digest += D(key_column_md || key_id)
            let inputs = key_column_md
                .to_fields()
                .into_iter()
                .chain(once(key_id))
                .collect_vec();
            let metadata_key_digest = map_to_curve_point(&inputs);
            metadata_digest += metadata_key_digest;

            assert_eq!(pi.metadata_digest(), metadata_digest.to_weierstrass());
        }
        // Check values digest
        {
            // TODO: Move to a common function.
            // values_digest += evm_word == 0 ? D(key_id || pack(left_pad32(key))) : CURVE_ZERO
            let packed_mapping_key = left_pad32(&mapping_key)
                .pack(Endianness::Big)
                .into_iter()
                .map(F::from_canonical_u32);
            if evm_word == 0 {
                let inputs = iter::once(key_id)
                    .chain(packed_mapping_key.clone())
                    .collect_vec();
                let values_key_digest = map_to_curve_point(&inputs);
                values_digest += values_key_digest;
            }
            // row_unique_data = H(pack(left_pad32(key))
            let row_unique_data = H::hash_no_pad(&packed_mapping_key.collect_vec());
            // row_id = H2int(row_unique_data || metadata_digest)
            let inputs = row_unique_data
                .to_fields()
                .into_iter()
                .chain(metadata_digest.to_fields())
                .collect_vec();
            let hash = H::hash_no_pad(&inputs);
            let row_id = hash_to_int_value(hash);

            // value_digest = value_digest * row_id
            let row_id = Scalar::from_noncanonical_biguint(row_id);
            values_digest *= row_id;

            assert_eq!(pi.values_digest(), values_digest.to_weierstrass());
        }
    }

    #[test]
    fn test_values_extraction_leaf_mapping_variable() {
        let mapping_key = random_vector(10);
        let storage_slot = StorageSlot::Mapping(mapping_key.clone(), 2);

        test_circuit_for_storage_slot(mapping_key, storage_slot);
    }

    #[test]
    fn test_values_extraction_leaf_mapping_struct() {
        let mapping_key = random_vector(20);
        let parent = StorageSlot::Mapping(mapping_key.clone(), 5);
        let storage_slot = StorageSlot::Node(StorageSlotNode::new_struct(parent, 20));

        test_circuit_for_storage_slot(mapping_key, storage_slot);
    }
}
