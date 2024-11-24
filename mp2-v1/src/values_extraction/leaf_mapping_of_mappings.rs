//! This circuit allows to extract data from mappings where the value stored in each mapping entry
//! is another mapping. In this case, we refer to the key for the first-layer mapping entry as the
//! outer key, while the key for the mapping stored in the entry mapping is referred to as inner key.

use crate::values_extraction::{
    gadgets::{
        column_gadget::ColumnGadget,
        metadata_gadget::{ColumnsMetadata, MetadataTarget},
    },
    public_inputs::{PublicInputs, PublicInputsArgs},
    INNER_KEY_ID_PREFIX, OUTER_KEY_ID_PREFIX,
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
    storage_key::{MappingOfMappingsSlotWires, MappingSlot},
    types::{CBuilder, GFp, MAPPING_LEAF_VALUE_LEN},
    utils::{Endianness, ToTargets},
    CHasher, D, F,
};
use plonky2::{
    field::types::Field,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::{iter, iter::once};

use super::gadgets::metadata_gadget::MetadataGadget;

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
    /// MPT metadata
    metadata: MetadataTarget<MAX_COLUMNS, MAX_FIELD_PER_EVM>,
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
    pub(crate) metadata: ColumnsMetadata<MAX_COLUMNS, MAX_FIELD_PER_EVM>,
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
        let two = b.two();

        let [outer_key_id, inner_key_id] = b.add_virtual_target_arr();
        let metadata = MetadataGadget::build(b);
        let slot = MappingSlot::build_mapping_of_mappings(b, metadata.evm_word);

        // Build the node wires.
        let wires =
            MPTLeafOrExtensionNode::build_and_advance_key::<_, D, NODE_LEN, MAX_LEAF_VALUE_LEN>(
                b,
                &slot.keccak_mpt.base.mpt_key,
            );
        let node = wires.node;
        let root = wires.root;

        // Left pad the leaf value.
        let value: Array<Target, MAPPING_LEAF_VALUE_LEN> = left_pad_leaf_value(b, &wires.value);

        // Compute the metadata digest and number of actual columns.
        let (metadata_digest, num_actual_columns) = metadata.digest_info(b, slot.mapping_slot);
        // Add inner key and outer key columns to the number of actual columns.
        let num_actual_columns = b.add(num_actual_columns, two);

        // Compute the outer and inner key metadata digests.
        let [outer_key_digest, inner_key_digest] = [
            (OUTER_KEY_ID_PREFIX, outer_key_id),
            (INNER_KEY_ID_PREFIX, inner_key_id),
        ]
        .map(|(prefix, key_id)| {
            let prefix = b.constant(F::from_canonical_u64(u64::from_be_bytes(
                prefix.try_into().unwrap(),
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
            &metadata.table_info[..MAX_FIELD_PER_EVM],
            &metadata.is_extracted_columns[..MAX_FIELD_PER_EVM],
        )
        .build(b);

        // Compute the outer and inner key values digests.
        let curve_zero = b.curve_zero();
        let [packed_outer_key, packed_inner_key] =
            [&slot.outer_key, &slot.inner_key].map(|key| key.pack(b, Endianness::Big).to_targets());
        let is_evm_word_zero = b.is_equal(metadata.evm_word, zero);
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
            .chain(packed_inner_key)
            .collect();
        let row_unique_data = b.hash_n_to_hash_no_pad::<CHasher>(inputs);
        // row_id = H2int(row_unique_data || num_actual_columns)
        let inputs = row_unique_data
            .to_targets()
            .into_iter()
            .chain(once(num_actual_columns))
            .collect();
        let hash = b.hash_n_to_hash_no_pad::<CHasher>(inputs);
        let row_id = hash_to_int_target(b, hash);

        // values_digest = values_digest * row_id
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

        LeafMappingOfMappingsWires {
            node,
            value,
            root,
            slot,
            outer_key_id,
            inner_key_id,
            metadata,
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
        pw.set_target(wires.outer_key_id, self.outer_key_id);
        pw.set_target(wires.inner_key_id, self.inner_key_id);
        self.slot.assign_mapping_of_mappings(
            pw,
            &wires.slot,
            &self.inner_key,
            self.metadata.evm_word,
        );
        MetadataGadget::assign(pw, &self.metadata, &wires.metadata);
    }
}

/// Num of children = 0
impl<const NODE_LEN: usize, const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>
    CircuitLogicWires<F, D, 0>
    for LeafMappingOfMappingsWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    type CircuitBuilderParams = ();
    type Inputs = LeafMappingOfMappingsCircuit<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        tests::{TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM},
        values_extraction::{
            compute_leaf_mapping_of_mappings_metadata_digest,
            compute_leaf_mapping_of_mappings_values_digest,
        },
        MAX_LEAF_NODE_LEN,
    };
    use eth_trie::{Nibbles, Trie};
    use mp2_common::{
        array::Array,
        eth::{StorageSlot, StorageSlotNode},
        mpt_sequential::utils::bytes_to_nibbles,
        rlp::MAX_KEY_NIBBLE_LEN,
        utils::{keccak256, Endianness, Packer},
        C, D, F,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        mpt_sequential::generate_random_storage_mpt,
        utils::random_vector,
    };
    use plonky2::{
        field::types::Field,
        iop::{target::Target, witness::PartialWitness},
    };
    use rand::{thread_rng, Rng};
    use std::array;

    type LeafCircuit =
        LeafMappingOfMappingsCircuit<MAX_LEAF_NODE_LEN, TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>;
    type LeafWires =
        LeafMappingOfMappingsWires<MAX_LEAF_NODE_LEN, TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>;

    #[derive(Clone, Debug)]
    struct TestLeafMappingOfMappingsCircuit {
        c: LeafCircuit,
        exp_value: Vec<u8>,
    }

    impl UserCircuit<F, D> for TestLeafMappingOfMappingsCircuit {
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

    fn test_circuit_for_storage_slot(
        outer_key: Vec<u8>,
        inner_key: Vec<u8>,
        storage_slot: StorageSlot,
    ) {
        let rng = &mut thread_rng();

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
        let [outer_key_id, inner_key_id] = array::from_fn(|_| rng.gen());
        let metadata =
            ColumnsMetadata::<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>::sample(slot, evm_word);
        // Compute the metadata digest.
        let table_info = metadata.actual_table_info().to_vec();
        let extracted_column_identifiers = metadata.extracted_column_identifiers();
        let metadata_digest = compute_leaf_mapping_of_mappings_metadata_digest::<
            TEST_MAX_COLUMNS,
            TEST_MAX_FIELD_PER_EVM,
        >(table_info.clone(), slot, outer_key_id, inner_key_id);
        // Compute the values digest.
        let values_digest = compute_leaf_mapping_of_mappings_values_digest::<TEST_MAX_FIELD_PER_EVM>(
            table_info,
            &extracted_column_identifiers,
            value.clone().try_into().unwrap(),
            evm_word,
            outer_key.clone(),
            inner_key.clone(),
            outer_key_id,
            inner_key_id,
        );
        let slot = MappingSlot::new(slot, outer_key.clone());
        let c = LeafCircuit {
            node: node.clone(),
            slot,
            inner_key: inner_key.clone(),
            outer_key_id: F::from_canonical_u64(outer_key_id),
            inner_key_id: F::from_canonical_u64(inner_key_id),
            metadata,
        };
        let test_circuit = TestLeafMappingOfMappingsCircuit {
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
        assert_eq!(pi.metadata_digest(), metadata_digest.to_weierstrass());
        // Check values digest
        assert_eq!(pi.values_digest(), values_digest.to_weierstrass());
    }

    #[test]
    fn test_values_extraction_leaf_mapping_of_mappings_variable() {
        let outer_key = random_vector(10);
        let inner_key = random_vector(20);
        let parent = StorageSlot::Mapping(outer_key.clone(), 2);
        let storage_slot =
            StorageSlot::Node(StorageSlotNode::new_mapping(parent, inner_key.clone()).unwrap());

        test_circuit_for_storage_slot(outer_key, inner_key, storage_slot);
    }

    #[test]
    fn test_values_extraction_leaf_mapping_of_mappings_struct() {
        let outer_key = random_vector(10);
        let inner_key = random_vector(20);
        let grand = StorageSlot::Mapping(outer_key.clone(), 2);
        let parent =
            StorageSlot::Node(StorageSlotNode::new_mapping(grand, inner_key.clone()).unwrap());
        let storage_slot = StorageSlot::Node(StorageSlotNode::new_struct(parent, 30));

        test_circuit_for_storage_slot(outer_key, inner_key, storage_slot);
    }
}
