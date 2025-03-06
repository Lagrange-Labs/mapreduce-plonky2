//! Module handling the mapping entries inside a storage trie

use crate::values_extraction::{
    gadgets::{
        column_gadget::ColumnGadget,
        metadata_gadget::{ColumnsMetadata, MetadataTarget},
    },
    public_inputs::{PublicInputs, PublicInputsArgs},
    KEY_ID_PREFIX,
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
    storage_key::{MappingSlot, MappingStructSlotWires},
    types::{CBuilder, GFp, MAPPING_LEAF_VALUE_LEN},
    utils::{Endianness, PackerTarget, ToTargets},
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
    pub(crate) slot: MappingStructSlotWires,
    /// Identifier of the column of the table storing the key of the current mapping entry
    pub(crate) key_id: Target,
    /// MPT metadata
    metadata: MetadataTarget<MAX_COLUMNS, MAX_FIELD_PER_EVM>,
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
    pub(crate) metadata: ColumnsMetadata<MAX_COLUMNS, MAX_FIELD_PER_EVM>,
}

impl<const NODE_LEN: usize, const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>
    LeafMappingCircuit<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub fn build(b: &mut CBuilder) -> LeafMappingWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM> {
        let zero = b.zero();
        let one = b.one();

        let key_id = b.add_virtual_target();
        let metadata = MetadataGadget::build(b);
        let slot = MappingSlot::build_struct(b, metadata.evm_word);

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
        // We add key column to number of actual columns.
        let num_actual_columns = b.add(num_actual_columns, one);

        // key_column_md = H( "\0KEY" || slot)
        let key_id_prefix = b.constant(F::from_canonical_u32(u32::from_be_bytes(
            KEY_ID_PREFIX.try_into().unwrap(),
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
            &metadata.table_info[..MAX_FIELD_PER_EVM],
            &metadata.is_extracted_columns[..MAX_FIELD_PER_EVM],
        )
        .build(b);

        // values_digest += evm_word == 0 ? D(key_id || pack(left_pad32(key))) : CURVE_ZERO
        let packed_mapping_key = slot.mapping_key.arr.pack(b, Endianness::Big);
        let inputs = iter::once(key_id)
            .chain(packed_mapping_key.clone())
            .collect_vec();
        let values_key_digest = b.map_to_curve_point(&inputs);
        let is_evm_word_zero = b.is_equal(metadata.evm_word, zero);
        let curve_zero = b.curve_zero();
        let values_key_digest = b.curve_select(is_evm_word_zero, values_key_digest, curve_zero);
        let values_digest = b.add_curve_point(&[values_digest, values_key_digest]);
        // Compute the unique data to identify a row is the mapping key.
        // row_unique_data = H(pack(left_pad32(key))
        let row_unique_data = b.hash_n_to_hash_no_pad::<CHasher>(packed_mapping_key);
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

        LeafMappingWires {
            node,
            value,
            root,
            slot,
            key_id,
            metadata,
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
        pw.set_target(wires.key_id, self.key_id);
        self.slot
            .assign_struct(pw, &wires.slot, self.metadata.evm_word);
        MetadataGadget::assign(pw, &self.metadata, &wires.metadata);
    }
}

/// Num of children = 0
impl<const NODE_LEN: usize, const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>
    CircuitLogicWires<F, D, 0> for LeafMappingWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    type CircuitBuilderParams = ();
    type Inputs = LeafMappingCircuit<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>;

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
    use super::*;
    use crate::{
        tests::{TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM},
        values_extraction::{
            compute_leaf_mapping_metadata_digest, compute_leaf_mapping_values_digest,
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

    type LeafCircuit =
        LeafMappingCircuit<MAX_LEAF_NODE_LEN, TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>;
    type LeafWires = LeafMappingWires<MAX_LEAF_NODE_LEN, TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>;

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
        let key_id = rng.gen();
        let metadata =
            ColumnsMetadata::<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>::sample(slot, evm_word);
        // Compute the metadata digest.
        let table_info = metadata.actual_table_info().to_vec();
        let extracted_column_identifiers = metadata.extracted_column_identifiers();
        let metadata_digest = compute_leaf_mapping_metadata_digest::<
            TEST_MAX_COLUMNS,
            TEST_MAX_FIELD_PER_EVM,
        >(table_info.clone(), slot, key_id);
        // Compute the values digest.
        let values_digest = compute_leaf_mapping_values_digest::<TEST_MAX_FIELD_PER_EVM>(
            table_info,
            &extracted_column_identifiers,
            value.clone().try_into().unwrap(),
            mapping_key.clone(),
            evm_word,
            key_id,
        );
        let slot = MappingSlot::new(slot, mapping_key.clone());
        let c = LeafCircuit {
            node: node.clone(),
            slot,
            key_id: F::from_canonical_u64(key_id),
            metadata,
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
        assert_eq!(pi.metadata_digest(), metadata_digest.to_weierstrass());
        // Check values digest
        assert_eq!(pi.values_digest(), values_digest.to_weierstrass());
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
