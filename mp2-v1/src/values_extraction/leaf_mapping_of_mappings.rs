//! This circuit allows to extract data from mappings where the value stored in each mapping entry
//! is another mapping. In this case, we refer to the key for the first-layer mapping entry as the
//! outer key, while the key for the mapping stored in the entry mapping is referred to as inner key.

use crate::values_extraction::{
    gadgets::metadata_gadget::{TableMetadataGadget, TableMetadataTarget},
    public_inputs::{PublicInputs, PublicInputsArgs},
};
use anyhow::Result;

use mp2_common::{
    array::{Array, Targetable, Vector, VectorWire, L32},
    group_hashing::CircuitBuilderGroupHashing,
    keccak::{InputData, KeccakCircuit, KeccakWires},
    mpt_sequential::{utils::left_pad_leaf_value, MPTLeafOrExtensionNode, PAD_LEN},
    poseidon::hash_to_int_target,
    public_inputs::PublicInputCommon,
    storage_key::{MappingOfMappingsSlotWires, MappingSlot},
    types::{CBuilder, GFp},
    u256::UInt256Target,
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
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::iter::once;

use super::gadgets::metadata_gadget::TableMetadata;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LeafMappingOfMappingsWires<const MAX_COLUMNS: usize>
where
    [(); MAX_COLUMNS - 2]:,
{
    /// Full node from the MPT proof
    pub(crate) node: VectorWire<Target, { PAD_LEN(69) }>,
    /// Leaf value
    pub(crate) value: Array<Target, 32>,
    /// MPT root
    pub(crate) root: KeccakWires<{ PAD_LEN(69) }>,
    /// Mapping slot associating wires including outer and inner mapping keys
    pub(crate) slot: MappingOfMappingsSlotWires,
    /// MPT metadata
    metadata: TableMetadataTarget<MAX_COLUMNS, 2>,
    offset: Target,
}

/// Circuit to prove the correct derivation of the MPT key from mappings where
/// the value stored in each mapping entry is another mapping
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafMappingOfMappingsCircuit<const MAX_COLUMNS: usize>
where
    [(); MAX_COLUMNS - 2]:,
{
    pub(crate) node: Vec<u8>,
    pub(crate) slot: MappingSlot,
    pub(crate) inner_key: Vec<u8>,
    pub(crate) metadata: TableMetadata<MAX_COLUMNS, 2>,
    pub(crate) evm_word: u8,
}

impl<const MAX_COLUMNS: usize> LeafMappingOfMappingsCircuit<MAX_COLUMNS>
where
    [(); MAX_COLUMNS - 2]:,
{
    pub fn build(b: &mut CBuilder) -> LeafMappingOfMappingsWires<MAX_COLUMNS> {
        let offset = b.add_virtual_target();
        let metadata = TableMetadataGadget::<MAX_COLUMNS, 2>::build(b);
        let slot = MappingSlot::build_mapping_of_mappings(b, offset);

        let zero = b.zero();

        let key_input_no_offset = slot
            .keccak_mpt
            .base
            .keccak_location
            .output
            .pack(b, Endianness::Big);
        let key_input_with_offset = slot.keccak_mpt.location_bytes.pack(b, Endianness::Big);

        let u256_no_off =
            UInt256Target::new_from_be_limbs(key_input_no_offset.arr.as_slice()).unwrap();
        let u256_loc =
            UInt256Target::new_from_be_limbs(key_input_with_offset.arr.as_slice()).unwrap();

        // Build the node wires.
        let wires = MPTLeafOrExtensionNode::build_and_advance_key::<_, D, 69, 33>(
            b,
            &slot.keccak_mpt.base.mpt_key,
        );
        let node: VectorWire<Target, { PAD_LEN(69) }> = wires.node;
        let root = wires.root;

        // Left pad the leaf value.
        let value: Array<Target, 32> = left_pad_leaf_value(b, &wires.value);

        // Compute the metadata digest and the value digest
        let input_values: [Array<U32Target, { L32(32) }>; 2] = [&slot.outer_key, &slot.inner_key]
            .map(|key| Array::<Target, 32>::pack(key, b, Endianness::Big));

        let (input_metadata_digest, input_value_digest) = metadata.inputs_digests(b, &input_values);
        let (extracted_metadata_digest, extracted_value_digest) = metadata.extracted_digests::<32>(
            b,
            &value,
            &u256_no_off,
            &u256_loc,
            &[zero, zero, zero, zero, zero, zero, zero, slot.mapping_slot],
        );

        let metadata_digest =
            b.add_curve_point(&[input_metadata_digest, extracted_metadata_digest]);

        let input_selector = b.is_equal(zero, offset);
        let curve_zero = b.curve_zero();
        let input_value_digest = b.curve_select(input_selector, input_value_digest, curve_zero);
        let value_digest = b.add_curve_point(&[input_value_digest, extracted_value_digest]);

        // Compute the unique data to identify a row is the mapping key:
        // row_unique_data = H(outer_key || inner_key)
        let inputs = input_values
            .iter()
            .flat_map(|arr| {
                arr.arr
                    .iter()
                    .map(|t| t.to_target())
                    .collect::<Vec<Target>>()
            })
            .collect::<Vec<Target>>();
        let row_unique_data = b.hash_n_to_hash_no_pad::<CHasher>(inputs);
        // row_id = H2int(row_unique_data || num_actual_columns)
        let inputs = row_unique_data
            .to_targets()
            .into_iter()
            .chain(once(metadata.num_actual_columns))
            .collect();
        let hash = b.hash_n_to_hash_no_pad::<CHasher>(inputs);
        let row_id = hash_to_int_target(b, hash);

        // values_digest = values_digest * row_id
        let row_id = b.biguint_to_nonnative(&row_id);
        let values_digest = b.curve_scalar_mul(value_digest, &row_id);

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
            metadata,
            offset,
        }
    }

    pub fn assign(
        &self,
        pw: &mut PartialWitness<GFp>,
        wires: &LeafMappingOfMappingsWires<MAX_COLUMNS>,
    ) {
        let padded_node =
            Vector::<u8, { PAD_LEN(69) }>::from_vec(&self.node).expect("Invalid node");
        wires.node.assign(pw, &padded_node);
        KeccakCircuit::<{ PAD_LEN(69) }>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&padded_node),
        );

        self.slot.assign_mapping_of_mappings(
            pw,
            &wires.slot,
            &self.inner_key,
            self.evm_word as u32,
        );
        TableMetadataGadget::<MAX_COLUMNS, 2>::assign(pw, &self.metadata, &wires.metadata);
        pw.set_target(wires.offset, F::from_canonical_u8(self.evm_word));
    }
}

/// Num of children = 0
impl<const MAX_COLUMNS: usize> CircuitLogicWires<F, D, 0>
    for LeafMappingOfMappingsWires<MAX_COLUMNS>
where
    [(); MAX_COLUMNS - 2]:,
{
    type CircuitBuilderParams = ();
    type Inputs = LeafMappingOfMappingsCircuit<MAX_COLUMNS>;

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
        tests::TEST_MAX_COLUMNS,
        values_extraction::{INNER_KEY_ID_PREFIX, OUTER_KEY_ID_PREFIX},
    };
    use eth_trie::{Nibbles, Trie};
    use mp2_common::{
        array::Array,
        eth::{StorageSlot, StorageSlotNode},
        mpt_sequential::utils::bytes_to_nibbles,
        poseidon::{hash_to_int_value, H},
        rlp::MAX_KEY_NIBBLE_LEN,
        types::MAPPING_LEAF_VALUE_LEN,
        utils::{keccak256, Endianness, Packer, ToFields},
        C, D, F,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        mpt_sequential::generate_random_storage_mpt,
        utils::random_vector,
    };
    use plonky2::{
        field::types::Field,
        hash::hash_types::HashOut,
        iop::{target::Target, witness::PartialWitness},
        plonk::config::Hasher,
    };

    use plonky2_ecgfp5::curve::scalar_field::Scalar;

    use rand::{thread_rng, Rng};
    use std::array;

    #[derive(Clone, Debug)]
    struct TestNewLeafMappingOfMappingsCircuit {
        c: LeafMappingOfMappingsCircuit<TEST_MAX_COLUMNS>,
        exp_value: Vec<u8>,
    }

    impl UserCircuit<F, D> for TestNewLeafMappingOfMappingsCircuit {
        // Leaf wires + expected extracted value
        type Wires = (
            LeafMappingOfMappingsWires<TEST_MAX_COLUMNS>,
            Array<Target, MAPPING_LEAF_VALUE_LEN>,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let leaf_wires = LeafMappingOfMappingsCircuit::<TEST_MAX_COLUMNS>::build(b);
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
        outer_key: &[u8; 32],
        inner_key: &[u8; 32],
        storage_slot: StorageSlot,
    ) {
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
        // Compute the metadata digest.
        let table_metadata = TableMetadata::<TEST_MAX_COLUMNS, 2>::sample(
            true,
            &[OUTER_KEY_ID_PREFIX, INNER_KEY_ID_PREFIX],
            &[slot],
            F::from_canonical_u32(evm_word),
        );

        let metadata_digest = table_metadata.digest();
        let (input_val_digest, row_unique_data) =
            table_metadata.input_value_digest(&[outer_key, inner_key]);
        let extracted_val_digest =
            table_metadata.extracted_value_digest(&value, &[slot], F::from_canonical_u32(evm_word));

        // row_id = H2int(row_unique_data || num_actual_columns)
        let inputs = HashOut::from(row_unique_data)
            .to_fields()
            .into_iter()
            .chain(once(F::from_canonical_usize(
                table_metadata.num_actual_columns,
            )))
            .collect::<Vec<F>>();
        let hash = H::hash_no_pad(&inputs);
        let row_id = hash_to_int_value(hash);

        // values_digest = values_digest * row_id
        let row_id = Scalar::from_noncanonical_biguint(row_id);
        let values_digest = if evm_word == 0 {
            (extracted_val_digest + input_val_digest) * row_id
        } else {
            extracted_val_digest * row_id
        };

        let slot = MappingSlot::new(slot, outer_key.to_vec());

        let new_c = LeafMappingOfMappingsCircuit::<TEST_MAX_COLUMNS> {
            node: node.clone(),
            slot: slot.clone(),
            inner_key: inner_key.to_vec(),
            metadata: table_metadata,
            evm_word: evm_word as u8,
        };

        let new_test_circuit = TestNewLeafMappingOfMappingsCircuit {
            c: new_c,
            exp_value: value.clone(),
        };

        let proof = run_circuit::<F, D, C, _>(new_test_circuit);
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
        let rng = &mut thread_rng();
        let outer_key: [u8; 32] = array::from_fn(|_| rng.gen());
        let inner_key: [u8; 32] = array::from_fn(|_| rng.gen());
        let parent = StorageSlot::Mapping(outer_key.to_vec(), 2);
        let storage_slot =
            StorageSlot::Node(StorageSlotNode::new_mapping(parent, inner_key.to_vec()).unwrap());

        test_circuit_for_storage_slot(&outer_key, &inner_key, storage_slot);
    }

    #[test]
    fn test_values_extraction_leaf_mapping_of_mappings_struct() {
        let rng = &mut thread_rng();
        let outer_key: [u8; 32] = array::from_fn(|_| rng.gen());
        let inner_key: [u8; 32] = array::from_fn(|_| rng.gen());
        let grand = StorageSlot::Mapping(outer_key.to_vec(), 2);
        let parent =
            StorageSlot::Node(StorageSlotNode::new_mapping(grand, inner_key.to_vec()).unwrap());
        let storage_slot = StorageSlot::Node(StorageSlotNode::new_struct(parent, 30));

        test_circuit_for_storage_slot(&outer_key, &inner_key, storage_slot);
    }
}
