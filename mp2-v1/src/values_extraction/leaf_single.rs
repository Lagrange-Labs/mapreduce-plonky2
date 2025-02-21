//! Module handling the single variable inside a storage trie
#![allow(clippy::identity_op)]
use crate::values_extraction::{
    gadgets::metadata_gadget::TableMetadata,
    public_inputs::{PublicInputs, PublicInputsArgs},
};
use anyhow::Result;
use mp2_common::{
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires},
    mpt_sequential::{
        utils::left_pad_leaf_value, MPTLeafOrExtensionNode, MAX_LEAF_VALUE_LEN, PAD_LEN,
    },
    poseidon::{empty_poseidon_hash, hash_to_int_target},
    public_inputs::PublicInputCommon,
    storage_key::{SimpleSlot, SimpleStructSlotWires},
    types::{CBuilder, GFp, MAPPING_LEAF_VALUE_LEN},
    utils::ToTargets,
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
use std::iter::once;

use super::gadgets::metadata_gadget::{NonEmptyableTableMetadata, NonEmptyableTableMetadataTarget};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LeafSingleWires<const MAX_EXTRACTED_COLUMNS: usize> {
    /// Full node from the MPT proof
    node: VectorWire<Target, { PAD_LEN(69) }>,
    /// Leaf value
    value: Array<Target, 32>,
    /// MPT root
    root: KeccakWires<{ PAD_LEN(69) }>,
    /// Storage single variable slot
    slot: SimpleStructSlotWires,
    /// MPT metadata
    metadata: NonEmptyableTableMetadataTarget<MAX_EXTRACTED_COLUMNS>,
    /// Offset from the base slot,
    offset: Target,
}

/// Circuit to prove the correct derivation of the MPT key from a simple slot
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafSingleCircuit<const MAX_EXTRACTED_COLUMNS: usize> {
    pub(crate) node: Vec<u8>,
    pub(crate) slot: SimpleSlot,
    pub(crate) metadata: NonEmptyableTableMetadata,
    pub(crate) offset: u32,
}

impl<const MAX_EXTRACTED_COLUMNS: usize> LeafSingleCircuit<MAX_EXTRACTED_COLUMNS> {
    pub fn build(b: &mut CBuilder) -> LeafSingleWires<MAX_EXTRACTED_COLUMNS> {
        let metadata = TableMetadata::build(b, 0);
        let offset = b.add_virtual_target();
        let slot = SimpleSlot::build_struct(b, offset);
        let zero = b.zero();
        // Build the node wires.
        let wires = MPTLeafOrExtensionNode::build_and_advance_key::<_, D, 69, MAX_LEAF_VALUE_LEN>(
            b,
            &slot.base.mpt_key,
        );
        let node = wires.node;
        let root = wires.root;

        // Left pad the leaf value.
        let value: Array<Target, MAPPING_LEAF_VALUE_LEN> = left_pad_leaf_value(b, &wires.value);

        let extraction_id = [zero, zero, zero, zero, zero, zero, zero, slot.base.slot];

        // compute the metadata digest
        let metadata_digest = metadata.metadata_digest(
            b,
            &[], // there are no input columns
            &extraction_id,
        );

        // Compute the value digest
        let value_digest = metadata.extracted_value_digest::<MAPPING_LEAF_VALUE_LEN>(
            b,
            &value,
            offset,
            &[zero, zero, zero, zero, zero, zero, zero, slot.base.slot],
        );

        // row_id = H2int(H("") || num_actual_columns)
        let empty_hash = b.constant_hash(*empty_poseidon_hash());
        let inputs = empty_hash
            .to_targets()
            .into_iter()
            .chain(once(metadata.num_actual_columns))
            .collect();
        let hash = b.hash_n_to_hash_no_pad::<CHasher>(inputs);
        let row_id = hash_to_int_target(b, hash);

        // value_digest = value_digest * row_id
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

        LeafSingleWires {
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
        wires: &LeafSingleWires<MAX_EXTRACTED_COLUMNS>,
    ) {
        let padded_node =
            Vector::<u8, { PAD_LEN(69) }>::from_vec(&self.node).expect("Invalid node");
        wires.node.assign(pw, &padded_node);
        KeccakCircuit::<{ PAD_LEN(69) }>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&padded_node),
        );
        self.slot.assign_struct(pw, &wires.slot, self.offset);
        TableMetadata::assign(pw, &self.metadata, &wires.metadata);
        pw.set_target(wires.offset, GFp::from_canonical_u32(self.offset));
    }
}

/// Num of children = 0
impl<const MAX_EXTRACTED_COLUMNS: usize> CircuitLogicWires<F, D, 0>
    for LeafSingleWires<MAX_EXTRACTED_COLUMNS>
{
    type CircuitBuilderParams = ();
    type Inputs = LeafSingleCircuit<MAX_EXTRACTED_COLUMNS>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CBuilder,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        LeafSingleCircuit::build(builder)
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
        values_extraction::{storage_value_digest, StorageSlotInfo},
    };
    use eth_trie::{Nibbles, Trie};
    use mp2_common::{
        array::Array,
        eth::{StorageSlot, StorageSlotNode},
        mpt_sequential::utils::bytes_to_nibbles,
        rlp::MAX_KEY_NIBBLE_LEN,
        types::MAPPING_LEAF_VALUE_LEN,
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

    type LeafCircuit = LeafSingleCircuit<TEST_MAX_COLUMNS>;
    type LeafWires = LeafSingleWires<TEST_MAX_COLUMNS>;

    #[derive(Clone, Debug)]
    struct TestLeafSingleCircuit {
        c: LeafCircuit,
        exp_value: Vec<u8>,
    }

    impl UserCircuit<F, D> for TestLeafSingleCircuit {
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

    fn test_circuit_for_storage_slot(storage_slot: StorageSlot) {
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
        let table_metadata = TableMetadata::sample::<TEST_MAX_COLUMNS>(
            true,
            &[],
            &[slot],
            F::from_canonical_u32(evm_word),
        );

        let metadata_digest = table_metadata.digest();

        let slot_info = StorageSlotInfo::new(
            storage_slot.clone(),
            table_metadata.extracted_columns().to_vec(),
        );
        let values_digest = storage_value_digest(
            &table_metadata,
            &[],
            &value.clone().try_into().unwrap(),
            &slot_info,
        );
        let slot = SimpleSlot::new(slot);
        let c = LeafCircuit {
            node: node.clone(),
            slot,
            metadata: table_metadata,
            offset: evm_word,
        };
        let test_circuit = TestLeafSingleCircuit {
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
    fn test_values_extraction_leaf_single_variable() {
        let storage_slot = StorageSlot::Simple(2);

        test_circuit_for_storage_slot(storage_slot);
    }

    #[test]
    fn test_values_extraction_leaf_single_struct() {
        let parent = StorageSlot::Simple(5);
        let storage_slot = StorageSlot::Node(StorageSlotNode::new_struct(parent, 10));

        test_circuit_for_storage_slot(storage_slot);
    }
}
