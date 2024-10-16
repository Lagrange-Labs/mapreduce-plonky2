//! Module handling the single variable inside a storage trie

use crate::values_extraction::{
    gadgets::{
        column_gadget::ColumnGadget,
        metadata_gadget::{MetadataGadget, MetadataTarget},
    },
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
    storage_key::{SimpleSlot, SimpleSlotWires},
    types::{CBuilder, GFp, MAPPING_LEAF_VALUE_LEN},
    utils::ToTargets,
    CHasher, D, F,
};
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::proof::ProofWithPublicInputsTarget,
};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LeafSingleWires<
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
    /// MPT metadata
    metadata: MetadataTarget<MAX_COLUMNS, MAX_FIELD_PER_EVM>,
}

/// Circuit to prove the correct derivation of the MPT key from a simple slot
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafSingleCircuit<
    const NODE_LEN: usize,
    const MAX_COLUMNS: usize,
    const MAX_FIELD_PER_EVM: usize,
> {
    pub(crate) node: Vec<u8>,
    pub(crate) slot: SimpleSlot,
    pub(crate) metadata: MetadataGadget<MAX_COLUMNS, MAX_FIELD_PER_EVM>,
}

impl<const NODE_LEN: usize, const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>
    LeafSingleCircuit<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub fn build(b: &mut CBuilder) -> LeafSingleWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM> {
        let metadata = MetadataGadget::build(b);
        let slot = SimpleSlot::build_with_offset(b, metadata.evm_word);

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
        let metadata_digest = metadata.digest(b, slot.slot);

        // Compute the values digest.
        let values_digest = ColumnGadget::<MAX_FIELD_PER_EVM>::new(
            &value.arr,
            &metadata.table_info[..MAX_FIELD_PER_EVM],
            &metadata.is_extracted_columns[..MAX_FIELD_PER_EVM],
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

        LeafSingleWires {
            node,
            value,
            root,
            slot,
            metadata,
        }
    }

    pub fn assign(
        &self,
        pw: &mut PartialWitness<GFp>,
        wires: &LeafSingleWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>,
    ) {
        let padded_node =
            Vector::<u8, { PAD_LEN(NODE_LEN) }>::from_vec(&self.node).expect("Invalid node");
        wires.node.assign(pw, &padded_node);
        KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&padded_node),
        );
        self.slot.assign(pw, &wires.slot, self.metadata.evm_word);
        self.metadata.assign(pw, &wires.metadata);
    }
}

/// Num of children = 0
impl<const NODE_LEN: usize, const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>
    CircuitLogicWires<F, D, 0> for LeafSingleWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    type CircuitBuilderParams = ();
    type Inputs = LeafSingleCircuit<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>;

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
        tests::{TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM},
        values_extraction::compute_leaf_single_values_digest,
        MAX_LEAF_NODE_LEN,
    };
    use eth_trie::{Nibbles, Trie};
    use itertools::Itertools;
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
        field::types::{Field, PrimeField64},
        iop::{target::Target, witness::PartialWitness},
    };

    type LeafCircuit =
        LeafSingleCircuit<MAX_LEAF_NODE_LEN, TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>;
    type LeafWires = LeafSingleWires<MAX_LEAF_NODE_LEN, TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>;

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
        let metadata =
            MetadataGadget::<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>::sample(slot, evm_word);
        // Compute the metadata digest.
        let metadata_digest = metadata.digest();
        // Compute the values digest.
        let table_info = metadata.table_info[..metadata.num_actual_columns].to_vec();
        let extracted_column_identifiers = table_info[..metadata.num_extracted_columns]
            .iter()
            .map(|column_info| column_info.identifier.to_canonical_u64())
            .collect_vec();
        let values_digest = compute_leaf_single_values_digest::<TEST_MAX_FIELD_PER_EVM>(
            &metadata_digest,
            table_info,
            &extracted_column_identifiers,
            value.clone().try_into().unwrap(),
        );
        let slot = SimpleSlot::new(slot);
        let c = LeafCircuit {
            node: node.clone(),
            slot,
            metadata,
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
