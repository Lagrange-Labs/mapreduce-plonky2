//! Module handling the single variable inside a storage trie

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
    },
    DEFAULT_MAX_COLUMNS, DEFAULT_MAX_FIELD_PER_EVM, MAX_LEAF_NODE_LEN,
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
    serialization::{
        deserialize_array, deserialize_long_array, serialize_array, serialize_long_array,
    },
    storage_key::{SimpleSlot, SimpleSlotWires},
    types::{CBuilder, GFp, MAPPING_LEAF_VALUE_LEN},
    utils::ToTargets,
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
use std::array;

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
pub struct LeafSingleCircuit<
    const NODE_LEN: usize,
    const MAX_COLUMNS: usize,
    const MAX_FIELD_PER_EVM: usize,
> {
    pub(crate) node: Vec<u8>,
    pub(crate) slot: SimpleSlot,
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
    LeafSingleCircuit<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub fn build(b: &mut CBuilder) -> LeafSingleWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM> {
        let evm_word = b.add_virtual_target();
        let table_info = array::from_fn(|_| b.add_virtual_column_info());
        let [is_actual_columns, is_extracted_columns] =
            array::from_fn(|_| array::from_fn(|_| b.add_virtual_bool_target_safe()));

        let slot = SimpleSlot::build_with_offset(b, evm_word);

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

        LeafSingleWires {
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
        self.slot.assign(pw, &wires.slot, self.evm_word);
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
    for LeafSingleWires<MAX_LEAF_NODE_LEN, DEFAULT_MAX_COLUMNS, DEFAULT_MAX_FIELD_PER_EVM>
{
    type CircuitBuilderParams = ();
    type Inputs =
        LeafSingleCircuit<MAX_LEAF_NODE_LEN, DEFAULT_MAX_COLUMNS, DEFAULT_MAX_FIELD_PER_EVM>;

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

/* gupeng
#[cfg(test)]
mod tests {
    use super::{
        super::{
            compute_leaf_single_metadata_digest, compute_leaf_single_values_digest,
            identifier_single_var_column,
        },
        *,
    };
    use alloy::primitives::Address;
    use eth_trie::{Nibbles, Trie};
    use mp2_common::{
        array::Array,
        eth::StorageSlot,
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
        plonk::circuit_builder::CircuitBuilder,
    };
    use std::str::FromStr;

    const TEST_CONTRACT_ADDRESS: &str = "0x105dD0eF26b92a3698FD5AaaF688577B9Cafd970";

    #[derive(Clone, Debug)]
    struct TestLeafSingleCircuit<const NODE_LEN: usize> {
        c: LeafSingleCircuit<NODE_LEN>,
        exp_value: Vec<u8>,
    }

    impl<const NODE_LEN: usize> UserCircuit<F, D> for TestLeafSingleCircuit<NODE_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
    {
        // Leaf wires + expected extracted value
        type Wires = (
            LeafSingleWires<NODE_LEN>,
            Array<Target, MAPPING_LEAF_VALUE_LEN>,
        );

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let exp_value = Array::<Target, MAPPING_LEAF_VALUE_LEN>::new(b);

            let leaf_wires = LeafSingleCircuit::<NODE_LEN>::build(b);
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

    #[test]
    fn test_values_extraction_leaf_single_circuit() {
        const NODE_LEN: usize = 80;

        let simple_slot = 2_u8;
        let slot = StorageSlot::Simple(simple_slot as usize);
        let contract_address = Address::from_str(TEST_CONTRACT_ADDRESS).unwrap();
        let chain_id = 10;
        let id = identifier_single_var_column(simple_slot, &contract_address, chain_id, vec![]);

        let (mut trie, _) = generate_random_storage_mpt::<3, MAPPING_LEAF_VALUE_LEN>();
        let value = random_vector(MAPPING_LEAF_VALUE_LEN);
        let encoded_value: Vec<u8> = rlp::encode(&value).to_vec();
        // assert we added one byte of RLP header
        assert_eq!(encoded_value.len(), MAPPING_LEAF_VALUE_LEN + 1);
        println!("encoded value {:?}", encoded_value);
        trie.insert(&slot.mpt_key(), &encoded_value).unwrap();
        trie.root_hash().unwrap();

        let proof = trie.get_proof(&slot.mpt_key_vec()).unwrap();
        let node = proof.last().unwrap().clone();

        let c = LeafSingleCircuit::<NODE_LEN> {
            node: node.clone(),
            slot: SimpleSlot::new(simple_slot),
            id,
        };
        let test_circuit = TestLeafSingleCircuit {
            c,
            exp_value: value.clone(),
        };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::new(&proof.public_inputs);

        {
            let exp_hash = keccak256(&node).pack(Endianness::Little);
            assert_eq!(pi.root_hash(), exp_hash);
        }
        {
            let (key, ptr) = pi.mpt_key_info();

            let exp_key = slot.mpt_key_vec();
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
        // Check values digest
        {
            let exp_digest = compute_leaf_single_values_digest(id, &value);
            assert_eq!(pi.values_digest(), exp_digest.to_weierstrass());
        }
        // Check metadata digest
        {
            let exp_digest = compute_leaf_single_metadata_digest(id, simple_slot);
            assert_eq!(pi.metadata_digest(), exp_digest.to_weierstrass());
        }
        assert_eq!(pi.n(), F::ONE);
    }
}
*/
