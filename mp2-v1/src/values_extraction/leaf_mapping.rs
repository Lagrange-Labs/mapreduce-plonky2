//! Module handling the mapping entries inside a storage trie

use super::{public_inputs::PublicInputs, MAX_LEAF_NODE_LEN};
use mp2_common::{
    array::{Array, Vector, VectorWire},
    group_hashing::CircuitBuilderGroupHashing,
    keccak::{InputData, KeccakCircuit, KeccakWires},
    mpt_sequential::{
        utils::left_pad_leaf_value, MPTLeafOrExtensionNode, MAX_LEAF_VALUE_LEN, PAD_LEN,
    },
    storage_key::{MappingSlot, MappingSlotWires},
    types::{CBuilder, GFp, MAPPING_KEY_LEN, MAPPING_LEAF_VALUE_LEN},
    utils::convert_u8_targets_to_u32,
    D,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    serialization::{deserialize, serialize},
};
use serde::{Deserialize, Serialize};
use std::iter;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct LeafMappingWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
    slot: MappingSlotWires,
    value: Array<Target, MAPPING_LEAF_VALUE_LEN>,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    key_id: HashOutTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    value_id: HashOutTarget,
}

impl<const N: usize> LeafMappingWires<N>
where
    [(); PAD_LEN(N)]:,
{
    pub fn mapping_key(&self) -> Array<Target, MAPPING_KEY_LEN> {
        self.slot.mapping_key.clone()
    }

    pub fn mapping_slot(&self) -> Target {
        self.slot.mapping_slot
    }
}

/// Circuit to prove the correct derivation of the MPT key from a mapping slot
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LeafMappingCircuit<const NODE_LEN: usize> {
    pub(crate) node: Vec<u8>,
    pub(crate) slot: MappingSlot,
    pub(crate) key_id: HashOut<GFp>,
    pub(crate) value_id: HashOut<GFp>,
}

impl<const NODE_LEN: usize> LeafMappingCircuit<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub fn build(b: &mut CBuilder) -> LeafMappingWires<NODE_LEN> {
        let slot = MappingSlot::mpt_key(b);
        let key_id = b.add_virtual_hash();
        let value_id = b.add_virtual_hash();

        // Build the node wires.
        let wires =
            MPTLeafOrExtensionNode::build_and_advance_key::<_, D, NODE_LEN, MAX_LEAF_VALUE_LEN>(
                b,
                &slot.keccak_mpt.mpt_key,
            );
        let node = wires.node;
        let root = wires.root;

        // Left pad the leaf value.
        let value = left_pad_leaf_value(b, &wires.value);

        // Compute the metadata digest - D(key_id || value_id || slot).
        let inputs: Vec<_> = key_id
            .elements
            .iter()
            .cloned()
            .chain(value_id.elements)
            .chain([slot.mapping_slot])
            .collect();
        assert_eq!(inputs.len(), 9);

        let metadata_digest = b.map_to_curve_point(&inputs);

        // Compute the values digest - D(D(key_id || key) + D(value_id || value)).
        assert_eq!(slot.mapping_key.arr.len(), MAPPING_KEY_LEN);
        assert_eq!(value.arr.len(), MAPPING_LEAF_VALUE_LEN);
        let [packed_key, packed_value] = [&slot.mapping_key, &value].map(|arr| {
            convert_u8_targets_to_u32(b, &arr.arr)
                .into_iter()
                .map(|t| t.0)
                .collect::<Vec<_>>()
        });
        let inputs: Vec<_> = key_id.elements.into_iter().chain(packed_key).collect();
        let k_digest = b.map_to_curve_point(&inputs);
        let inputs: Vec<_> = value_id.elements.into_iter().chain(packed_value).collect();
        let v_digest = b.map_to_curve_point(&inputs);
        // D(key_id || key) + D(value_id || value)
        let add_digest = b.curve_add(k_digest, v_digest);
        let inputs: Vec<_> = add_digest
            .0
             .0
            .into_iter()
            .flat_map(|ext| ext.0)
            .chain(iter::once(k_digest.0 .1.target))
            .collect();
        let values_digest = b.map_to_curve_point(&inputs);

        // Only one leaf in this node.
        let n = b.one();

        // Register the public inputs.
        /* TODO
        PublicInputs::register(
            b,
            &root.output_array,
            &wires.key,
            values_digest,
            metadata_digest,
            n,
        );
        */

        LeafMappingWires {
            node,
            root,
            slot,
            value,
            key_id,
            value_id,
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &LeafMappingWires<NODE_LEN>) {
        let pad_node =
            Vector::<u8, { PAD_LEN(NODE_LEN) }>::from_vec(&self.node).expect("invalid node given");
        wires.node.assign(pw, &pad_node);
        KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&pad_node),
        );
        self.slot.assign(pw, &wires.slot);
        pw.set_hash_target(wires.key_id, self.key_id);
        pw.set_hash_target(wires.value_id, self.value_id);
    }
}

/// Num of children = 0
impl CircuitLogicWires<GFp, D, 0> for LeafMappingWires<MAX_LEAF_NODE_LEN> {
    type CircuitBuilderParams = ();

    type Inputs = LeafMappingCircuit<MAX_LEAF_NODE_LEN>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GFp>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<GFp, D>,
        _verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<D>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        LeafMappingCircuit::build(builder)
    }

    fn assign_input(
        &self,
        inputs: Self::Inputs,
        pw: &mut PartialWitness<GFp>,
    ) -> anyhow::Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            compute_leaf_mapping_key_id, compute_leaf_mapping_metadata_digest,
            compute_leaf_mapping_value_id, compute_leaf_mapping_values_digest,
        },
        *,
    };
    use eth_trie::{Nibbles, Trie};
    use ethers::types::Address;
    use mp2_common::{
        array::Array,
        eth::{left_pad32, StorageSlot},
        group_hashing::map_to_curve_point,
        mpt_sequential::utils::bytes_to_nibbles,
        rlp::MAX_KEY_NIBBLE_LEN,
        utils::{convert_u8_to_u32_slice, keccak256, pack_and_compute_poseidon_value},
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
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use std::str::FromStr;

    const TEST_CONTRACT_ADDRESS: &str = "0x105dD0eF26b92a3698FD5AaaF688577B9Cafd970";

    #[derive(Clone, Debug)]
    struct TestLeafMappingCircuit<const NODE_LEN: usize> {
        c: LeafMappingCircuit<NODE_LEN>,
        exp_value: Vec<u8>,
    }

    impl<const NODE_LEN: usize> UserCircuit<F, D> for TestLeafMappingCircuit<NODE_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
    {
        // Leaf wires + expected extracted value
        type Wires = (
            LeafMappingWires<NODE_LEN>,
            Array<Target, MAPPING_LEAF_VALUE_LEN>,
        );

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let exp_value = Array::<Target, MAPPING_LEAF_VALUE_LEN>::new(b);

            let leaf_wires = LeafMappingCircuit::<NODE_LEN>::build(b);
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
    fn test_values_extraction_leaf_mapping_circuit() {
        const NODE_LEN: usize = 80;

        let mapping_slot = 2_u8;
        let mapping_key = hex::decode("1234").unwrap();
        let slot = StorageSlot::Mapping(mapping_key.clone(), mapping_slot as usize);
        let contract_address = Address::from_str(TEST_CONTRACT_ADDRESS).unwrap();
        let key_id = compute_leaf_mapping_key_id(mapping_slot, &contract_address);
        let value_id = compute_leaf_mapping_value_id(mapping_slot, &contract_address);

        let (mut trie, _) = generate_random_storage_mpt::<3, MAPPING_LEAF_VALUE_LEN>();
        let value = random_vector(MAPPING_LEAF_VALUE_LEN);
        let encoded_value: Vec<u8> = rlp::encode(&value).to_vec();
        trie.insert(&slot.mpt_key(), &encoded_value).unwrap();
        trie.root_hash().unwrap();

        let proof = trie.get_proof(&slot.mpt_key_vec()).unwrap();
        let node = proof.last().unwrap().clone();

        let c = LeafMappingCircuit::<NODE_LEN> {
            node: node.clone(),
            slot: MappingSlot::new(mapping_slot, mapping_key.clone()),
            key_id,
            value_id,
        };
        let test_circuit = TestLeafMappingCircuit {
            c,
            exp_value: value.clone(),
        };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::new(&proof.public_inputs);

        {
            let exp_hash = keccak256(&node);
            let exp_hash = convert_u8_to_u32_slice(&exp_hash);
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
            let exp_digest =
                compute_leaf_mapping_values_digest(&key_id, &value_id, &mapping_key, &value);
            assert_eq!(pi.values_digest(), exp_digest.to_weierstrass());
        }
        // Check metadata digest
        {
            let exp_digest = compute_leaf_mapping_metadata_digest(&key_id, &value_id, mapping_slot);
            assert_eq!(pi.metadata_digest(), exp_digest.to_weierstrass());
        }
        assert_eq!(pi.n(), F::ONE);
    }
}
