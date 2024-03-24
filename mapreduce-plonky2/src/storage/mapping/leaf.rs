//! Module handling the recursive proving of mapping entries specically
//! inside a storage trie.

use std::array::from_fn as create_array;

use crate::array::L32;
use crate::circuit::UserCircuit;
use crate::mpt_sequential::MAX_LEAF_VALUE_LEN;
use crate::rlp::short_string_len;
use crate::storage::key::{MappingSlotWires, MAPPING_INPUT_TOTAL_LEN};
use crate::storage::{MAX_EXTENSION_NODE_LEN, MAX_LEAF_NODE_LEN};
use crate::types::MAPPING_KEY_LEN;
use crate::utils::convert_u8_targets_to_u32;
use crate::{
    array::{Array, Vector, VectorWire},
    group_hashing::CircuitBuilderGroupHashing,
    keccak::{InputData, KeccakCircuit, KeccakWires, HASH_LEN},
    mpt_sequential::{Circuit as MPTCircuit, PAD_LEN},
    rlp::decode_fixed_list,
};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use super::super::key::MappingSlot;
use crate::storage::mapping::public_inputs::PublicInputs;

/// This constant represents the maximum size a value can be inside the storage trie.
/// It is different than the `MAX_LEAF_VALUE_LEN` constant because it represents the
/// value **not** RLP encoded,i.e. without the 1-byte RLP header.
pub(crate) const VALUE_LEN: usize = 32;

/// Circuit implementing the circuit to prove the correct derivation of the
/// MPT key from a mapping key and mapping slot. It also do the usual recursive
/// MPT proof verification logic.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LeafCircuit<const NODE_LEN: usize> {
    pub(crate) node: Vec<u8>,
    pub(crate) slot: MappingSlot,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub(crate) struct LeafWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
    mapping_slot: MappingSlotWires,
    value: Array<Target, VALUE_LEN>,
}
impl<const N: usize> LeafWires<N>
where
    [(); PAD_LEN(N)]:,
{
    pub fn mapping_key(&self) -> Array<Target, MAPPING_KEY_LEN> {
        self.mapping_slot.mapping_key.clone()
    }

    pub fn mapping_slot(&self) -> Target {
        self.mapping_slot.mapping_slot
    }
}

impl<const NODE_LEN: usize> LeafCircuit<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> LeafWires<NODE_LEN> {
        let zero = b.zero();
        let tru = b._true();
        let node = VectorWire::<Target, { PAD_LEN(NODE_LEN) }>::new(b);
        // always ensure theThanks all node is bytes at the beginning
        node.assert_bytes(b);

        // First expose the keccak root of this subtree starting at this node
        let root = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(b, &node);

        // Then derives the correct MPT key from this (mappingkey,mappingslot) pair
        let mapping_slot_wires = MappingSlot::mpt_key(b);

        // Then advance the key and extract the value
        // only decode two headers in the case of leaf
        let rlp_headers = decode_fixed_list::<_, _, 2>(b, &node.arr.arr, zero);
        let (new_key, encoded_value, is_valid) =
            MPTCircuit::<1, NODE_LEN>::advance_key_leaf_or_extension::<_, _, _, MAX_LEAF_VALUE_LEN>(
                b,
                &node.arr,
                &mapping_slot_wires.keccak_mpt.mpt_key,
                &rlp_headers,
            );
        b.connect(tru.target, is_valid.target);
        // Read the length of the relevant data (RLP header - 0x80)
        let data_len = short_string_len(b, &encoded_value[0]);
        // Create vector of only the relevant data - skipping the RLP header
        // + stick with the same encoding of the data but pad_left32.
        let big_endian_left_padded = encoded_value
            .take_last::<GoldilocksField, 2, VALUE_LEN>()
            .into_vec(data_len)
            .normalize_left::<_, _, VALUE_LEN>(b);
        // Then creates the initial accumulator from the (mapping_key, value)
        let mut inputs = [b.zero(); MAPPING_INPUT_TOTAL_LEN];
        inputs[0..MAPPING_KEY_LEN].copy_from_slice(&mapping_slot_wires.mapping_key.arr);
        inputs[MAPPING_KEY_LEN..MAPPING_KEY_LEN + VALUE_LEN]
            .copy_from_slice(&big_endian_left_padded.arr);
        // couldn't make it work with array API because of const generic issue...
        //let packed = Array { arr: inputs }.convert_u8_to_u32(b);
        let packed = convert_u8_targets_to_u32(b, &inputs)
            .into_iter()
            .map(|x| x.0)
            .collect::<Vec<_>>();
        let leaf_accumulator = b.map_to_curve_point(&packed);

        // and register the public inputs
        let n = b.one(); // only one leaf seen in that leaf !
        PublicInputs::register(
            b,
            &new_key,
            mapping_slot_wires.mapping_slot,
            n,
            &root.output_array,
            &leaf_accumulator,
        );
        //mapping_slot_wires.mapping_key.register_as_public_input(b);
        //big_endian_left_padded.register_as_public_input(b);
        LeafWires {
            node,
            root,
            mapping_slot: mapping_slot_wires,
            value: big_endian_left_padded,
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &LeafWires<NODE_LEN>) {
        let pad_node =
            Vector::<u8, { PAD_LEN(NODE_LEN) }>::from_vec(&self.node).expect("invalid node given");
        wires.node.assign(pw, &pad_node);
        KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&pad_node),
        );
        self.slot.assign(pw, &wires.mapping_slot);
    }
}

pub(super) type StorageLeafWire = LeafWires<MAX_LEAF_NODE_LEN>;
/// D = 2,
/// Num of children = 0
impl CircuitLogicWires<GoldilocksField, 2, 0> for StorageLeafWire {
    type CircuitBuilderParams = ();

    type Inputs = LeafCircuit<MAX_LEAF_NODE_LEN>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GoldilocksField>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<GoldilocksField, 2>,
        verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<2>; 0],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        LeafCircuit::build(builder)
    }

    fn assign_input(
        &self,
        inputs: Self::Inputs,
        pw: &mut PartialWitness<GoldilocksField>,
    ) -> anyhow::Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}
#[cfg(test)]
mod test {
    use std::array::from_fn as create_array;

    use crate::circuit::test::run_circuit;
    use crate::mpt_sequential::test::generate_random_storage_mpt;
    use crate::rlp::MAX_KEY_NIBBLE_LEN;
    use crate::storage::lpn::leaf_digest_for_mapping;
    use crate::utils::keccak256;
    use crate::utils::test::random_vector;
    use eth_trie::{Nibbles, Trie};
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use rand::{thread_rng, Rng};

    use super::{LeafCircuit, LeafWires, PublicInputs, VALUE_LEN};
    use crate::array::Array;
    use crate::circuit::UserCircuit;
    use crate::eth::{left_pad32, StorageSlot};
    use crate::group_hashing::map_to_curve_point;
    use crate::mpt_sequential::{bytes_to_nibbles, MAX_LEAF_VALUE_LEN};
    use crate::storage::key::MappingSlot;
    use crate::utils::convert_u8_to_u32_slice;
    use plonky2::field::types::Field;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    use crate::storage::mapping::leaf::PAD_LEN;
    #[derive(Clone, Debug)]
    struct TestLeafCircuit<const NODE_LEN: usize> {
        c: LeafCircuit<NODE_LEN>,
        exp_value: Vec<u8>,
    }
    impl<const NODE_LEN: usize> UserCircuit<F, D> for TestLeafCircuit<NODE_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
    {
        // normal wires + expected extracted value
        type Wires = (LeafWires<NODE_LEN>, Array<Target, VALUE_LEN>);

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let exp_value = Array::<Target, VALUE_LEN>::new(b);
            let leaf_wires = LeafCircuit::<NODE_LEN>::build(b);
            leaf_wires.value.enforce_equal(b, &exp_value);
            //let eq = leaf_wires.value.equals(b, &exp_value);
            //let tt = b._true();
            //b.connect(tt.target, eq.target);
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
    fn test_leaf_circuit() {
        let mapping_key = hex::decode("1234").unwrap();
        let mapping_slot = 2;
        let slot = StorageSlot::Mapping(mapping_key.clone(), mapping_slot);
        let (mut trie, _) = generate_random_storage_mpt::<3, VALUE_LEN>();
        // generating a fake uint256 value
        let random_value = random_vector(VALUE_LEN);
        let encoded_value: Vec<u8> = rlp::encode(&random_value).to_vec();
        trie.insert(&slot.mpt_key(), &encoded_value).unwrap();
        trie.root_hash().unwrap();
        let proof = trie.get_proof(&slot.mpt_key_vec()).unwrap();
        let node = proof.last().unwrap().clone(); // proof from RPC gives leaf as last
        let mpt_key = slot.mpt_key_vec();
        let slot = MappingSlot::new(mapping_slot as u8, mapping_key.clone());
        let circuit = LeafCircuit::<80> {
            node: node.clone(),
            slot,
        };
        let test = TestLeafCircuit {
            c: circuit,
            exp_value: random_value.clone(),
        };
        let proof = run_circuit::<F, D, C, _>(test);
        let pi = PublicInputs::<F>::from(&proof.public_inputs);
        {
            // expected accumulator Acc((mappping_key,value))
            let exp_digest = leaf_digest_for_mapping(&mapping_key, &random_value).to_weierstrass();
            let found_digest = pi.accumulator();
            assert_eq!(exp_digest, found_digest);
        }
        {
            // expected MPT hash
            let exp_hash = keccak256(&node);
            let found_hash = pi.root_hash();
            let exp_packed = convert_u8_to_u32_slice(&exp_hash);
            assert_eq!(exp_packed, found_hash);
        }
        {
            // expected mpt key wire
            let (key, ptr) = pi.mpt_key_info();
            let exp_key = bytes_to_nibbles(&mpt_key)
                .into_iter()
                .map(F::from_canonical_u8)
                .collect::<Vec<_>>();
            assert_eq!(key, exp_key);
            let leaf_key: Vec<Vec<u8>> = rlp::decode_list(&node);
            let nib = Nibbles::from_compact(&leaf_key[0].clone());
            let exp_ptr = F::from_canonical_usize(MAX_KEY_NIBBLE_LEN - 1 - nib.nibbles().len());
            assert_eq!(exp_ptr, ptr);
        }
        {
            // expected mapping slot
            let ms = pi.mapping_slot();
            let exp_ms = F::from_canonical_usize(mapping_slot);
            assert_eq!(ms, exp_ms);
        }
        {
            // expected number of leaf seen
            let n = pi.n();
            let exp_n = F::ONE;
            assert_eq!(n, exp_n);
        }
    }

    impl<const NODE_LEN: usize> UserCircuit<F, D> for LeafCircuit<NODE_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
    {
        type Wires = LeafWires<NODE_LEN>;
        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            LeafCircuit::build(b)
        }
        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.assign(pw, wires);
        }
    }
}
