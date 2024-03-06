//! Module handling the recursive proving of mapping entries specically
//! inside a storage trie.

use crate::circuit::UserCircuit;
use crate::mpt_sequential::MAX_LEAF_VALUE_LEN;
use crate::storage::key::MappingSlotWires;
use crate::storage::mapping::extension::MAX_EXTENSION_NODE_LEN;
use crate::{
    array::{Array, Vector, VectorWire},
    eth::left_pad32,
    group_hashing::{self, CircuitBuilderGroupHashing},
    keccak::{
        ByteKeccakWires, InputData, KeccakCircuit, KeccakWires, OutputHash, HASH_LEN,
        PACKED_HASH_LEN,
    },
    mpt_sequential::{Circuit as MPTCircuit, MPTKeyWire, PAD_LEN},
    rlp::{decode_fixed_list, MAX_ITEMS_IN_LIST, MAX_KEY_NIBBLE_LEN},
    utils::{convert_u8_targets_to_u32, keccak256},
};
use core::array::from_fn as create_array;
use ethers::types::spoof::Storage;
use plonky2::field::extension::quintic::QuinticExtension;
use plonky2::field::extension::FieldExtension;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{RichField, NUM_HASH_OUT_ELTS},
        keccak,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::curve::curve::WeierstrassPoint;
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use plonky2_ecgfp5::gadgets::{base_field::QuinticExtensionTarget, curve::CurveTarget};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use super::super::key::{MappingSlot, MAPPING_KEY_LEN};
use crate::storage::mapping::public_inputs::PublicInputs;

pub(super) const MAX_LEAF_NODE_LEN: usize = MAX_EXTENSION_NODE_LEN;
/// Circuit implementing the circuit to prove the correct derivation of the
/// MPT key from a mapping key and mapping slot. It also do the usual recursive
/// MPT proof verification logic.
#[derive(Clone, Debug)]
pub(crate) struct LeafCircuit<const NODE_LEN: usize> {
    pub(super) node: Vec<u8>,
    pub(super) slot: MappingSlot,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LeafWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
    mapping_slot: MappingSlotWires,
    value: Array<Target, MAX_LEAF_VALUE_LEN>,
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
        let (new_key, value, is_valid) = MPTCircuit::<1, NODE_LEN>::advance_key_leaf_or_extension(
            b,
            &node.arr,
            &mapping_slot_wires.keccak_mpt.mpt_key,
            &rlp_headers,
        );
        b.connect(tru.target, is_valid.target);
        // Then creates the initial accumulator from the (mapping_key, value)
        let mut inputs = [b.zero(); HASH_LEN * 2];
        inputs[0..HASH_LEN].copy_from_slice(&mapping_slot_wires.mapping_key.arr);
        inputs[HASH_LEN..2 * HASH_LEN].copy_from_slice(&value.arr);
        let leaf_accumulator = b.map_to_curve_point(&inputs);

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
        LeafWires {
            node,
            root,
            mapping_slot: mapping_slot_wires,
            value,
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
    use crate::utils::keccak256;
    use eth_trie::{Nibbles, Trie};
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::{
        field::extension::Extendable, hash::hash_types::RichField,
        plonk::circuit_builder::CircuitBuilder,
    };
    use plonky2_crypto::u32::arithmetic_u32::U32Target;
    use plonky2_ecgfp5::curve::curve::WeierstrassPoint;
    use plonky2_ecgfp5::gadgets::curve::CurveTarget;
    use rand::{thread_rng, Rng};
    use rlp::Rlp;

    use super::{LeafCircuit, LeafWires, PublicInputs};
    use crate::array::Array;
    use crate::circuit::UserCircuit;
    use crate::eth::{left_pad32, StorageSlot};
    use crate::group_hashing::{map_to_curve_point, CircuitBuilderGroupHashing};
    use crate::keccak::PACKED_HASH_LEN;
    use crate::mpt_sequential::{bytes_to_nibbles, MPTKeyWire, MAX_LEAF_VALUE_LEN};
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
        type Wires = (LeafWires<NODE_LEN>, Array<Target, MAX_LEAF_VALUE_LEN>);

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let exp_value = Array::<Target, MAX_LEAF_VALUE_LEN>::new(b);
            let leaf_wires = LeafCircuit::<NODE_LEN>::build(b);
            let eq = leaf_wires.value.equals(b, &exp_value);
            let tt = b._true();
            b.connect(tt.target, eq.target);
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
        let (mut trie, _) = generate_random_storage_mpt::<3, 32>();
        let mut random_value = [0u8; 32];
        thread_rng().fill(&mut random_value);
        trie.insert(&slot.mpt_key(), &random_value).unwrap();
        trie.root_hash().unwrap();
        let proof = trie.get_proof(&slot.mpt_key()).unwrap();
        let node = proof.last().unwrap().clone(); // proof from RPC gives leaf as last
        let mpt_key = slot.mpt_key();
        let slot = MappingSlot::new(mapping_slot as u8, mapping_key.clone());
        let circuit = LeafCircuit::<80> {
            node: node.clone(),
            slot,
        };
        let test = TestLeafCircuit {
            c: circuit,
            exp_value: random_value.to_vec(),
        };
        let proof = run_circuit::<F, D, C, _>(test);
        let pi = PublicInputs::<F>::from(&proof.public_inputs);
        {
            // expected accumulator Acc((mappping_key,value))
            let inputs_field = left_pad32(&mapping_key)
                .into_iter()
                .chain(left_pad32(&random_value))
                .map(F::from_canonical_u8)
                .collect::<Vec<_>>();
            let exp_accumulator = map_to_curve_point(&inputs_field).to_weierstrass();
            let found_accumulator = pi.accumulator();
            assert_eq!(exp_accumulator, found_accumulator);
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
}
