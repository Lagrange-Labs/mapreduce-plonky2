use std::sync::Arc;

use eth_trie::{EthTrie, MemoryDB, Trie};
use ethers::types::H160;
use mp2_common::{
    eth::StorageSlot,
    types::{CBuilder, GFp},
    utils::{convert_u8_to_u32_slice, keccak256},
    D,
};
use mp2_test::circuit::{run_circuit, UserCircuit};
use plonky2::{field::types::Field, iop::witness::PartialWitness, plonk::config::PoseidonGoldilocksConfig};
use rand::{thread_rng, Rng};

use super::{leaf_mapping::{LeafLengthCircuit, LeafLengthWires}, public_inputs::PublicInputs};

const DEPTH: usize = 4;
const NODE_LEN: usize = 500;

#[test]
fn prove_and_verify_length_extraction_circuit() {
    let test_data = TestData::generate::<DEPTH>();
    let exp_slot = GFp::from_canonical_u8(test_data.slot);
    let exp_value = GFp::from_canonical_u32(test_data.value);
    let exp_root_hash: Vec<_> =
        convert_u8_to_u32_slice(&keccak256(test_data.nodes.last().unwrap()))
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

    let variable_key: Vec<_> = test_data.nodes[0].iter().cloned().take(32).collect();
    let variable_key_field: Vec<_> = variable_key
        .iter()
        .map(|k| GFp::from_canonical_u8(*k))
        .collect();

    let is_rlp_encoded = true;
    let length_slot = test_data.slot;
    let mapping_slot = test_data.slot;
    let mapping_key = variable_key.clone();
    let mapping_node = &test_data.nodes[0];

    let test_circuit = LengthExtractionTestCircuit {
        base: LeafLengthCircuit::new(
            is_rlp_encoded,
            length_slot,
            mapping_slot,
            mapping_key,
            mapping_node,
        )
        .unwrap(),
    };

    let proof = run_circuit::<_, D, PoseidonGoldilocksConfig, _>(test_circuit);
    let pi = PublicInputs::<GFp>::from_slice(&proof.public_inputs);

    /*
    let is_rlp_encoded = GFp::ZERO;
    let dm = map_to_curve_point(
        &iter::once(GFp::from_canonical_u8(test_data.slot))
            .chain(iter::once(GFp::from_canonical_u8(test_data.slot)))
            .chain(variable_key_field.iter().cloned())
            .chain(iter::once(is_rlp_encoded))
            .collect::<Vec<_>>(),
    );

    let proof = run_circuit::<_, D, PoseidonGoldilocksConfig, _>(test_circuit);
    let pi = PublicInputs::<GFp>::from_slice(&proof.public_inputs);

    let x = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| pi.metadata().0[i]);
    let y = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| pi.metadata().1[i]);
    let is_inf = pi.metadata().2 == &GFp::ONE;
    let dm_p = WeierstrassPoint {
        x: GFp5::from_basefield_array(x),
        y: GFp5::from_basefield_array(y),
        is_inf,
    };

    assert_eq!(pi.length(), &exp_value);
    assert_eq!(pi.root_hash(), exp_root_hash);
    assert_eq!(dm.to_weierstrass(), dm_p);
    */
}

/*
use std::{array, iter, marker::PhantomData, sync::Arc};

use eth_trie::{EthTrie, MemoryDB, Trie};
use ethers::types::H160;
use mp2_common::{
    eth::{left_pad32, StorageSlot},
    group_hashing::{map_to_curve_point, EXTENSION_DEGREE},
    mpt_sequential::PAD_LEN,
    types::{CBuilder, GFp, GFp5},
    utils::{convert_u8_to_u32_slice, keccak256},
    D,
};
use mp2_test::circuit::{run_circuit, UserCircuit};
use plonky2::{
    field::{extension::FieldExtension, types::Field},
    iop::witness::PartialWitness,
    plonk::config::PoseidonGoldilocksConfig,
};
use plonky2_ecgfp5::curve::curve::WeierstrassPoint;
use rand::{thread_rng, Rng};

use crate::length_extraction::public_inputs::PublicInputs;

use super::{
    leaf_mapping::{LeafMappingLengthCircuit, LeafMappingLengthWires},
    leaf_value::{LeafValueLengthCircuit, LeafValueLengthWires},
};

const DEPTH: usize = 4;
const NODE_LEN: usize = 500;

#[test]
fn prove_and_verify_leaf_value_extraction_circuit() {
    let test_data = TestData::generate::<DEPTH>();
    let exp_slot = GFp::from_canonical_u8(test_data.slot);
    let exp_value = GFp::from_canonical_u32(test_data.value);
    let exp_root_hash: Vec<_> =
        convert_u8_to_u32_slice(&keccak256(test_data.nodes.last().unwrap()))
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

    for is_rlp_encoded in [true, false] {
        let test_circuit = LengthExtractionTestCircuit::<
            LeafValueLengthCircuit<DEPTH, NODE_LEN>,
            LeafValueLengthWires<DEPTH, NODE_LEN>,
        > {
            base: LeafValueLengthCircuit::new(
                test_data.slot,
                test_data.slot,
                is_rlp_encoded,
                test_data.nodes.clone(),
            ),
            wires: PhantomData,
        };

        let dm = map_to_curve_point(&[
            GFp::from_canonical_u8(test_data.slot),
            GFp::from_canonical_u8(test_data.slot),
            GFp::from_bool(is_rlp_encoded),
        ]);

        let proof = run_circuit::<_, D, PoseidonGoldilocksConfig, _>(test_circuit);
        let pi = PublicInputs::<GFp>::from_slice(&proof.public_inputs);

        let x = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| pi.metadata().0[i]);
        let y = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| pi.metadata().1[i]);
        let is_inf = pi.metadata().2 == &GFp::ONE;
        let dm_p = WeierstrassPoint {
            x: GFp5::from_basefield_array(x),
            y: GFp5::from_basefield_array(y),
            is_inf,
        };

        assert_eq!(pi.length(), &exp_value);
        assert_eq!(pi.root_hash(), exp_root_hash);
        assert_eq!(dm.to_weierstrass(), dm_p);
    }
}
#[test]

fn prove_and_verify_leaf_mapping_extraction_circuit() {
    const DEPTH: usize = 4;
    const NODE_LEN: usize = 500;

    let test_data = TestData::generate::<DEPTH>();
    let exp_slot = GFp::from_canonical_u8(test_data.slot);
    let exp_value = GFp::from_canonical_u32(test_data.value);
    let exp_root_hash: Vec<_> =
        convert_u8_to_u32_slice(&keccak256(test_data.nodes.last().unwrap()))
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

    let variable_key: Vec<_> = test_data.nodes[0].iter().cloned().take(32).collect();
    let variable_key_field: Vec<_> = variable_key
        .iter()
        .map(|k| GFp::from_canonical_u8(*k))
        .collect();
    let test_circuit = LengthExtractionTestCircuit::<
        LeafMappingLengthCircuit<DEPTH, NODE_LEN>,
        LeafMappingLengthWires<DEPTH, NODE_LEN>,
    > {
        base: LeafMappingLengthCircuit::new(
            test_data.slot,
            test_data.slot,
            variable_key.clone(),
            test_data.nodes.clone(),
        ),
        wires: PhantomData,
    };

    let is_rlp_encoded = GFp::ZERO;
    let dm = map_to_curve_point(
        &iter::once(GFp::from_canonical_u8(test_data.slot))
            .chain(iter::once(GFp::from_canonical_u8(test_data.slot)))
            .chain(variable_key_field.iter().cloned())
            .chain(iter::once(is_rlp_encoded))
            .collect::<Vec<_>>(),
    );

    let proof = run_circuit::<_, D, PoseidonGoldilocksConfig, _>(test_circuit);
    let pi = PublicInputs::<GFp>::from_slice(&proof.public_inputs);

    let x = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| pi.metadata().0[i]);
    let y = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| pi.metadata().1[i]);
    let is_inf = pi.metadata().2 == &GFp::ONE;
    let dm_p = WeierstrassPoint {
        x: GFp5::from_basefield_array(x),
        y: GFp5::from_basefield_array(y),
        is_inf,
    };

    assert_eq!(pi.length(), &exp_value);
    assert_eq!(pi.root_hash(), exp_root_hash);
    assert_eq!(dm.to_weierstrass(), dm_p);
}
*/

#[derive(Clone, Debug)]
struct LengthExtractionTestCircuit {
    base: LeafLengthCircuit<NODE_LEN>,
}

impl UserCircuit<GFp, D> for LengthExtractionTestCircuit {
    type Wires = LeafLengthWires<NODE_LEN>;

    fn build(cb: &mut CBuilder) -> Self::Wires {
        LeafLengthCircuit::build(cb)
    }

    fn prove(&self, pw: &mut PartialWitness<GFp>, wires: &Self::Wires) {
        self.base.assign(pw, wires);
    }
}

struct TestData {
    slot: u8,
    value: u32,
    contract_address: H160,
    nodes: Vec<Vec<u8>>,
}

impl TestData {
    fn generate<const DEPTH: usize>() -> Self {
        let mut elements = Vec::new();
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));

        // Loop to insert random elements as long as a random selected proof is
        // not of the right length.
        let mut rng = thread_rng();
        let (slot, contract_address, mpt_key, value_int) = loop {
            // Generate a MPT key from the slot and contract address.
            let slot = rng.gen::<u8>();
            let contract_address = H160(rng.gen::<[u8; 20]>());
            let storage_slot = StorageSlot::Simple(slot as usize);
            let key = storage_slot.mpt_key_vec();

            // Insert the key and value.
            let value = rng.gen::<u32>();
            // in eth, integers are big endian
            trie.insert(&key, &rlp::encode(&value.to_be_bytes().to_vec()))
                .unwrap();
            trie.root_hash().unwrap();

            // Save the slot, contract address and key temporarily.
            elements.push((slot, contract_address, key, value));

            // Check if any node has the DEPTH elements.
            if let Some((slot, contract_address, key, value)) = elements
                .iter()
                .find(|(_, _, key, _)| trie.get_proof(key).unwrap().len() == DEPTH)
            {
                break (*slot, *contract_address, key, value);
            }
        };

        let root_hash = trie.root_hash().unwrap();
        let value_buff: Vec<u8> = rlp::decode(&trie.get(mpt_key).unwrap().unwrap()).unwrap();

        // value is encoded with bigendian but our conversion to u32 expects little endian
        // and we exactly take 4 bytes so we need padding at the end
        let value_le_padded = value_buff
            .clone()
            .into_iter()
            .rev()
            .chain(std::iter::repeat(0))
            .take(4)
            .collect::<Vec<u8>>();

        let value = convert_u8_to_u32_slice(&value_le_padded)[0];
        assert_eq!(value, *value_int as u32);

        let mut nodes = trie.get_proof(mpt_key).unwrap();
        nodes.reverse();
        assert!(keccak256(nodes.last().unwrap()) == root_hash.to_fixed_bytes());

        Self {
            slot,
            value,
            contract_address,
            nodes,
        }
    }
}
