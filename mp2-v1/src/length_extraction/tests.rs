use std::{array, sync::Arc};

use eth_trie::{EthTrie, MemoryDB, Trie};
use mp2_common::{
    eth::StorageSlot,
    group_hashing::{map_to_curve_point, EXTENSION_DEGREE},
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

use super::{LeafLengthCircuit, LeafLengthWires, PublicInputs};

const NODE_LEN: usize = 500;

#[test]
fn prove_and_verify_length_extraction_circuit() {
    let mut cases = vec![];

    // max u32 shouldn't overflow
    cases.push((true, 0xba, u32::MAX, 0xfa));

    for (is_rlp_encoded, slot, length, variable_slot) in cases {
        let node = generate_length_slot_node(is_rlp_encoded, slot, length);
        let root_hash: Vec<_> = convert_u8_to_u32_slice(&keccak256(&node))
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        let test_circuit = LengthExtractionTestCircuit {
            base: LeafLengthCircuit::new(is_rlp_encoded, slot, &node, variable_slot).unwrap(),
        };

        let proof = run_circuit::<_, D, PoseidonGoldilocksConfig, _>(test_circuit);
        let pi = PublicInputs::<GFp>::from_slice(&proof.public_inputs);

        let length = GFp::from_canonical_u32(length);
        let dm = map_to_curve_point(&[
            GFp::from_canonical_u8(slot),
            GFp::from_canonical_u8(variable_slot),
            GFp::from_bool(is_rlp_encoded),
        ]);

        let x = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| pi.metadata().0[i]);
        let y = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| pi.metadata().1[i]);
        let is_inf = pi.metadata().2 == &GFp::ONE;
        let dm_p = WeierstrassPoint {
            x: GFp5::from_basefield_array(x),
            y: GFp5::from_basefield_array(y),
            is_inf,
        };

        assert_eq!(pi.length(), &length);
        assert_eq!(pi.root_hash(), root_hash);
        assert_eq!(dm.to_weierstrass(), dm_p);
    }
}

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

fn generate_length_slot_node(is_rlp_encoded: bool, slot: u8, length: u32) -> Vec<u8> {
    let memdb = Arc::new(MemoryDB::new(true));
    let mut trie = EthTrie::new(Arc::clone(&memdb));

    // generate the data
    let storage_slot = StorageSlot::Simple(slot as usize);
    let mpt_key = storage_slot.mpt_key_vec();
    let encoded_value = if is_rlp_encoded {
        rlp::encode(&length).to_vec()
    } else {
        length.to_be_bytes().to_vec()
    };

    trie.insert(&mpt_key, &encoded_value).unwrap();

    let node = trie.get_proof(&mpt_key).unwrap()[0].clone();

    node
}
