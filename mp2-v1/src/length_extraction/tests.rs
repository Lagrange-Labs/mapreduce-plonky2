use std::{array, sync::Arc};

use eth_trie::{EthTrie, MemoryDB, Trie};
use mp2_common::{
    eth::StorageSlot,
    group_hashing::{map_to_curve_point, EXTENSION_DEGREE},
    types::{CBuilder, GFp, GFp5},
    utils::{convert_u8_to_u32_slice, keccak256},
    D,
};
use mp2_test::circuit::{prove_circuit, setup_circuit, UserCircuit};
use plonky2::{
    field::{extension::FieldExtension, types::Field},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::config::PoseidonGoldilocksConfig,
};
use plonky2_ecgfp5::curve::curve::WeierstrassPoint;

use super::{
    BranchLengthCircuit, BranchLengthWires, LeafLengthCircuit, LeafLengthWires, PublicInputs,
};

const NODE_LEN: usize = 500;

#[test]
fn prove_and_verify_length_extraction_circuit() {
    let setup_leaf = setup_circuit::<_, D, PoseidonGoldilocksConfig, LeafLengthCircuit<NODE_LEN>>();
    let setup_branch = setup_circuit::<_, D, PoseidonGoldilocksConfig, BranchTestCircuit>();
    let mut cases = vec![];

    // max u32 shouldn't overflow
    cases.push(TestCase {
        is_rlp_encoded: true,
        slot: 0xba,
        length: u32::MAX,
        variable_slot: 0xfa,
    });

    // encoded RLP low value should decode
    cases.push(TestCase {
        is_rlp_encoded: true,
        slot: 0xba,
        length: 15,
        variable_slot: 0xfa,
    });

    // raw value should decode
    cases.push(TestCase {
        is_rlp_encoded: false,
        slot: 0xba,
        length: 8943278,
        variable_slot: 0xfa,
    });

    for TestCase {
        is_rlp_encoded,
        slot,
        length,
        variable_slot,
    } in cases
    {
        let node = generate_length_slot_node(is_rlp_encoded, slot, length);
        let root = keccak256(&node);
        let root_hash: Vec<_> = convert_u8_to_u32_slice(&root)
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        // Leaf extraction

        let leaf_circuit =
            LeafLengthCircuit::new(is_rlp_encoded, slot, &node, variable_slot).unwrap();

        let leaf_proof = prove_circuit(&setup_leaf, &leaf_circuit);
        let leaf_pi = PublicInputs::<GFp>::from_slice(&leaf_proof.public_inputs);

        let length = GFp::from_canonical_u32(length);
        let dm = map_to_curve_point(&[
            GFp::from_canonical_u8(slot),
            GFp::from_canonical_u8(variable_slot),
            GFp::from_bool(is_rlp_encoded),
        ]);

        let x = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| leaf_pi.metadata().0[i]);
        let y = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| leaf_pi.metadata().1[i]);
        let is_inf = leaf_pi.metadata().2 == &GFp::ONE;
        let dm_p = WeierstrassPoint {
            x: GFp5::from_basefield_array(x),
            y: GFp5::from_basefield_array(y),
            is_inf,
        };

        assert_eq!(leaf_pi.length(), &length);
        assert_eq!(leaf_pi.root_hash(), root_hash);
        assert_eq!(dm.to_weierstrass(), dm_p);

        if is_rlp_encoded {
            // Branch extraction

            let branch_circuit = BranchTestCircuit {
                base: BranchLengthCircuit::<NODE_LEN>::new(&root).unwrap(),
                pi: &leaf_proof.public_inputs,
            };
            let branch_proof = prove_circuit(&setup_branch, &branch_circuit);
            let branch_pi = PublicInputs::<GFp>::from_slice(&branch_proof.public_inputs);

            let root = keccak256(&root);
            let root_hash: Vec<_> = convert_u8_to_u32_slice(&root)
                .into_iter()
                .map(GFp::from_canonical_u32)
                .collect();

            assert_eq!(
                *branch_pi.mpt_key_pointer(),
                *leaf_pi.mpt_key_pointer() - GFp::ONE
            );
            assert_eq!(branch_pi.root_hash(), root_hash);
        }
    }
}

impl UserCircuit<GFp, D> for LeafLengthCircuit<NODE_LEN> {
    type Wires = LeafLengthWires<NODE_LEN>;

    fn build(cb: &mut CBuilder) -> Self::Wires {
        LeafLengthCircuit::build(cb)
    }

    fn prove(&self, pw: &mut PartialWitness<GFp>, wires: &Self::Wires) {
        self.assign(pw, wires);
    }
}

#[derive(Debug, Clone)]
struct BranchTestWires {
    base: BranchLengthWires<NODE_LEN>,
    pi: Vec<Target>,
}

#[derive(Debug, Clone)]
struct BranchTestCircuit<'a> {
    base: BranchLengthCircuit<NODE_LEN>,
    pi: &'a [GFp],
}

impl<'a> UserCircuit<GFp, D> for BranchTestCircuit<'a> {
    type Wires = BranchTestWires;

    fn build(cb: &mut CBuilder) -> Self::Wires {
        let pi = cb.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
        let base = BranchLengthCircuit::build(cb, PublicInputs::from_slice(&pi));

        BranchTestWires { base, pi }
    }

    fn prove(&self, pw: &mut PartialWitness<GFp>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.pi, self.pi);
        self.base.assign(pw, &wires.base);
    }
}

struct TestCase {
    pub is_rlp_encoded: bool,
    pub slot: u8,
    pub length: u32,
    pub variable_slot: u8,
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

    trie.get_proof(&mpt_key).unwrap()[0].clone()
}
