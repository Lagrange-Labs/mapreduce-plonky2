use std::{array, sync::Arc};

use eth_trie::{EthTrie, MemoryDB, Nibbles, Node, Trie};
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
use rand::{rngs::StdRng, RngCore, SeedableRng};

use super::{
    BranchLengthCircuit, BranchLengthWires, ExtensionLengthCircuit, ExtensionLengthWires,
    LeafLengthCircuit, LeafLengthWires, PublicInputs,
};

const NODE_LEN: usize = 532;

#[test]
fn prove_and_verify_length_extraction_circuit() {
    let setup_leaf = setup_circuit::<_, D, PoseidonGoldilocksConfig, LeafLengthCircuit<NODE_LEN>>();
    let setup_branch = setup_circuit::<_, D, PoseidonGoldilocksConfig, BranchTestCircuit>();
    let setup_extension = setup_circuit::<_, D, PoseidonGoldilocksConfig, ExtensionTestCircuit>();
    let mut cases = vec![];

    // max u32 shouldn't overflow
    cases.push(TestCase {
        seed: 0xbeef,
        length_slot: 0xba,
        variable_slot: 0xfa,
        length: u32::MAX,
    });

    // encoded RLP low value should decode
    cases.push(TestCase {
        seed: 0xbeef,
        length_slot: 0xba,
        variable_slot: 0xfa,
        length: 15,
    });

    for case in cases {
        let TestData {
            length_key,
            length_node,
            branch_node,
            ext_node,
            root_node,
        } = case.generate();

        // Leaf extraction

        let leaf_circuit =
            LeafLengthCircuit::new(case.length_slot, &length_node, case.variable_slot).unwrap();

        let leaf_proof = prove_circuit(&setup_leaf, &leaf_circuit);
        let leaf_pi = PublicInputs::<GFp>::from_slice(&leaf_proof.public_inputs);
        let length = GFp::from_canonical_u32(case.length);
        let pointer = GFp::from_canonical_u8(63);

        case.assert_correct_dm(case.length_slot, &leaf_pi);
        case.assert_correct_root(&length_node, &leaf_pi);

        assert_eq!(leaf_pi.length(), &length);
        assert_eq!(leaf_pi.mpt_key(), &length_key);
        assert_eq!(leaf_pi.mpt_key_pointer(), &pointer);

        // First branch extraction

        let branch_circuit = BranchTestCircuit {
            base: BranchLengthCircuit::<NODE_LEN>::new(&branch_node).unwrap(),
            pi: &leaf_proof.public_inputs,
        };
        let branch_proof = prove_circuit(&setup_branch, &branch_circuit);
        let branch_pi = PublicInputs::<GFp>::from_slice(&branch_proof.public_inputs);
        let pointer = GFp::from_canonical_u8(62);

        case.assert_correct_dm(case.length_slot, &branch_pi);
        case.assert_correct_root(&branch_node, &branch_pi);

        assert_eq!(branch_pi.length(), &length);
        assert_eq!(branch_pi.mpt_key(), &length_key);
        assert_eq!(branch_pi.mpt_key_pointer(), &pointer);

        // Extension extraction

        let ext_circuit = ExtensionTestCircuit {
            base: ExtensionLengthCircuit::new(ext_node.clone()),
            pi: &branch_pi.to_vec(),
        };
        let ext_proof = prove_circuit(&setup_extension, &ext_circuit);
        let ext_pi = PublicInputs::<GFp>::from_slice(&ext_proof.public_inputs);
        let pointer = GFp::from_canonical_u8(61);

        case.assert_correct_dm(case.length_slot, &ext_pi);
        case.assert_correct_root(&ext_node, &ext_pi);

        assert_eq!(ext_pi.length(), &length);
        assert_eq!(ext_pi.mpt_key(), &length_key);
        assert_eq!(ext_pi.mpt_key_pointer(), &pointer);

        // Root extraction

        let root_circuit = BranchTestCircuit {
            base: BranchLengthCircuit::<NODE_LEN>::new(&root_node).unwrap(),
            pi: &ext_proof.public_inputs,
        };
        let root_proof = prove_circuit(&setup_branch, &root_circuit);
        let root_pi = PublicInputs::<GFp>::from_slice(&root_proof.public_inputs);
        let pointer = GFp::from_canonical_u8(60);

        case.assert_correct_dm(case.length_slot, &root_pi);
        case.assert_correct_root(&root_node, &root_pi);

        assert_eq!(root_pi.length(), &length);
        assert_eq!(root_pi.mpt_key(), &length_key);
        assert_eq!(root_pi.mpt_key_pointer(), &pointer);
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

#[derive(Debug, Clone)]
struct ExtensionTestWires {
    base: ExtensionLengthWires,
    pi: Vec<Target>,
}

#[derive(Debug, Clone)]
struct ExtensionTestCircuit<'a> {
    base: ExtensionLengthCircuit,
    pi: &'a [GFp],
}

impl<'a> UserCircuit<GFp, D> for ExtensionTestCircuit<'a> {
    type Wires = ExtensionTestWires;

    fn build(cb: &mut CBuilder) -> Self::Wires {
        let pi = cb.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
        let base = ExtensionLengthCircuit::build(cb, PublicInputs::from_slice(&pi));

        ExtensionTestWires { base, pi }
    }

    fn prove(&self, pw: &mut PartialWitness<GFp>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.pi, self.pi);
        self.base.assign(pw, &wires.base);
    }
}

struct TestCase {
    pub seed: u64,
    pub length_slot: u8,
    pub variable_slot: u8,
    pub length: u32,
}

struct TestData {
    pub length_key: Vec<GFp>,
    pub length_node: Vec<u8>,
    pub branch_node: Vec<u8>,
    pub ext_node: Vec<u8>,
    pub root_node: Vec<u8>,
}

impl TestCase {
    pub fn generate(&self) -> TestData {
        let rng = &mut StdRng::seed_from_u64(self.seed);
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));

        let storage_slot = StorageSlot::Simple(self.length_slot as usize);
        let length_key = storage_slot.mpt_key_vec();
        let length_nibbles = Nibbles::from_raw(&length_key, true);
        let length_value = rlp::encode(&self.length).to_vec();
        let length_node = Node::from_leaf(length_nibbles.clone(), length_value);

        let next_nibble = length_nibbles.offset(1).at(0);
        let branch_node: [_; 16] = array::from_fn(|i| {
            if i == next_nibble {
                length_node.clone()
            } else {
                let mut rng_nibbles = [0u8; 32];
                let mut rng_value = [0u8; 32];

                rng.fill_bytes(&mut rng_nibbles);
                rng.fill_bytes(&mut rng_value);

                let rng_nibbles = Nibbles::from_raw(&rng_nibbles, false);

                match rng.next_u32() % 4 {
                    0 => Node::Empty,
                    1 => Node::from_leaf(rng_nibbles, rng_value.to_vec()),
                    2 => Node::from_branch(array::from_fn(|_| Node::Empty), None),
                    3 => Node::from_extension(rng_nibbles, Node::Empty),
                    _ => unreachable!(),
                }
            }
        });
        let branch_node = Node::from_branch(branch_node, None);

        let prefix = length_nibbles.offset(2);
        let ext_node = Node::from_extension(prefix, branch_node.clone());

        let next_nibble = length_nibbles.offset(3).at(0);
        let root_node: [_; 16] = array::from_fn(|i| {
            if i == next_nibble {
                ext_node.clone()
            } else {
                let mut rng_nibbles = [0u8; 32];
                let mut rng_value = [0u8; 32];

                rng.fill_bytes(&mut rng_nibbles);
                rng.fill_bytes(&mut rng_value);

                let rng_nibbles = Nibbles::from_raw(&rng_nibbles, false);

                match rng.next_u32() % 4 {
                    0 => Node::Empty,
                    1 => Node::from_leaf(rng_nibbles, rng_value.to_vec()),
                    2 => Node::from_branch(array::from_fn(|_| Node::Empty), None),
                    3 => Node::from_extension(rng_nibbles, Node::Empty),
                    _ => unreachable!(),
                }
            }
        });
        let root_node = Node::from_branch(root_node, None);

        // trie encoding mutates the state
        trie.encode_raw(&branch_node);
        trie.encode_raw(&ext_node);
        trie.encode_raw(&root_node);
        trie.root_hash().unwrap();

        let length_key = length_nibbles
            .nibbles()
            .to_vec()
            .into_iter()
            .map(GFp::from_canonical_u8)
            .collect();

        TestData {
            length_key,
            length_node: trie.encode_raw(&length_node),
            branch_node: trie.encode_raw(&branch_node),
            ext_node: trie.encode_raw(&ext_node),
            root_node: trie.encode_raw(&root_node),
        }
    }

    pub fn assert_correct_dm(&self, slot: u8, pi: &PublicInputs<GFp>) {
        let dm = map_to_curve_point(&[
            GFp::from_canonical_u8(slot),
            GFp::from_canonical_u8(self.variable_slot),
        ])
        .to_weierstrass();

        let x = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| pi.metadata().0[i]);
        let y = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| pi.metadata().1[i]);
        let is_inf = pi.metadata().2 == &GFp::ONE;
        let dm_p = WeierstrassPoint {
            x: GFp5::from_basefield_array(x),
            y: GFp5::from_basefield_array(y),
            is_inf,
        };

        assert_eq!(dm, dm_p);
    }

    pub fn assert_correct_root(&self, node: &[u8], pi: &PublicInputs<GFp>) {
        let root: Vec<_> = convert_u8_to_u32_slice(&keccak256(node))
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        assert_eq!(pi.root_hash(), &root);
    }
}
