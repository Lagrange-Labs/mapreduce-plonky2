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
use plonky2_ecgfp5::curve::curve::{Point, WeierstrassPoint};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

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
        depth: 3,
        is_rlp_encoded: true,
        length: u32::MAX,
        ext_length: u8::MAX as u32,
        variable_slot: 0xfa,
    });

    /*
    // encoded RLP low value should decode
    cases.push(TestCase {
        seed: 0xdead,
        depth: 4,
        is_rlp_encoded: true,
        length: 15,
        ext_length: u8::MAX as u32,
        variable_slot: 0xfa,
    });

    // raw value should decode
    cases.push(TestCase {
        seed: 0xdead,
        depth: 4,
        is_rlp_encoded: true,
        length: 8943278,
        ext_length: u8::MAX as u32,
        variable_slot: 0xfa,
    });
    */

    for case in cases {
        // Leaf extraction

        let TreePath {
            slot,
            key,
            mut path,
            ext_key,
            ext_path,
        } = case.generate();

        let node = path.pop().unwrap();
        let leaf_circuit =
            LeafLengthCircuit::new(case.is_rlp_encoded, slot, &node, case.variable_slot).unwrap();

        let leaf_proof = prove_circuit(&setup_leaf, &leaf_circuit);
        let leaf_pi = PublicInputs::<GFp>::from_slice(&leaf_proof.public_inputs);
        let length = GFp::from_canonical_u32(case.length);
        let pointer = GFp::from_canonical_u8(63);

        case.assert_correct_dm(slot, &leaf_pi);
        case.assert_correct_root(&node, &leaf_pi);

        assert_eq!(leaf_pi.length(), &length);
        assert_eq!(leaf_pi.mpt_key(), &key);
        assert_eq!(leaf_pi.mpt_key_pointer(), &pointer);

        /*
        // Branch extraction

        let branch_circuit = BranchTestCircuit {
            base: BranchLengthCircuit::<NODE_LEN>::new(&path[case.depth - 2]).unwrap(),
            pi: &leaf_proof.public_inputs,
        };

        let branch_proof = prove_circuit(&setup_branch, &branch_circuit);
        let branch_pi = PublicInputs::<GFp>::from_slice(&branch_proof.public_inputs);
        let pointer = GFp::from_canonical_u8(61);

        case.assert_correct_dm(slot, &branch_pi);
        case.assert_correct_root(&path[case.depth - 2], &branch_pi);

        assert_eq!(branch_pi.length(), &length);
        assert_eq!(branch_pi.mpt_key(), &key);
        assert_eq!(branch_pi.mpt_key_pointer(), &pointer);
        */

        // Extension extraction

        /*
        let TreePath {
            slot,
            key,
            path,
            ext_key,
            ext_path,
        } = case.generate(true);

        let ext_circuit = ExtensionTestCircuit {
            base: ExtensionLengthCircuit::new(ext_path[case.depth - 1].clone()),
            pi: &leaf_pi.to_vec(),
        };
        let ext_proof = prove_circuit(&setup_extension, &ext_circuit);
        */

        /*
        let ext_pi = PublicInputs::<GFp>::from_slice(&ext_proof.public_inputs);

        let pointer = GFp::from_canonical_u8(64);
        let root = keccak256(&extension);
        let root_hash: Vec<_> = convert_u8_to_u32_slice(&root)
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        let x = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| ext_pi.metadata().0[i]);
        let y = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| ext_pi.metadata().1[i]);
        let is_inf = ext_pi.metadata().2 == &GFp::ONE;
        let dm_p = WeierstrassPoint {
            x: GFp5::from_basefield_array(x),
            y: GFp5::from_basefield_array(y),
            is_inf,
        };

        let dm = map_to_curve_point(&[
            GFp::from_canonical_u8(slot),
            GFp::from_canonical_u8(variable_slot),
            GFp::from_bool(is_rlp_encoded),
        ]);

        assert_eq!(ext_pi.length(), &length);
        assert_eq!(ext_pi.root_hash(), root_hash);
        assert_eq!(dm.to_weierstrass(), dm_p);
        assert_eq!(ext_pi.mpt_key(), &key);
        assert_eq!(ext_pi.mpt_key_pointer(), &pointer);
        */

        /*


        let x = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| branch_pi.metadata().0[i]);
        let y = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| branch_pi.metadata().1[i]);
        let is_inf = branch_pi.metadata().2 == &GFp::ONE;
        let dm_p = WeierstrassPoint {
            x: GFp5::from_basefield_array(x),
            y: GFp5::from_basefield_array(y),
            is_inf,
        };

        let pointer = GFp::from_canonical_usize(61);
        let root: Vec<_> = convert_u8_to_u32_slice(&keccak256(&path[depth - 2]))
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        assert_eq!(branch_pi.length(), &length);
        assert_eq!(branch_pi.root_hash(), &root);
        assert_eq!(dm.to_weierstrass(), dm_p);
        assert_eq!(branch_pi.mpt_key(), &key);
        assert_eq!(branch_pi.mpt_key_pointer(), &pointer);
        */

        /*
        // Extension extraction
        // creates a dummy extension

        let PublicInputs { dm, k, t, n, .. } = leaf_pi;
        let ext_pi = PublicInputs {
            h: &extension_hash,
            dm,
            k,
            t,
            n,
        }
        .to_vec();
        let ext_circuit = ExtensionTestCircuit {
            base: ExtensionLengthCircuit::new(extension.clone()),
            pi: &ext_pi,
        };
        let ext_proof = prove_circuit(&setup_extension, &ext_circuit);
        let ext_pi = PublicInputs::<GFp>::from_slice(&ext_proof.public_inputs);

        let pointer = GFp::from_canonical_u8(64);
        let root = keccak256(&extension);
        let root_hash: Vec<_> = convert_u8_to_u32_slice(&root)
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        let x = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| ext_pi.metadata().0[i]);
        let y = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| ext_pi.metadata().1[i]);
        let is_inf = ext_pi.metadata().2 == &GFp::ONE;
        let dm_p = WeierstrassPoint {
            x: GFp5::from_basefield_array(x),
            y: GFp5::from_basefield_array(y),
            is_inf,
        };

        let dm = map_to_curve_point(&[
            GFp::from_canonical_u8(slot),
            GFp::from_canonical_u8(variable_slot),
            GFp::from_bool(is_rlp_encoded),
        ]);

        assert_eq!(ext_pi.length(), &length);
        assert_eq!(ext_pi.root_hash(), root_hash);
        assert_eq!(dm.to_weierstrass(), dm_p);
        assert_eq!(ext_pi.mpt_key(), &key);
        assert_eq!(ext_pi.mpt_key_pointer(), &pointer);
        */
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

#[derive(Debug, Clone)]
struct TreePath {
    pub slot: u8,
    pub key: Vec<GFp>,
    pub ext_key: Vec<GFp>,
    pub path: Vec<Vec<u8>>,
    pub ext_path: Vec<Vec<u8>>,
}

struct TestCase {
    pub seed: u64,
    pub depth: usize,
    pub is_rlp_encoded: bool,
    pub length: u32,
    pub ext_length: u32,
    pub variable_slot: u8,
}

impl TestCase {
    /// Insert random slots until the depth is of the desired size
    fn generate(&self) -> TreePath {
        let rng = &mut StdRng::seed_from_u64(self.seed);
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));
        let mut elements = Vec::new();

        let (slot, key, ext_key) = loop {
            let slot = rng.gen::<u8>();
            let storage_slot = StorageSlot::Simple(slot as usize);
            let key = storage_slot.mpt_key_vec();

            let value = rng.next_u32().to_be_bytes().to_vec();
            let value = if self.is_rlp_encoded {
                rlp::encode(&value).to_vec()
            } else {
                value
            };

            trie.insert(&key, &value).unwrap();
            trie.root_hash().unwrap();

            elements.push((slot, key));

            if let Some((slot, key)) = elements
                .iter()
                .find(|(_, key)| trie.get_proof(key).unwrap().len() == self.depth)
            {
                // cheap way to generate an extension node by modifying only the last key nibble
                let mut ext_key = key.clone();
                ext_key[31] = ext_key[31] ^ 0b10000000;

                let ext_value = self.ext_length.to_be_bytes().to_vec();
                let ext_value = if self.is_rlp_encoded {
                    rlp::encode(&ext_value).to_vec()
                } else {
                    ext_value
                };

                let value = self.length.to_be_bytes().to_vec();
                let value = if self.is_rlp_encoded {
                    rlp::encode(&value).to_vec()
                } else {
                    value
                };

                trie.insert(&key, &value).unwrap();
                trie.insert(&ext_key, &ext_value).unwrap();
                trie.root_hash().unwrap();

                break (*slot, key, ext_key);
            }
        };

        let path = trie.get_proof(key).unwrap();
        let nibbles = Nibbles::from_raw(&key, true);
        let key = nibbles
            .nibbles()
            .to_vec()
            .into_iter()
            .map(GFp::from_canonical_u8)
            .collect();

        //let ext_path = trie.get_proof(&ext_key).unwrap();
        let ext_path = vec![];
        let ext_nibbles = Nibbles::from_raw(&ext_key, true);
        let ext_key = ext_nibbles
            .nibbles()
            .to_vec()
            .into_iter()
            .map(GFp::from_canonical_u8)
            .collect();

        TreePath {
            slot,
            key,
            ext_key,
            path,
            ext_path,
        }
    }

    pub fn assert_correct_dm(&self, slot: u8, pi: &PublicInputs<GFp>) {
        let dm = map_to_curve_point(&[
            GFp::from_canonical_u8(slot),
            GFp::from_canonical_u8(self.variable_slot),
            GFp::from_bool(self.is_rlp_encoded),
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
