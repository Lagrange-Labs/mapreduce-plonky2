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
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

use super::{
    BranchLengthCircuit, BranchLengthWires, ExtensionLengthCircuit, ExtensionLengthWires,
    LeafLengthCircuit, LeafLengthWires, PublicInputs,
};

const NODE_LEN: usize = 500;

#[test]
fn prove_and_verify_length_extraction_circuit() {
    let setup_leaf = setup_circuit::<_, D, PoseidonGoldilocksConfig, LeafLengthCircuit<NODE_LEN>>();
    let setup_extension = setup_circuit::<_, D, PoseidonGoldilocksConfig, ExtensionTestCircuit>();
    let setup_branch = setup_circuit::<_, D, PoseidonGoldilocksConfig, BranchTestCircuit>();
    let mut cases = vec![];

    // max u32 shouldn't overflow
    cases.push(TestCase {
        seed: 0xdead,
        depth: 4,
        is_rlp_encoded: true,
        length: u32::MAX,
        variable_slot: 0xfa,
    });

    // encoded RLP low value should decode
    cases.push(TestCase {
        seed: 0xdead,
        depth: 4,
        is_rlp_encoded: true,
        length: 15,
        variable_slot: 0xfa,
    });

    // raw value should decode
    cases.push(TestCase {
        seed: 0xdead,
        depth: 4,
        is_rlp_encoded: false,
        length: 8943278,
        variable_slot: 0xfa,
    });

    for TestCase {
        seed,
        depth,
        is_rlp_encoded,
        length,
        variable_slot,
    } in cases
    {
        let TreePath {
            slot,
            key,
            extension,
            extension_hash,
            path,
        } = TreePath::generate(seed, depth, length, is_rlp_encoded);

        // Leaf extraction
        // open the length over the MPT

        let leaf_circuit =
            LeafLengthCircuit::new(is_rlp_encoded, slot, &path[depth - 1], variable_slot).unwrap();

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

        let pointer = GFp::from_canonical_u8(62);
        let root: Vec<_> = convert_u8_to_u32_slice(&keccak256(&path[depth - 1]))
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        assert_eq!(leaf_pi.length(), &length);
        assert_eq!(leaf_pi.root_hash(), &root);
        assert_eq!(dm.to_weierstrass(), dm_p);
        assert_eq!(leaf_pi.mpt_key(), &key);
        assert_eq!(leaf_pi.mpt_key_pointer(), &pointer);

        // Branch extraction
        // traverse one level of the tree and expect `T` to be updated

        let branch_circuit = BranchTestCircuit {
            base: BranchLengthCircuit::<NODE_LEN>::new(&path[depth - 2]).unwrap(),
            pi: &leaf_proof.public_inputs,
        };

        let branch_proof = prove_circuit(&setup_branch, &branch_circuit);
        let branch_pi = PublicInputs::<GFp>::from_slice(&branch_proof.public_inputs);

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
    pub depth: usize,
    pub is_rlp_encoded: bool,
    pub length: u32,
    pub variable_slot: u8,
}

#[derive(Debug, Clone)]
struct TreePath {
    pub slot: u8,
    pub key: Vec<GFp>,
    pub extension: Vec<u8>,
    pub extension_hash: Vec<GFp>,
    pub path: Vec<Vec<u8>>,
}

impl TreePath {
    /// Insert random slots until the depth is of the desired size
    fn generate(seed: u64, depth: usize, length: u32, is_rlp_encoded: bool) -> Self {
        let rng = &mut StdRng::seed_from_u64(seed);
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));
        let mut elements = Vec::new();

        let (slot, key) = loop {
            // Generate a MPT key from the slot and contract address.
            let slot = rng.gen::<u8>();
            let storage_slot = StorageSlot::Simple(slot as usize);
            let key = storage_slot.mpt_key_vec();

            let value = rng.next_u32().to_be_bytes().to_vec();
            let value = if is_rlp_encoded {
                rlp::encode(&value).to_vec()
            } else {
                value
            };

            trie.insert(&key, &value).unwrap();
            trie.root_hash().unwrap();

            elements.push((slot, key));

            if let Some((slot, key)) = elements
                .iter()
                .find(|(_, key)| trie.get_proof(key).unwrap().len() == depth)
            {
                break (*slot, key);
            }
        };

        let value = length.to_be_bytes().to_vec();
        let value = if is_rlp_encoded {
            rlp::encode(&value).to_vec()
        } else {
            value
        };

        trie.insert(&key, &value).unwrap();
        trie.root_hash().unwrap();

        let path = trie.get_proof(key).unwrap();
        let nibbles = Nibbles::from_raw(&key, true);
        let key = nibbles
            .nibbles()
            .to_vec()
            .into_iter()
            .map(GFp::from_canonical_u8)
            .collect();

        let extension_slot = StorageSlot::Simple(slot as usize);
        let extension_key = extension_slot.mpt_key_vec();
        let extension_nibbles = Nibbles::from_raw(&extension_key, true);
        let extension_leaf = Node::from_leaf(extension_nibbles.clone(), value);
        let extension_hash = trie.encode_raw(&extension_leaf);
        let extension = Node::from_extension(extension_nibbles, extension_leaf);
        let extension = trie.encode_raw(&extension);
        let extension_hash = convert_u8_to_u32_slice(&keccak256(&extension_hash))
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        Self {
            slot,
            key,
            extension,
            extension_hash,
            path,
        }
    }
}
