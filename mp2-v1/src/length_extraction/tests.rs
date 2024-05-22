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
        let tree = TestTree::generate(is_rlp_encoded, slot, length);
        let mut pointer = GFp::from_canonical_u64(63);
        let root = keccak256(&tree.node);
        let root_hash: Vec<_> = convert_u8_to_u32_slice(&root)
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();
        let mpt_key: Vec<_> = tree
            .key
            .iter()
            .copied()
            .map(GFp::from_canonical_u8)
            .collect();

        // Leaf extraction

        let leaf_circuit =
            LeafLengthCircuit::new(is_rlp_encoded, slot, &tree.node, variable_slot).unwrap();

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
        assert_eq!(leaf_pi.mpt_key(), &mpt_key);
        assert_eq!(leaf_pi.mpt_key_pointer(), &pointer);

        // Extension extraction

        let root = keccak256(&tree.extension);
        let root_hash: Vec<_> = convert_u8_to_u32_slice(&root)
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        let ext_circuit = ExtensionTestCircuit {
            base: ExtensionLengthCircuit::new(tree.extension),
            pi: &leaf_proof.public_inputs,
        };
        let ext_proof = prove_circuit(&setup_extension, &ext_circuit);
        let ext_pi = PublicInputs::<GFp>::from_slice(&ext_proof.public_inputs);

        let x = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| ext_pi.metadata().0[i]);
        let y = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| ext_pi.metadata().1[i]);
        let is_inf = ext_pi.metadata().2 == &GFp::ONE;
        let dm_p = WeierstrassPoint {
            x: GFp5::from_basefield_array(x),
            y: GFp5::from_basefield_array(y),
            is_inf,
        };

        assert_eq!(ext_pi.length(), &length);
        assert_eq!(ext_pi.root_hash(), root_hash);
        assert_eq!(dm.to_weierstrass(), dm_p);
        assert_eq!(ext_pi.mpt_key(), &mpt_key);
        assert_eq!(ext_pi.mpt_key_pointer(), &(pointer - GFp::ONE));

        // Branch extraction

        pointer = pointer - GFp::ONE;

        let root = keccak256(&tree.branch);
        let root_hash: Vec<_> = convert_u8_to_u32_slice(&root)
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        let branch_circuit = BranchTestCircuit {
            base: BranchLengthCircuit::<NODE_LEN>::new(&tree.branch).unwrap(),
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

        assert_eq!(branch_pi.length(), &length);
        assert_eq!(branch_pi.mpt_key(), &mpt_key);
        assert_eq!(branch_pi.mpt_key_pointer(), &pointer);
        assert_eq!(dm.to_weierstrass(), dm_p);
        assert_eq!(branch_pi.root_hash(), root_hash);
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
    pub is_rlp_encoded: bool,
    pub slot: u8,
    pub length: u32,
    pub variable_slot: u8,
}

struct TestTree {
    pub key: Vec<u8>,
    pub node: Vec<u8>,
    pub extension: Vec<u8>,
    pub branch: Vec<u8>,
}

impl TestTree {
    fn generate(is_rlp_encoded: bool, slot: u8, length: u32) -> Self {
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

        let nibbles = Nibbles::from_raw(&mpt_key, true);
        let leaf = Node::from_leaf(nibbles.clone(), encoded_value.clone());
        let key = nibbles.nibbles().to_vec();
        let extension = Node::from_extension(nibbles, leaf.clone());
        let branch = Node::from_branch(
            array::from_fn(|i| (i == 0).then(|| leaf.clone()).unwrap_or(Node::Empty)),
            None,
        );

        Self {
            key,
            node: trie.encode_raw(&leaf),
            extension: trie.encode_raw(&extension),
            branch: trie.encode_raw(&branch),
        }
    }
}
