use std::ops::Add;

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::hash_types::HashOut,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{GenericConfig, GenericHashOut, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuit::{test::run_circuit, UserCircuit},
    eth::left_pad32,
    storage::lpn::{intermediate_node_hash, leaf_digest_for_mapping, leaf_hash_for_mapping},
};

use super::{
    inner_node::{NodeCircuit, NodeWires},
    leaf::LeafCircuit,
    PublicInputs,
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

#[derive(Clone, Debug)]
struct NodeCircuitValidator<'a> {
    validated: NodeCircuit,
    children: &'a [PublicInputs<'a, F>; 2],
}

impl UserCircuit<GoldilocksField, 2> for NodeCircuitValidator<'_> {
    type Wires = (NodeWires, [Vec<Target>; 2]);

    fn build(c: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let child_inputs = [
            c.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN),
            c.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN),
        ];
        let children_io = std::array::from_fn(|i| PublicInputs::from(child_inputs[i].as_slice()));
        let wires = NodeCircuit::build(c, children_io);
        (wires, child_inputs)
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.1[0], self.children[0].inputs);
        pw.set_target_arr(&wires.1[1], self.children[1].inputs);
        self.validated.assign(pw, &wires.0);
    }
}

#[test]
fn test_leaf_whatever() {
    test_leaf("deadbeef", "0badf00d");
}

#[test]
fn test_leaf_all0() {
    test_leaf("", "");
}

#[test]
fn test_leaf_0_nonzero() {
    test_leaf("", "a278bf");
}

#[test]
fn test_leaf_nonzero_zero() {
    test_leaf("1235", "00");
}

struct LeafProofResult {
    proof: ProofWithPublicInputs<F, C, D>,
}
impl LeafProofResult {
    fn io(&self) -> PublicInputs<F> {
        PublicInputs::from(self.proof.public_inputs.as_slice())
    }
}

fn run_leaf_proof(k: &[u8], v: &[u8]) -> LeafProofResult {
    let circuit = LeafCircuit {
        mapping_key: left_pad32(k),
        mapping_value: left_pad32(v),
    };

    let proof = run_circuit::<F, D, C, _>(circuit);
    LeafProofResult { proof }
}

fn test_leaf(ks: &'_ str, vs: &'_ str) {
    let (k, v) = (ks.as_bytes(), vs.as_bytes());
    let r = run_leaf_proof(k, v);

    // Check the digest
    let exp_digest = leaf_digest_for_mapping(k, v).to_weierstrass();
    let found_digest = r.io().digest();
    assert_eq!(exp_digest, found_digest);

    // Check the root hash
    let exp_root = HashOut::from_bytes(&leaf_hash_for_mapping(k, v));
    let found_root = r.io().root_hash();
    assert_eq!(exp_root, found_root);
}

#[test]
fn test_inner_node() {
    test_mini_tree("012345", "900600", "dead", "beef");
}

fn test_mini_tree(k1s: &'_ str, v1s: &'_ str, k2s: &'_ str, v2s: &'_ str) {
    let (k1, v1, k2, v2) = (
        k1s.as_bytes(),
        v1s.as_bytes(),
        k2s.as_bytes(),
        v2s.as_bytes(),
    );
    let left = run_leaf_proof(k1, v1);
    let right = run_leaf_proof(k2, v2);

    // Build the inner node circuit wrapper
    let circuit = NodeCircuitValidator {
        validated: NodeCircuit {},
        children: &[
            PublicInputs::from(left.proof.public_inputs.as_slice()),
            PublicInputs::from(right.proof.public_inputs.as_slice()),
        ],
    };
    let proof = run_circuit::<F, D, C, _>(circuit);
    let ios = PublicInputs::<F>::from(proof.public_inputs.as_slice());

    // Check the digest
    let expected_digest = leaf_digest_for_mapping(k1, v1)
        .add(leaf_digest_for_mapping(k2, v2))
        .to_weierstrass();
    let expected_other_digest = leaf_digest_for_mapping(k2, v2)
        .add(leaf_digest_for_mapping(k1, v1))
        .to_weierstrass();
    let found_digest = ios.digest();
    assert_eq!(expected_digest, found_digest);
    // The digest must commute
    assert_eq!(expected_other_digest, found_digest);

    // Check the nested root hash
    // Left child
    let hash_left = leaf_hash_for_mapping(k1, v1);
    let exp_left = PublicInputs::from(left.proof.public_inputs.as_slice()).root_hash();
    assert!(exp_left == HashOut::from_bytes(&hash_left));
    // Right child
    let hash_right = leaf_hash_for_mapping(k2, v2);
    let exp_right = PublicInputs::from(right.proof.public_inputs.as_slice()).root_hash();
    assert!(exp_right == HashOut::from_bytes(&hash_right));

    // Mini tree
    let expected_hash = HashOut::from_bytes(&intermediate_node_hash(&hash_left, &hash_right));
    let found_hash = ios.root_hash();
    assert_eq!(expected_hash, found_hash);

    // Hash is not commutative
    let wrong_hash = HashOut::from_bytes(&intermediate_node_hash(&hash_right, &hash_left));
    assert_ne!(wrong_hash, found_hash);
}
