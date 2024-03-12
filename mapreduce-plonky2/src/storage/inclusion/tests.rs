use std::ops::Add;

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuit::{test::run_circuit, UserCircuit},
    eth::left_pad32,
    group_hashing::map_to_curve_point,
    storage::inclusion::{LEAF_MARKER, NODE_MARKER},
};

use super::{
    inner_node::{NodeCircuit, NodeWires},
    leaf::LeafCircuit,
    PublicInputs,
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

#[derive(Clone)]
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
        (wires, child_inputs.try_into().unwrap())
    }

    fn prove(
        &self,
        pw: &mut plonky2::iop::witness::PartialWitness<GoldilocksField>,
        wires: &Self::Wires,
    ) {
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
    kv_gl: Vec<F>,
}
impl LeafProofResult {
    fn io(&self) -> PublicInputs<F> {
        PublicInputs::from(self.proof.public_inputs.as_slice())
    }
}

fn run_leaf_proof<'data>(k: &'_ str, v: &'_ str) -> LeafProofResult {
    let key = left_pad32(hex::decode(k).unwrap().as_slice());
    let key_gl = key
        .iter()
        .map(|x| F::from_canonical_u8(*x))
        .collect::<Vec<_>>();

    let value = left_pad32(hex::decode(v).unwrap().as_slice());
    let value_gl = value
        .iter()
        .map(|x| F::from_canonical_u8(*x))
        .collect::<Vec<_>>();

    let kv_gl = key_gl
        .iter()
        .copied()
        .chain(value_gl.iter().copied())
        .collect::<Vec<_>>();

    let circuit = LeafCircuit {
        key: key.try_into().unwrap(),
        value: value.try_into().unwrap(),
    };

    let proof = run_circuit::<F, D, C, _>(circuit);
    LeafProofResult { proof, kv_gl }
}

fn test_leaf(k: &str, v: &str) {
    let r = run_leaf_proof(k, v);

    // Check the digest
    let exp_digest = map_to_curve_point(&r.kv_gl).to_weierstrass();
    let found_digest = r.io().digest();
    assert_eq!(exp_digest, found_digest);

    // Check the root hash
    let to_hash = std::iter::once(LEAF_MARKER())
        .chain(r.kv_gl.iter().copied())
        .collect::<Vec<_>>();
    let exp_root = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(to_hash.as_slice());
    let found_root = r.io().root();
    assert_eq!(exp_root, found_root);
}

#[test]
fn test_inner_node() {
    test_mini_tree("012345", "900600", "dead", "beef");
}

fn test_mini_tree(k1: &str, v1: &str, k2: &str, v2: &str) {
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
    let expected_digest = map_to_curve_point(&left.kv_gl)
        .add(map_to_curve_point(&right.kv_gl))
        .to_weierstrass();
    let expected_other_digest = map_to_curve_point(&right.kv_gl)
        .add(map_to_curve_point(&left.kv_gl))
        .to_weierstrass();
    let found_digest = ios.digest();
    assert_eq!(expected_digest, found_digest);
    // The digest commutes
    assert_eq!(expected_other_digest, found_digest);

    // Check the nested root hash
    // Left child
    let to_hash_left = std::iter::once(LEAF_MARKER())
        .chain(left.kv_gl.iter().copied())
        .collect::<Vec<_>>();
    let hash_left = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(to_hash_left.as_slice());

    // Right child
    let to_hash_right = std::iter::once(LEAF_MARKER())
        .chain(right.kv_gl.iter().copied())
        .collect::<Vec<_>>();
    let hash_right = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(to_hash_right.as_slice());

    // Mini tree
    let to_hash = std::iter::once(NODE_MARKER())
        .chain(hash_left.elements.iter().copied())
        .chain(hash_right.elements.iter().copied())
        .collect::<Vec<_>>();
    let expected_hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(to_hash.as_slice());

    let found_hash = ios.root();
    assert_eq!(expected_hash, found_hash);

    // Hash is not commutative
    let to_wrongly_hash = std::iter::once(NODE_MARKER())
        .chain(hash_right.elements.iter().copied())
        .chain(hash_left.elements.iter().copied())
        .collect::<Vec<_>>();
    let wrong_hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(to_wrongly_hash.as_slice());
    assert_ne!(wrong_hash, found_hash);
}
