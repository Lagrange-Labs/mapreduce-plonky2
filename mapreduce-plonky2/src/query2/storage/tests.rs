use std::{array, ops::Add};

use itertools::Itertools;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
        hashing::hash_n_to_hash_no_pad,
        poseidon::PoseidonPermutation,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{GenericConfig, GenericHashOut, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::{
    circuit::{test::run_circuit, UserCircuit},
    eth::left_pad32,
    group_hashing::map_to_curve_point,
    storage::lpn::{intermediate_node_hash, leaf_digest_for_mapping, leaf_hash_for_mapping},
};

use super::{
    full_inner::{FullInnerNodeCircuit, FullInnerNodeWires},
    leaf::LeafCircuit,
    partial_inner::{PartialInnerNodeCircuit, PartialInnerNodeWires},
    public_inputs::PublicInputs,
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

#[derive(Clone, Debug)]
struct PartialInnerNodeCircuitValidator<'a> {
    validated: PartialInnerNodeCircuit,

    proved_child: &'a PublicInputs<'a, F>,
    unproved_hash: Vec<F>,
    proved_is_left: F,
}
impl<'a> UserCircuit<GoldilocksField, 2> for PartialInnerNodeCircuitValidator<'a> {
    type Wires = (PartialInnerNodeWires, Vec<Target>, Vec<Target>, Target);

    fn build(c: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let leaf_child_pi = c.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
        let leaf_child_io = PublicInputs::from(leaf_child_pi.as_slice());
        let inner_child_hash_targets = c.add_virtual_targets(NUM_HASH_OUT_ELTS);
        let inner_child_position_target = c.add_virtual_target();

        let wires = PartialInnerNodeCircuit::build(
            c,
            &leaf_child_io,
            HashOutTarget::from_vec(inner_child_hash_targets.clone()),
            BoolTarget::new_unsafe(inner_child_position_target),
        );
        (
            wires,
            leaf_child_pi.try_into().unwrap(),
            inner_child_hash_targets,
            inner_child_position_target,
        )
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.1, self.proved_child.inputs);
        pw.set_target_arr(&wires.2, &self.unproved_hash);
        pw.set_target(wires.3, self.proved_is_left);
        self.validated.assign(pw, &wires.0);
    }
}

#[derive(Clone, Debug)]
struct FullInnerNodeCircuitValidator<'a> {
    validated: FullInnerNodeCircuit,
    children: &'a [PublicInputs<'a, F>; 2],
}
impl<'a> UserCircuit<GoldilocksField, 2> for FullInnerNodeCircuitValidator<'a> {
    type Wires = (FullInnerNodeWires, [Vec<Target>; 2]);

    fn build(c: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let child_inputs = [
            c.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN),
            c.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN),
        ];
        let children_io = std::array::from_fn(|i| PublicInputs::from(child_inputs[i].as_slice()));
        let wires = FullInnerNodeCircuit::build(c, children_io);
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

struct LeafProofResult {
    proof: ProofWithPublicInputs<F, C, D>,
    kv_gl: Vec<F>,
    owner_gl: Vec<F>,
}
impl LeafProofResult {
    fn io(&self) -> PublicInputs<F> {
        PublicInputs::from(self.proof.public_inputs.as_slice())
    }
}

fn run_leaf_proof<'data>(k: &[u8], v: &[u8]) -> LeafProofResult {
    let k = left_pad32(k);
    let v = left_pad32(v);

    let kv_gl = k
        .iter()
        .chain(v.iter())
        .copied()
        .map(F::from_canonical_u8)
        .collect_vec();

    let owner_gl = v.iter().copied().map(F::from_canonical_u8).collect_vec();

    let circuit = LeafCircuit { key: k, value: v };

    LeafProofResult {
        proof: run_circuit(circuit),
        kv_gl,
        owner_gl,
    }
}

fn test_leaf(k: &[u8], v: &[u8]) {
    let r = run_leaf_proof(k, v);

    // Check the generated root hash
    let exp_root = HashOut::from_bytes(&leaf_hash_for_mapping(k, v));
    assert_eq!(exp_root, r.io().root());

    // Check that the owner is correctly forwared
    assert_eq!(&r.owner_gl, r.io().owner());
}

#[test]
fn test_leaf_whatever() {
    test_leaf(b"deadbeef", b"0badf00d");
}

#[test]
fn test_leaf_all0() {
    test_leaf(b"", b"");
}

#[test]
fn test_leaf_0_nonzero() {
    test_leaf(b"", b"a278bf");
}

#[test]
fn test_leaf_nonzero_zero() {
    test_leaf(b"1235", b"00");
}

/// Builds & proves the following tree
///
/// Top-level - PartialInnerCircuit
/// ├── Middle sub-tree – FullInnerNodeCircuit
/// │   ├── LeafCircuit - K, V
/// │   └── LeafCircuit - K, V
/// └── Untouched sub-tree – hash == Poseidon("jean-michel")
fn test_mini_tree(k: &[u8], v: &[u8]) {
    let left = run_leaf_proof(k, v);
    let middle = run_leaf_proof(k, v);
    let (k1, v1) = (k, v);
    let (k2, v2) = (k, v);

    // Build the inner node circuit wrapper
    let inner = FullInnerNodeCircuitValidator {
        validated: FullInnerNodeCircuit {},
        children: &[
            PublicInputs::from(left.proof.public_inputs.as_slice()),
            PublicInputs::from(middle.proof.public_inputs.as_slice()),
        ],
    };
    let middle_proof = run_circuit::<F, D, C, _>(inner);
    let middle_ios = PublicInputs::<F>::from(middle_proof.public_inputs.as_slice());

    // Check the digest
    let expected_digest = leaf_digest_for_mapping(k1, v1)
        .add(leaf_digest_for_mapping(k2, v2))
        .to_weierstrass();
    let expected_other_digest = leaf_digest_for_mapping(k2, v2)
        .add(leaf_digest_for_mapping(k1, v1))
        .to_weierstrass();
    let found_digest = middle_ios.digest();
    assert_eq!(expected_digest, found_digest);
    // The digest must commute
    assert_eq!(expected_other_digest, found_digest);

    // Check the nested root hash
    let expected_hash = HashOut::from_bytes(&intermediate_node_hash(
        &leaf_hash_for_mapping(k1, v1),
        &leaf_hash_for_mapping(k2, v2),
    ));

    assert_eq!(expected_hash, middle_ios.root());

    // Check that the owner is correctly forwarded
    assert_eq!(left.owner_gl, middle_ios.owner());
    assert_eq!(middle.owner_gl, middle_ios.owner());

    let some_hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(
        &b"jean-michel"
            .iter()
            .copied()
            .map(F::from_canonical_u8)
            .collect_vec(),
    );

    let top = PartialInnerNodeCircuitValidator {
        validated: PartialInnerNodeCircuit {},
        proved_child: &middle_ios,
        unproved_hash: some_hash.to_vec(),
        proved_is_left: F::from_bool(true),
    };
    let top_proof = run_circuit::<F, D, C, _>(top);
    let top_ios = PublicInputs::<F>::from(top_proof.public_inputs.as_slice());

    // Mini tree root
    let expected_hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(
        some_hash
            .elements
            .iter()
            .copied()
            .chain(middle_ios.root().elements.iter().copied())
            .collect::<Vec<_>>()
            .as_slice(),
    );
    assert_eq!(expected_hash, top_ios.root());

    let wrong_hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(
        middle_ios
            .root()
            .elements
            .iter()
            .copied()
            .chain(some_hash.elements.iter().copied())
            .collect::<Vec<_>>()
            .as_slice(),
    );
    assert_ne!(wrong_hash, top_ios.root());

    // Check that the owner is correctly forwarded
    assert_eq!(left.owner_gl, top_ios.owner());
}

#[test]
fn test_inner_node() {
    test_mini_tree(b"012345", b"900600");
}

impl<'a, T: Copy + Default> PublicInputs<'a, T> {
    /// Writes the parts of the public inputs into the provided target array.
    pub fn parts_into_values(
        values: &mut [T; PublicInputs::<()>::TOTAL_LEN],
        root: &[T; PublicInputs::<()>::ROOT_LEN],
        digest: &[T; PublicInputs::<()>::DIGEST_LEN],
        owner: &[T; PublicInputs::<()>::OWNER_LEN],
    ) {
        values[Self::ROOT_OFFSET..Self::ROOT_OFFSET + Self::ROOT_LEN].copy_from_slice(root);
        values[Self::DIGEST_OFFSET..Self::DIGEST_OFFSET + Self::DIGEST_LEN].copy_from_slice(digest);
        values[Self::OWNER_OFFSET..Self::OWNER_OFFSET + Self::OWNER_LEN].copy_from_slice(owner);
    }
}

impl<'a, F: RichField> PublicInputs<'a, F> {
    pub fn values_from_seed(seed: u64) -> [F; PublicInputs::<()>::TOTAL_LEN] {
        let rng = &mut StdRng::seed_from_u64(seed);

        let root = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let digest = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let owner = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));

        let mut values = array::from_fn(|_| F::ZERO);
        Self::parts_into_values(&mut values, &root, &digest, &owner);

        values
    }
}
