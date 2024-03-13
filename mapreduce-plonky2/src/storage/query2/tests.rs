use itertools::Itertools;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{HashOutTarget, NUM_HASH_OUT_ELTS},
        hashing::hash_n_to_hash_no_pad,
        poseidon::PoseidonPermutation,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuit::{test::run_circuit, UserCircuit},
    eth::left_pad32,
    storage::LEAF_MARKER,
};

use super::{
    full_inner::{FullInnerNodeCircuit, FullInnerNodeWires},
    leaf::InclusionCircuit,
    partial_inner::{PartialInnerNodeCircuit, PartialInnerNodeWires},
    public_inputs::PublicInputs,
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

#[derive(Clone)]
struct PartialInnerNodeCircuitValidator<'a> {
    validated: PartialInnerNodeCircuit,

    leaf_child: &'a PublicInputs<'a, F>,
    inner_child_hash: Vec<F>,
    inner_child_position: F,
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
        pw.set_target_arr(&wires.1, self.leaf_child.inputs);
        pw.set_target_arr(&wires.2, &self.inner_child_hash);
        pw.set_target(wires.3, self.inner_child_position);
        self.validated.assign(pw, &wires.0);
    }
}

#[derive(Clone)]
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

fn run_leaf_proof<'data>(k: &'_ str, v: &'_ str) -> LeafProofResult {
    let key = left_pad32(hex::decode(k).unwrap().as_slice())
        .into_iter()
        .collect_vec();
    let value = left_pad32(hex::decode(v).unwrap().as_slice())
        .into_iter()
        .collect_vec();

    let kv_gl = key
        .iter()
        .copied()
        .chain(value.iter().copied())
        .map(F::from_canonical_u8)
        .collect_vec();

    let owner_gl = value
        .iter()
        .copied()
        .map(F::from_canonical_u8)
        .collect_vec();

    let circuit = InclusionCircuit {
        key: key.try_into().unwrap(),
        value: value.try_into().unwrap(),
    };

    LeafProofResult {
        proof: run_circuit(circuit),
        kv_gl,
        owner_gl,
    }
}

fn test_leaf(k: &str, v: &str) {
    let r = run_leaf_proof(k, v);

    // Check the generated root hash
    let to_hash = std::iter::once(LEAF_MARKER())
        .chain(r.kv_gl.iter().copied())
        .collect_vec();
    let exp_root = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(to_hash.as_slice());
    assert_eq!(exp_root, r.io().root());
    assert_eq!(r.owner_gl, r.io().owner());
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
