//! Tests module for the leaf circuit

use std::array;

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::RichField, hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
    iop::witness::PartialWitness,
    plonk::{circuit_builder::CircuitBuilder, config::PoseidonGoldilocksConfig},
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::{
    circuit::{test::run_circuit, UserCircuit},
    state::{
        block_linking,
        lpn::{LeafWires, PublicInputs},
        BlockLinkingPublicInputs,
    },
};

use super::LeafCircuit;

#[test]
fn public_inputs_data_correspond_to_block_linking_pi_structure() {
    let target = block_linking_pi_from_seed(0xbeef);
    let block_linking = BlockLinkingPublicInputs::from_slice(&target);

    let mut target = [GoldilocksField::ZERO; PublicInputs::<()>::TOTAL_LEN];
    PublicInputs::block_linking_into_target(&mut target, &block_linking);
    let pi = PublicInputs::from_slice(&target);

    assert_eq!(pi.block_header_data(), block_linking.block_hash());
    assert_eq!(pi.block_number_data(), block_linking.s()[0]);
    assert_eq!(pi.prev_block_header_data(), block_linking.prev_block_hash());
}

#[test]
fn prove_and_verify_leaf_circuit() {
    let target = block_linking_pi_from_seed(0xdead);
    let block_linking = BlockLinkingPublicInputs::from_slice(&target);
    let circuit = TestLeafCircuit::from(block_linking.clone());

    let proof = run_circuit::<_, _, PoseidonGoldilocksConfig, _>(circuit);
    let pi = PublicInputs::from(proof.public_inputs.as_slice());

    assert_eq!(pi.block_header_data(), block_linking.block_hash());
    assert_eq!(pi.block_number_data(), block_linking.block_number()[0]);
    assert_eq!(pi.prev_block_header_data(), block_linking.prev_block_hash());
}

impl<'a, F: RichField> PublicInputs<'a, F> {
    /// Writes the parts of the block liking public inputs into the provided target array.
    pub fn block_linking_into_target<'b>(
        target: &mut [F; PublicInputs::<()>::TOTAL_LEN],
        pi: &'b BlockLinkingPublicInputs<'b, F>,
    ) {
        let len = 1 + pi.a().len() + pi.merkle_root().len() + pi.s().len() + pi.m().len();
        let mut node = Vec::with_capacity(len);
        node.push(F::ONE); // "LEAF"
        node.extend_from_slice(pi.a());
        node.extend_from_slice(pi.merkle_root());
        node.extend_from_slice(pi.s());
        node.extend_from_slice(pi.m());
        let root = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&node);

        target[Self::C_IDX..Self::C_IDX + Self::C_LEN].copy_from_slice(&root.elements);
        target[Self::H_IDX..Self::H_IDX + Self::H_LEN].copy_from_slice(pi.block_hash());
        target[Self::N_IDX..Self::N_IDX + Self::N_LEN].copy_from_slice(pi.s());
        target[Self::PREV_H_IDX..Self::PREV_H_IDX + Self::PREV_H_LEN]
            .copy_from_slice(pi.prev_block_hash());
    }
}

#[derive(Clone)]
struct TestLeafCircuit<'a> {
    c: LeafCircuit<'a, GoldilocksField>,
}

impl<'a> From<BlockLinkingPublicInputs<'a, GoldilocksField>> for TestLeafCircuit<'a> {
    fn from(block_linking: BlockLinkingPublicInputs<'a, GoldilocksField>) -> Self {
        Self {
            c: LeafCircuit { block_linking },
        }
    }
}

impl<'a, T: Clone> From<&'a [T]> for PublicInputs<'a, T> {
    fn from(proof_inputs: &'a [T]) -> Self {
        Self { proof_inputs }
    }
}

impl<'a> UserCircuit<GoldilocksField, 2> for TestLeafCircuit<'a> {
    type Wires = LeafWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        LeafCircuit::build(b)
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        self.c.assign(pw, wires);
    }
}

fn block_linking_pi_from_seed<F: RichField>(
    seed: u64,
) -> [F; BlockLinkingPublicInputs::<()>::TOTAL_LEN] {
    let rng = &mut StdRng::seed_from_u64(seed);

    let h = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
    let n = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
    let prev_h = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
    let a = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
    let d = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
    let m = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
    let s = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
    let c = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));

    let mut target = array::from_fn(|_| F::ZERO);
    BlockLinkingPublicInputs::parts_into_target(&mut target, &h, &n, &prev_h, &a, &d, &m, &s, &c);

    target
}
