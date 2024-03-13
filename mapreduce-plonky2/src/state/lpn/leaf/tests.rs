//! Tests module for the leaf circuit

use std::array;

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{HashOutTarget, RichField},
        hashing::hash_n_to_hash_no_pad,
        poseidon::PoseidonPermutation,
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::PoseidonGoldilocksConfig},
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::{
    circuit::{test::run_circuit, UserCircuit},
    state::{BlockLinkingInputs, LeafInputs},
};

use super::LeafCircuit;

#[test]
fn prove_and_verify_leaf_circuit() {
    let block_linking_values = BlockLinkingInputs::values_from_seed(TestLeafCircuit::PI_SEED);
    let block_linking = BlockLinkingInputs::from_slice(&block_linking_values);

    let preimage =
        LeafCircuit::node_preimage(GoldilocksField::ONE, &block_linking).collect::<Vec<_>>();
    let root = hash_n_to_hash_no_pad::<_, PoseidonPermutation<_>>(&preimage);

    let circuit = TestLeafCircuit {
        block_linking_values: block_linking_values.to_vec(),
        c: LeafCircuit,
    };
    let proof = run_circuit::<_, _, PoseidonGoldilocksConfig, _>(circuit);
    let pi = LeafInputs::from(proof.public_inputs.as_slice());

    assert_eq!(pi.root_data(), root.elements);
    assert_eq!(pi.block_header_data(), block_linking.block_hash());
    assert_eq!(pi.block_number_data(), block_linking.block_number()[0]);
    assert_eq!(pi.prev_block_header_data(), block_linking.prev_block_hash());
}

impl<'a, T: Clone> From<&'a [T]> for LeafInputs<'a, T> {
    fn from(proof_inputs: &'a [T]) -> Self {
        Self { proof_inputs }
    }
}

impl<'a, T: Copy + Default> LeafInputs<'a, T> {
    /// Writes the parts of the block liking public inputs into the provided target array.
    pub fn parts_into_values(
        values: &mut [T; LeafInputs::<()>::TOTAL_LEN],
        c: &[T; LeafInputs::<()>::C_LEN],
        h: &[T; LeafInputs::<()>::H_LEN],
        n: &[T; LeafInputs::<()>::N_LEN],
        prev_h: &[T; LeafInputs::<()>::PREV_H_LEN],
    ) {
        values[LeafInputs::<()>::C_IDX..LeafInputs::<()>::C_IDX + LeafInputs::<()>::C_LEN]
            .copy_from_slice(c);
        values[LeafInputs::<()>::H_IDX..LeafInputs::<()>::H_IDX + LeafInputs::<()>::H_LEN]
            .copy_from_slice(h);
        values[LeafInputs::<()>::N_IDX..LeafInputs::<()>::N_IDX + LeafInputs::<()>::N_LEN]
            .copy_from_slice(n);
        values[LeafInputs::<()>::PREV_H_IDX
            ..LeafInputs::<()>::PREV_H_IDX + LeafInputs::<()>::PREV_H_LEN]
            .copy_from_slice(prev_h);
    }

    pub fn update_root_data(values: &mut [T; LeafInputs::<()>::TOTAL_LEN], data: &[T]) {
        values[LeafInputs::<()>::C_IDX..LeafInputs::<()>::C_IDX + LeafInputs::<()>::C_LEN]
            .copy_from_slice(data);
    }
}

impl<'a, F: RichField> LeafInputs<'a, F> {
    pub fn values_from_seed(seed: u64) -> [F; LeafInputs::<()>::TOTAL_LEN] {
        let rng = &mut StdRng::seed_from_u64(seed);

        let c = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let h = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let n = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let prev_h = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));

        let mut values = array::from_fn(|_| F::ZERO);
        Self::parts_into_values(&mut values, &c, &h, &n, &prev_h);

        values
    }

    pub fn update_root_data_from_seed(values: &mut [F; LeafInputs::<()>::TOTAL_LEN], seed: u64) {
        let rng = &mut StdRng::seed_from_u64(seed);
        let c: [F; LeafInputs::<()>::C_LEN] =
            array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));

        Self::update_root_data(values, &c);
    }
}

#[derive(Clone)]
struct TestLeafWires {
    block_linking: Vec<Target>,
    root: HashOutTarget,
}

#[derive(Clone)]
struct TestLeafCircuit {
    block_linking_values: Vec<GoldilocksField>,
    c: LeafCircuit,
}

impl TestLeafCircuit {
    const PI_SEED: u64 = 0xbeef;
}

impl UserCircuit<GoldilocksField, 2> for TestLeafCircuit {
    type Wires = TestLeafWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let targets = b.add_virtual_targets(BlockLinkingInputs::<()>::TOTAL_LEN);
        let block_linking = BlockLinkingInputs::from_slice(&targets);
        let root = LeafCircuit::build(b, &block_linking);

        TestLeafWires {
            block_linking: targets.clone(),
            root,
        }
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        let block_linking = BlockLinkingInputs::from_slice(&wires.block_linking);

        self.block_linking_values
            .iter()
            .zip(block_linking.inner.iter())
            .for_each(|(&v, &t)| pw.set_target(t, v));
    }
}
