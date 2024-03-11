//! Tests module for the leaf circuit

use std::array;

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::PoseidonGoldilocksConfig},
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::{
    circuit::{test::run_circuit, UserCircuit},
    state::{
        lpn::{LeafWires, PublicInputs},
        BlockLinkingPublicInputs,
    },
};

use super::LeafCircuit;

#[test]
fn prove_and_verify_leaf_circuit() {
    let block_linking = block_linking_pi_from_seed(TestLeafCircuit::PI_SEED).to_vec();
    let block_linking = BlockLinkingPublicInputs::from_slice(&block_linking);

    let circuit = TestLeafCircuit { c: LeafCircuit };
    let proof = run_circuit::<_, _, PoseidonGoldilocksConfig, _>(circuit);
    let pi = PublicInputs::from(proof.public_inputs.as_slice());

    assert_eq!(pi.block_header_data(), block_linking.block_hash());
    assert_eq!(pi.block_number_data(), block_linking.block_number()[0]);
    assert_eq!(pi.prev_block_header_data(), block_linking.prev_block_hash());
}

impl<'a, T: Clone> From<&'a [T]> for PublicInputs<'a, T> {
    fn from(proof_inputs: &'a [T]) -> Self {
        Self { proof_inputs }
    }
}

#[derive(Clone)]
struct TestLeafWires {
    block_linking_values: Vec<GoldilocksField>,
    block_linking: Vec<Target>,
    root: HashOutTarget,
}

#[derive(Clone)]
struct TestLeafCircuit {
    c: LeafCircuit,
}

impl TestLeafCircuit {
    const PI_SEED: u64 = 0xbeef;
}

impl UserCircuit<GoldilocksField, 2> for TestLeafCircuit {
    type Wires = TestLeafWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let targets = b.add_virtual_targets(BlockLinkingPublicInputs::<()>::TOTAL_LEN);

        let block_linking_values = block_linking_pi_from_seed(TestLeafCircuit::PI_SEED).to_vec();
        let block_linking = BlockLinkingPublicInputs::from_slice(&targets);
        let wires = LeafCircuit::build(b, block_linking);

        TestLeafWires {
            block_linking_values,
            block_linking: targets.clone(),
            root: wires.root,
        }
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        wires
            .block_linking
            .iter()
            .zip(wires.block_linking_values.iter())
            .for_each(|(t, v)| pw.set_target(*t, *v));

        let block_linking = BlockLinkingPublicInputs::from_slice(&wires.block_linking);
        let wires = LeafWires {
            block_linking,
            root: wires.root,
        };

        self.c.assign(pw, &wires).unwrap();
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
