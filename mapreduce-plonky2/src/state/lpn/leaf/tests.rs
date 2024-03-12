//! Tests module for the leaf circuit

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::HashOutTarget, hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation,
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::PoseidonGoldilocksConfig},
};

use crate::{
    circuit::{test::run_circuit, UserCircuit},
    state::{
        lpn::leaf::{LeafWires, PublicInputs},
        BlockLinkingPublicInputs,
    },
};

use super::LeafCircuit;

#[test]
fn prove_and_verify_leaf_circuit() {
    let block_linking_values = BlockLinkingPublicInputs::values_from_seed(TestLeafCircuit::PI_SEED);
    let block_linking = BlockLinkingPublicInputs::from_slice(&block_linking_values);

    let preimage =
        LeafWires::node_preimage(GoldilocksField::ONE, &block_linking).collect::<Vec<_>>();
    let root = hash_n_to_hash_no_pad::<_, PoseidonPermutation<_>>(&preimage);

    let circuit = TestLeafCircuit {
        block_linking_values: block_linking_values.to_vec(),
        c: LeafCircuit,
    };
    let proof = run_circuit::<_, _, PoseidonGoldilocksConfig, _>(circuit);
    let pi = PublicInputs::from(proof.public_inputs.as_slice());

    assert_eq!(pi.root_data(), root.elements);
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
        let targets = b.add_virtual_targets(BlockLinkingPublicInputs::<()>::TOTAL_LEN);
        let block_linking = BlockLinkingPublicInputs::from_slice(&targets);
        let wires = LeafCircuit::build(b, block_linking);

        TestLeafWires {
            block_linking: targets.clone(),
            root: wires.root,
        }
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        let block_linking = BlockLinkingPublicInputs::from_slice(&wires.block_linking);

        self.block_linking_values
            .iter()
            .zip(block_linking.inner.iter())
            .for_each(|(&v, &t)| pw.set_target(t, v));

        let wires = LeafWires {
            block_linking: BlockLinkingPublicInputs::from_slice(&wires.block_linking),
            root: wires.root,
        };

        self.c.assign(pw, &wires);
    }
}
