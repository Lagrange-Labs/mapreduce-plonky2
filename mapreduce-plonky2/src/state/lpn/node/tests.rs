//! Tests module for the intermediate node circuit

use std::iter;

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
    state::{lpn::node::PublicInputs, BlockLinkingPublicInputs},
};

use super::NodeCircuit;

#[test]
fn prove_and_verify_node_circuit() {
    let block_linking_values = BlockLinkingPublicInputs::values_from_seed(TestNodeCircuit::PI_SEED);
    let block_linking = BlockLinkingPublicInputs::from_slice(&block_linking_values);
    let depth = 5;
    let mut node = TestNodeCircuit::leaf_hash_with_slot(&block_linking, depth);

    for d in 0..depth {
        let is_left_sibling = (d & 1) == 0;
        let values = TestNodeCircuit::leaf_hash_with_slot(&block_linking, d);

        let (left_values, right_values) = if is_left_sibling {
            (node.to_vec(), values.to_vec())
        } else {
            (values.to_vec(), node.to_vec())
        };

        let mut preimage = vec![GoldilocksField::ZERO];
        preimage.extend_from_slice(&left_values);
        preimage.extend_from_slice(&right_values);

        let root = hash_n_to_hash_no_pad::<_, PoseidonPermutation<_>>(&preimage);
        node.copy_from_slice(&root.elements);

        let circuit = TestNodeCircuit {
            block_linking_values: block_linking_values.to_vec(),
            left_values,
            right_values,
            c: NodeCircuit,
        };

        let proof = run_circuit::<_, _, PoseidonGoldilocksConfig, _>(circuit);
        let pi = PublicInputs::from(proof.public_inputs.as_slice());

        assert_eq!(pi.root_data(), node);
        assert_eq!(pi.block_header_data(), block_linking.block_hash());
        assert_eq!(pi.block_number_data(), block_linking.block_number()[0]);
        assert_eq!(pi.prev_block_header_data(), block_linking.prev_block_hash());
    }
}

impl<'a, T: Clone> From<&'a [T]> for PublicInputs<'a, T> {
    fn from(proof_inputs: &'a [T]) -> Self {
        Self { proof_inputs }
    }
}

#[derive(Clone)]
struct TestNodeWires {
    block_linking: Vec<Target>,
    left: HashOutTarget,
    right: HashOutTarget,
    root: HashOutTarget,
}

#[derive(Clone)]
struct TestNodeCircuit {
    block_linking_values: Vec<GoldilocksField>,
    left_values: Vec<GoldilocksField>,
    right_values: Vec<GoldilocksField>,
    c: NodeCircuit,
}

impl TestNodeCircuit {
    const PI_SEED: u64 = 0xbeef;

    fn leaf_hash_with_slot<'a>(
        block_linking: &'a BlockLinkingPublicInputs<'a, GoldilocksField>,
        slot: u32,
    ) -> Vec<GoldilocksField> {
        let preimage: Vec<_> = block_linking
            .a()
            .iter()
            .chain(block_linking.merkle_root().iter())
            .cloned()
            .chain(iter::once(block_linking.s()[0]))
            .chain(iter::once(GoldilocksField::from_canonical_u32(slot)))
            .collect();

        hash_n_to_hash_no_pad::<_, PoseidonPermutation<_>>(&preimage)
            .elements
            .to_vec()
    }
}

impl UserCircuit<GoldilocksField, 2> for TestNodeCircuit {
    type Wires = TestNodeWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let targets = b.add_virtual_targets(BlockLinkingPublicInputs::<()>::TOTAL_LEN);
        let block_linking = BlockLinkingPublicInputs::from_slice(&targets);

        let left = b.add_virtual_hash();
        let right = b.add_virtual_hash();

        let mut left_sibling = left.elements.to_vec();
        left_sibling.extend_from_slice(block_linking.block_hash());
        left_sibling.push(block_linking.block_number()[0]);
        left_sibling.extend_from_slice(block_linking.prev_block_hash());
        let left_sibling = PublicInputs::from_slice(&left_sibling);

        let mut right_sibling = right.elements.to_vec();
        right_sibling.extend_from_slice(block_linking.block_hash());
        right_sibling.push(block_linking.block_number()[0]);
        right_sibling.extend_from_slice(block_linking.prev_block_hash());
        let right_sibling = PublicInputs::from_slice(&right_sibling);

        let wires = NodeCircuit::build(b, block_linking, left_sibling, right_sibling);

        TestNodeWires {
            block_linking: targets.clone(),
            left,
            right,
            root: wires.root,
        }
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        let block_linking = BlockLinkingPublicInputs::from_slice(&wires.block_linking);

        self.block_linking_values
            .iter()
            .zip(block_linking.inner.iter())
            .for_each(|(&v, &t)| pw.set_target(t, v));

        self.left_values
            .iter()
            .zip(wires.left.elements.iter())
            .for_each(|(&v, &t)| pw.set_target(t, v));

        self.right_values
            .iter()
            .zip(wires.right.elements.iter())
            .for_each(|(&v, &t)| pw.set_target(t, v));
    }
}
