//! Tests module for the intermediate node circuit

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::PoseidonGoldilocksConfig},
};

use crate::{
    circuit::{test::run_circuit, UserCircuit},
    state::{lpn::node::NodeCircuit, LeafInputs},
};

#[test]
fn prove_and_verify_node_circuit() {
    let depth = 3;
    let mut left = LeafInputs::values_from_seed(0xbeef);
    let mut right = left;
    let mut node = LeafInputs::from_slice(&left).root_data().to_vec();

    let right_inputs = LeafInputs::from_slice(&right);
    let block_header = right_inputs.block_header_data().to_vec();
    let block_number = right_inputs.block_number_data();
    let prev_block_header = right_inputs.prev_block_header_data().to_vec();

    for d in 0..depth {
        let is_left_sibling = (d & 1) == 0;
        if is_left_sibling {
            LeafInputs::update_root_data_from_seed(&mut right, d);
            LeafInputs::update_root_data(&mut left, &node);
        } else {
            LeafInputs::update_root_data_from_seed(&mut left, d);
            LeafInputs::update_root_data(&mut right, &node);
        }

        let mut preimage = vec![GoldilocksField::ZERO];
        preimage.extend_from_slice(&LeafInputs::from_slice(&left).root_data());
        preimage.extend_from_slice(&LeafInputs::from_slice(&right).root_data());
        node = hash_n_to_hash_no_pad::<_, PoseidonPermutation<_>>(&preimage)
            .elements
            .to_vec();

        let circuit = TestNodeCircuit {
            left: left.to_vec(),
            right: right.to_vec(),
            c: NodeCircuit,
        };

        let proof = run_circuit::<_, _, PoseidonGoldilocksConfig, _>(circuit);
        let pi = LeafInputs::from_slice(proof.public_inputs.as_slice());

        assert_eq!(pi.root_data(), node);
        assert_eq!(pi.block_header_data(), &block_header);
        assert_eq!(pi.block_number_data(), block_number);
        assert_eq!(pi.prev_block_header_data(), &prev_block_header);
    }
}

#[derive(Clone)]
struct TestNodeWires {
    left: Vec<Target>,
    right: Vec<Target>,
}

#[derive(Clone)]
struct TestNodeCircuit {
    left: Vec<GoldilocksField>,
    right: Vec<GoldilocksField>,
    c: NodeCircuit,
}

impl UserCircuit<GoldilocksField, 2> for TestNodeCircuit {
    type Wires = TestNodeWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let left = b.add_virtual_targets(LeafInputs::<()>::TOTAL_LEN);
        let right = b.add_virtual_targets(LeafInputs::<()>::TOTAL_LEN);

        let left_sibling = LeafInputs::from_slice(&left);
        let right_sibling = LeafInputs::from_slice(&right);

        NodeCircuit::build(b, left_sibling, right_sibling);

        TestNodeWires { left, right }
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        self.left
            .iter()
            .zip(wires.left.iter())
            .for_each(|(&v, &t)| pw.set_target(t, v));

        self.right
            .iter()
            .zip(wires.right.iter())
            .for_each(|(&v, &t)| pw.set_target(t, v));
    }
}
