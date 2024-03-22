//! Tests module for the intermediate node circuit

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::HashOut, hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{GenericHashOut, PoseidonGoldilocksConfig},
    },
};

use crate::{
    circuit::{test::run_circuit, UserCircuit},
    state::{
        lpn::{node::NodeCircuit, state_node_hash},
        StateInputs,
    },
};

#[test]
fn prove_and_verify_node_circuit() {
    let depth = 3;
    let mut left = StateInputs::values_from_seed(0xbeef);
    let mut right = left;
    let mut node = StateInputs::from_slice(&left).root_data().to_vec();

    let right_inputs = StateInputs::from_slice(&right);
    let block_header = right_inputs.block_header_data().to_vec();
    let block_number = right_inputs.block_number_data();
    let prev_block_header = right_inputs.prev_block_header_data().to_vec();

    for d in 0..depth {
        let is_left_sibling = (d & 1) == 0;
        if is_left_sibling {
            StateInputs::update_root_data_from_seed(&mut right, d);
            StateInputs::update_root_data(&mut left, &node);
        } else {
            StateInputs::update_root_data_from_seed(&mut left, d);
            StateInputs::update_root_data(&mut right, &node);
        }

        let mut preimage = vec![];
        preimage.extend_from_slice(StateInputs::from_slice(&left).root_data());
        preimage.extend_from_slice(StateInputs::from_slice(&right).root_data());
        node = hash_n_to_hash_no_pad::<_, PoseidonPermutation<_>>(&preimage)
            .elements
            .to_vec();

        let circuit = TestNodeCircuit {
            left: left.to_vec(),
            right: right.to_vec(),
            c: NodeCircuit,
        };

        let proof = run_circuit::<_, _, PoseidonGoldilocksConfig, _>(circuit);
        let pi = StateInputs::from_slice(proof.public_inputs.as_slice());

        assert_eq!(pi.root_data(), node);
        assert_eq!(pi.block_header_data(), &block_header);
        assert_eq!(pi.block_number_data(), block_number);
        assert_eq!(pi.prev_block_header_data(), &prev_block_header);

        let left_pi = StateInputs::from_slice(&left);
        let right_pi = StateInputs::from_slice(&right);
        let left_hash = HashOut::<GoldilocksField> {
            elements: left_pi.root_data().to_vec().try_into().unwrap(),
        }
        .to_bytes();
        let right_hash = HashOut::<GoldilocksField> {
            elements: right_pi.root_data().to_vec().try_into().unwrap(),
        }
        .to_bytes();
        let exp_root_hash = state_node_hash(
            left_hash.try_into().unwrap(),
            right_hash.try_into().unwrap(),
        )
        .to_vec();
        let computed_hash = HashOut::<GoldilocksField> {
            elements: pi.root_data().to_vec().try_into().unwrap(),
        }
        .to_bytes();
        assert_eq!(exp_root_hash, computed_hash);
    }
}

#[derive(Clone)]
struct TestNodeWires {
    left: Vec<Target>,
    right: Vec<Target>,
}

#[derive(Clone, Debug)]
struct TestNodeCircuit {
    left: Vec<GoldilocksField>,
    right: Vec<GoldilocksField>,
    c: NodeCircuit,
}

impl UserCircuit<GoldilocksField, 2> for TestNodeCircuit {
    type Wires = TestNodeWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let left = b.add_virtual_targets(StateInputs::<()>::TOTAL_LEN);
        let right = b.add_virtual_targets(StateInputs::<()>::TOTAL_LEN);

        let left_sibling = StateInputs::from_slice(&left);
        let right_sibling = StateInputs::from_slice(&right);

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
