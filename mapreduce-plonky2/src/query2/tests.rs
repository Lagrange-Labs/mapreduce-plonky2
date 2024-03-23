use std::array::from_fn as create_array;

use crate::{
    circuit::test::run_circuit,
    eth::{left_pad, left_pad32},
    query2::state::tests::run_state_circuit,
    types::MAPPING_KEY_LEN,
};
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
    },
};

use crate::{block::public_inputs::PublicInputs as BlockPublicInputs, circuit::UserCircuit};

use super::{
    aggregation::{
        full_node::{FullNodeCircuit, FullNodeWires},
        partial_node::{PartialNodeCircuit, PartialNodeWires},
        AggregationPublicInputs,
    },
    revelation::{
        circuit::{RevelationCircuit, RevelationWires},
        RevelationPublicInputs,
    },
    EWord, EWordTarget, EWORD_LEN,
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

#[derive(Debug, Clone)]
struct FullNodeCircuitValidator<'a> {
    validated: FullNodeCircuit,
    children: &'a [AggregationPublicInputs<'a, F>; 2],
}

impl UserCircuit<GoldilocksField, D> for FullNodeCircuitValidator<'_> {
    type Wires = (FullNodeWires, [Vec<Target>; 2]);

    fn build(c: &mut CircuitBuilder<GoldilocksField, D>) -> Self::Wires {
        let child_inputs = [
            c.add_virtual_targets(AggregationPublicInputs::<Target>::total_len()),
            c.add_virtual_targets(AggregationPublicInputs::<Target>::total_len()),
        ];
        let children_io = std::array::from_fn(|i| {
            AggregationPublicInputs::<Target>::from(child_inputs[i].as_slice())
        });
        let wires = FullNodeCircuit::build(c, children_io);
        (wires, child_inputs)
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.1[0], self.children[0].inputs);
        pw.set_target_arr(&wires.1[1], self.children[1].inputs);
        self.validated.assign(pw, &wires.0);
    }
}

#[derive(Clone, Debug)]
struct PartialNodeCircuitValidator<'a> {
    validated: PartialNodeCircuit,
    child_proof: AggregationPublicInputs<'a, F>,
    // the hash of a sibling node in the tree that don't contain any results, i.e.
    // there is no proofs to verify for this children
    sibling_hash: Vec<F>,
    child_to_prove_is_left: F,
}
impl UserCircuit<F, D> for PartialNodeCircuitValidator<'_> {
    type Wires = (PartialNodeWires, Vec<Target>, Vec<Target>, Target);

    fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
        let child_to_prove_pi =
            c.add_virtual_targets(AggregationPublicInputs::<Target>::total_len());
        let child_to_prove_io =
            AggregationPublicInputs::<Target>::from(child_to_prove_pi.as_slice());
        let proven_child_hash_targets = c.add_virtual_targets(NUM_HASH_OUT_ELTS);
        let child_to_prove_position_target = c.add_virtual_target();
        let wires = PartialNodeCircuit::build(
            c,
            &child_to_prove_io,
            HashOutTarget::from_vec(proven_child_hash_targets.clone()),
            BoolTarget::new_unsafe(child_to_prove_position_target),
        );

        (
            wires,
            child_to_prove_pi.try_into().unwrap(),
            proven_child_hash_targets,
            child_to_prove_position_target,
        )
    }

    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.1, self.child_proof.inputs);
        pw.set_target_arr(&wires.2, &self.sibling_hash);
        pw.set_target(wires.3, self.child_to_prove_is_left);
        self.validated.assign(pw, &wires.0);
    }
}

#[derive(Clone, Debug)]
struct RevelationCircuitValidator<'a, const L: usize> {
    validated: RevelationCircuit<L>,
    db_proof: BlockPublicInputs<'a, F>,
    root_proof: AggregationPublicInputs<'a, F>,
}
impl<const L: usize> UserCircuit<F, D> for RevelationCircuitValidator<'_, L> {
    type Wires = (
        RevelationWires<L>,
        Vec<Target>,
        Vec<Target>,
        Vec<EWordTarget>,
    );

    fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
        let db_proof_io = c.add_virtual_targets(BlockPublicInputs::<Target>::TOTAL_LEN);
        let db_proof_pi = BlockPublicInputs::<Target>::from(db_proof_io.as_slice());

        let root_proof_io = c.add_virtual_targets(AggregationPublicInputs::<Target>::total_len());
        let root_proof_pi = AggregationPublicInputs::<Target>::from(root_proof_io.as_slice());

        let values = (0..L)
            .map(|_| c.add_virtual_target_arr::<EWORD_LEN>())
            .collect_vec();

        let wires = RevelationCircuit::<L>::build(c, db_proof_pi, root_proof_pi);
        (wires, db_proof_io, root_proof_io, values)
    }

    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.1, self.db_proof.proof_inputs);
        pw.set_target_arr(&wires.2, self.root_proof.inputs);
        self.validated.assign(pw, &wires.0);
    }
}

/// Builds & proves the following tree
///
/// Top-level - PartialInnerCircuit
/// ├── Middle sub-tree - FullInnerNodeCircuit
/// │   ├── LeafCircuit -
/// │   └── LeafCircuit -
/// └── Untouched sub-tree - hash == Poseidon("ernesto")
fn test_mini_tree() {
    const L: usize = 4;
    let num_entries = 2;
    let values: [u32; 4] = [0, 0, 0xdead, 0xbeef];

    let left_leaf_proof_io = run_state_circuit(0xdead);
    let right_leaf_proof_io = run_state_circuit(0xbeef);

    let left_leaf_pi = AggregationPublicInputs::<'_, F>::from(left_leaf_proof_io.as_slice());
    let right_leaf_pi = AggregationPublicInputs::<'_, F>::from(right_leaf_proof_io.as_slice());

    let middle_proof = run_circuit::<F, D, C, _>(FullNodeCircuitValidator {
        validated: FullNodeCircuit {},
        children: &[left_leaf_pi, right_leaf_pi],
    });

    let proved = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(
        &b"ernesto"
            .iter()
            .copied()
            .map(F::from_canonical_u8)
            .collect_vec(),
    );

    let top_proof = run_circuit::<F, D, C, _>(PartialNodeCircuitValidator {
        validated: PartialNodeCircuit {},
        child_proof: AggregationPublicInputs::<F>::from(middle_proof.public_inputs.as_slice()),
        sibling_hash: proved.elements.to_vec(),
        child_to_prove_is_left: F::from_bool(false),
    });
    let revelation_circuit = RevelationCircuit::<L> {
        raw_keys: create_array(|i| left_pad::<MAPPING_KEY_LEN>(&values[i].to_be_bytes())),
        num_entries,
    };
    let root_pi =
        AggregationPublicInputs::<GoldilocksField>::from(top_proof.public_inputs.as_slice());

    let final_proof = run_circuit::<F, D, C, _>(RevelationCircuitValidator {
        validated: revelation_circuit,
        db_proof: todo!(),
        root_proof: root_pi,
    });
}
