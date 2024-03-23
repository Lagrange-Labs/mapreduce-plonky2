use std::ops::Add;

use crate::query2::provenance::tests::{run_provenance_circuit, run_provenance_circuit_with_slot};
use itertools::Itertools;
use plonky2::{
    field::{
        extension::{Extendable, Frobenius},
        goldilocks_field::GoldilocksField,
        types::Field,
    },
    hash::{
        hash_types::{HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
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
use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::{
    block::public_inputs::PublicInputs as BlockPublicInputs,
    circuit::{test::run_circuit, UserCircuit},
};

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
struct FullNodeCircuitValidator<const L: usize> {
    validated: FullNodeCircuit<F, L>,
}

impl<const L: usize> UserCircuit<GoldilocksField, D> for FullNodeCircuitValidator<L> {
    type Wires = FullNodeWires;

    fn build(c: &mut CircuitBuilder<GoldilocksField, D>) -> Self::Wires {
        FullNodeCircuit::<F, L>::build(c)
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        self.validated.assign(pw, wires);
    }
}

#[derive(Clone, Debug)]
struct PartialNodeCircuitValidator<'a, const L: usize> {
    validated: PartialNodeCircuit<L>,
    child_to_prove: AggregationPublicInputs<'a, F, L>,
    proven_child: Vec<F>,
    child_to_prove_is_left: F,
}
impl<const L: usize> UserCircuit<F, D> for PartialNodeCircuitValidator<'_, L> {
    type Wires = (PartialNodeWires, Vec<Target>, Vec<Target>, Target);

    fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
        let child_to_prove_pi =
            c.add_virtual_targets(AggregationPublicInputs::<Target, L>::total_len());
        let child_to_prove_io =
            AggregationPublicInputs::<Target, L>::from(child_to_prove_pi.as_slice());
        let proven_child_hash_targets = c.add_virtual_targets(NUM_HASH_OUT_ELTS);
        let child_to_prove_position_target = c.add_virtual_target();
        let wires = PartialNodeCircuit::<L>::build(
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
        pw.set_target_arr(&wires.1, self.child_to_prove.inputs);
        pw.set_target_arr(&wires.2, &self.proven_child);
        pw.set_target(wires.3, self.child_to_prove_is_left);
        self.validated.assign(pw, &wires.0);
    }
}

#[derive(Clone, Debug)]
struct RevelationCircuitValidator<const L: usize> {
    validated: RevelationCircuit<F, L>,
}
impl<const L: usize> UserCircuit<F, D> for RevelationCircuitValidator<L> {
    type Wires = RevelationWires;

    fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
        RevelationCircuit::<F, L>::build(c)
    }

    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        self.validated.assign(pw, wires);
    }
}

/// Builds & proves the following tree
///
/// Top-level - PartialInnerCircuit
/// ├── Middle sub-tree – FullInnerNodeCircuit
/// │   ├── LeafCircuit - // TODO: @victor
/// │   └── LeafCircuit - // TODO: @victor
/// └── Untouched sub-tree – hash == Poseidon("ernesto")
#[test]
fn test_mini_tree() {
    let EWORD_ZERO: EWord<F> = [0u32; 8]
        .into_iter()
        .map(F::from_canonical_u32)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    const L: usize = 4;
    // Need integration with leaf proof @Victor

    const SLOT_LENGTH: u32 = 9;
    const MAPPING_SLOT: u32 = 48372;
    let (left_value, left_leaf_proof_io) =
        run_provenance_circuit_with_slot::<L>(0xdead, SLOT_LENGTH, MAPPING_SLOT);
    let (right_value, right_leaf_proof_io) =
        run_provenance_circuit_with_slot::<L>(0xbeef, SLOT_LENGTH, MAPPING_SLOT);
    let values = [
        EWORD_ZERO.clone(),
        EWORD_ZERO.clone(),
        left_value,
        right_value,
    ];

    let left_leaf_pi = AggregationPublicInputs::<'_, F, L>::from(left_leaf_proof_io.as_slice());
    let right_leaf_pi = AggregationPublicInputs::<'_, F, L>::from(right_leaf_proof_io.as_slice());

    let middle_proof = run_circuit::<F, D, C, _>(FullNodeCircuitValidator {
        validated: FullNodeCircuit::<F, L> {
            children: [left_leaf_proof_io, right_leaf_proof_io],
        },
    });

    let proved = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(
        &b"ernesto"
            .iter()
            .copied()
            .map(F::from_canonical_u8)
            .collect_vec(),
    );

    let top_proof = run_circuit::<F, D, C, _>(PartialNodeCircuitValidator {
        validated: PartialNodeCircuit::<L> {},
        child_to_prove: AggregationPublicInputs::<F, L>::from(
            middle_proof.public_inputs.as_slice(),
        ),
        proven_child: proved.elements.to_vec(),
        child_to_prove_is_left: F::from_bool(false),
    });

    let rng = &mut StdRng::seed_from_u64(0x5eed);

    let root_proof =
        AggregationPublicInputs::<GoldilocksField, L>::from(top_proof.public_inputs.as_slice());

    let prev_root = std::iter::repeat_with(|| F::from_canonical_u32(25))
        .take(NUM_HASH_OUT_ELTS)
        .collect_vec();
    let new_root = root_proof.root().elements;
    let first_block = root_proof.block_number();
    let block_number = F::from_canonical_u8(34);
    let block_header = [
        F::from_canonical_u8(11),
        F::from_canonical_u8(12),
        F::from_canonical_u8(13),
        F::from_canonical_u8(14),
        F::from_canonical_u8(15),
        F::from_canonical_u8(16),
        F::from_canonical_u8(17),
        F::from_canonical_u8(18),
    ];

    let block_data: [F; BlockPublicInputs::<F>::TOTAL_LEN] = prev_root
        .into_iter()
        .chain(new_root.iter().copied())
        .chain(std::iter::once(first_block))
        .chain(std::iter::once(block_number))
        .chain(block_header.into_iter())
        .collect_vec()
        .try_into()
        .unwrap();
    let db_proof = BlockPublicInputs::<F>::from(block_data.as_slice());

    let final_proof = run_circuit::<F, D, C, _>(RevelationCircuitValidator {
        validated: RevelationCircuit {
            db_proof: db_proof.proof_inputs.to_owned(),
            root_proof: root_proof.inputs.to_owned(),
            ys: values,
            min_block_number: root_proof.block_number(),
            max_block_number: root_proof.block_number().add(root_proof.range()),
        },
    });
}
