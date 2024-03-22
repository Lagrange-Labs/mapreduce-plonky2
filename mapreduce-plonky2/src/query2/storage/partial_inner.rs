//! Mechanism for partially-recomputed inner node, i.e. only one child proof needs to be recomputed

use itertools::Itertools;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{
        hash_types::{HashOutTarget, NUM_HASH_OUT_ELTS},
        hashing::PlonkyPermutation,
        poseidon::PoseidonHash,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::PartialWitness,
    },
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use super::public_inputs::PublicInputs;
pub struct PartialInnerNodeWires {}

/// This circuit prove the root of the subtree made of:
///   - an child whose hash has not changes on the side defined by unproved_is_left
///   - another child whose hash has been updated.
#[derive(Clone, Debug)]
pub struct PartialInnerNodeCircuit {}

type H = PoseidonHash;
type P = <PoseidonHash as AlgebraicHasher<GoldilocksField>>::AlgebraicPermutation;

/// Hash the concatenation of the two provided 4-wide inputs, swapping them if specified.
fn hash_maybe_swap(
    b: &mut CircuitBuilder<GoldilocksField, 2>,
    inputs: &[[Target; NUM_HASH_OUT_ELTS]; 2],
    do_swap: BoolTarget,
) -> HashOutTarget {
    let zero = b.zero();

    let inputs = inputs.iter().flat_map(|i| i.iter()).copied().collect_vec();
    let mut state = P::new(core::iter::repeat(zero));
    for input_chunk in inputs.chunks(P::RATE) {
        state.set_from_slice(input_chunk, 0);
        state = H::permute_swapped(state, do_swap, b);
    }

    HashOutTarget {
        elements: {
            let mut outputs = Vec::with_capacity(NUM_HASH_OUT_ELTS);
            'aaa: loop {
                for &s in state.squeeze() {
                    outputs.push(s);
                    if outputs.len() == NUM_HASH_OUT_ELTS {
                        break 'aaa;
                    }
                }
                state = H::permute_swapped(state, do_swap, b);
            }
            outputs.try_into().unwrap()
        },
    }
}

impl PartialInnerNodeCircuit {
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        proved: &PublicInputs<Target>,
        unproved_hash: HashOutTarget,
        proved_is_right: BoolTarget,
    ) -> PartialInnerNodeWires {
        let root = hash_maybe_swap(
            b,
            &[proved.root().elements, unproved_hash.elements],
            proved_is_right,
        );
        PublicInputs::<GoldilocksField>::register(b, &root, &proved.digest(), &proved.owner());
        PartialInnerNodeWires {}
    }

    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &PartialInnerNodeWires) {}
}
