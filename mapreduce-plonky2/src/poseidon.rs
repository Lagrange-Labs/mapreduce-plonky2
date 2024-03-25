use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{
        hash_types::{HashOutTarget, NUM_HASH_OUT_ELTS},
        hashing::PlonkyPermutation,
        poseidon::PoseidonHash,
    },
    iop::target::{BoolTarget, Target},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

type H = PoseidonHash;
type P = <PoseidonHash as AlgebraicHasher<GoldilocksField>>::AlgebraicPermutation;

/// Hash the concatenation of the two provided 4-wide inputs, swapping them if specified.
pub(crate) fn hash_maybe_swap(
    b: &mut CircuitBuilder<GoldilocksField, 2>,
    inputs: &[[Target; NUM_HASH_OUT_ELTS]; 2],
    do_swap: BoolTarget,
) -> HashOutTarget {
    let zero = b.zero();

    let inputs = inputs
        .iter()
        .flat_map(|i| i.iter())
        .copied()
        .collect::<Vec<_>>();
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
