use crate::{
    circuit::{PCDCircuit, ProofOrDummyTarget, UserCircuit},
    utils::less_than,
};
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
        hashing::{hash_n_to_hash_no_pad, PlonkyPermutation},
        poseidon::{PoseidonHash, PoseidonPermutation, SPONGE_RATE},
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use std::iter;

#[derive(Clone, Debug)]
pub struct DigestWires<const ARITY: usize> {
    inputs: [Target; ARITY],
    real_len: Target,
    output: HashOutTarget,
}

#[derive(Clone, Debug)]
pub struct DigestCircuit<F, const D: usize, const ARITY: usize = { 64 }> {
    inputs: [F; ARITY],
    real_len: usize,
}

impl<F, const D: usize, const ARITY: usize> DigestCircuit<F, D, ARITY>
where
    F: RichField + Extendable<D>,
{
    pub fn new(mut inputs: Vec<F>) -> Self {
        let real_len = inputs.len();
        assert!(real_len <= ARITY);

        inputs.resize(ARITY, F::ZERO);
        let inputs = inputs.try_into().unwrap();

        Self { inputs, real_len }
    }
}

impl<F, const D: usize, const ARITY: usize> UserCircuit<F, D> for DigestCircuit<F, D, ARITY>
where
    F: RichField + Extendable<D>,
{
    type Wires = DigestWires<ARITY>;

    fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
        // This function code references `hash_n_to_m_no_pad` in plonky.
        // <https://github.com/nikkolasg/plonky2/blob/b53b079a2d6caabf317bc65aec2939aa5c72aaf0/plonky2/src/hash/hashing.rs#L30>

        let real_len = b.add_virtual_target();
        let inputs = b.add_virtual_target_arr::<ARITY>();

        // Initialize the poseison state to zeros.
        let zero = b.zero();
        let mut state =
            <PoseidonPermutation<Target> as PlonkyPermutation<Target>>::new(iter::repeat(zero));

        // Absorb all input chunks with a rate, and update the state.
        inputs
            .chunks(SPONGE_RATE)
            .enumerate()
            .for_each(|(i, chunks)| {
                let chunk_start = SPONGE_RATE * i;

                chunks.iter().enumerate().for_each(|(i, elt)| {
                    // Set the element to state if it's a real data by comparing
                    // with real length.
                    let elt_offset = b.constant(F::from_canonical_usize(chunk_start + i));
                    let is_elt = less_than(b, elt_offset, real_len, 8);

                    let elt = b.select(is_elt, *elt, state.as_ref()[i]);
                    state.set_elt(elt, i);
                });

                // Update to new state if the chunk start position (which is
                // `SPONGE_RATE * i`, and i starts from 0) is less than the real
                // data length. If so, the data of
                // `[chunk_start..chunk_start + SPONGE_RATE]` should be permuted
                // to the new state. The real data length must satisfies one of
                // the below conditions:
                // . real_len > chunk_start + SPONGE_RATE
                // . real_len > chunk_start && real_len <= chunk_start + SPONGE_RATE
                let new_state = b.permute::<PoseidonHash>(state);
                let chunk_start = b.constant(F::from_canonical_usize(chunk_start));
                let is_new_state = less_than(b, chunk_start, real_len, 8);

                let elts: Vec<_> = state
                    .as_ref()
                    .iter()
                    .zip(new_state.as_ref())
                    .map(|(elt, new_elt)| b.select(is_new_state, *new_elt, *elt))
                    .collect();

                elts.into_iter()
                    .enumerate()
                    .for_each(|(i, elt)| state.set_elt(elt, i));
            });

        // Squeeze outputs from the state.
        let mut outputs = Vec::with_capacity(NUM_HASH_OUT_ELTS);
        loop {
            for &s in state.squeeze() {
                outputs.push(s);
                if outputs.len() == NUM_HASH_OUT_ELTS {
                    let output = HashOutTarget::from_vec(outputs);

                    return Self::Wires {
                        inputs,
                        real_len,
                        output,
                    };
                }
            }
            state = b.permute::<PoseidonHash>(state);
        }
    }

    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.inputs, &self.inputs);
        pw.set_target(wires.real_len, F::from_canonical_usize(self.real_len));

        let output =
            hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&self.inputs[..self.real_len]);
        pw.set_hash_target(wires.output, output);
    }
}

impl<F, const D: usize, const ARITY: usize> PCDCircuit<F, D, ARITY> for DigestCircuit<F, D, ARITY>
where
    F: RichField + Extendable<D>,
{
    fn build_recursive(
        b: &mut CircuitBuilder<F, D>,
        _: &[ProofOrDummyTarget<D>; ARITY],
    ) -> Self::Wires {
        let wires = <Self as UserCircuit<F, D>>::build(b);
        b.register_public_inputs(&wires.output.elements);

        wires
    }

    fn base_inputs(&self) -> Vec<F> {
        F::rand_vec(NUM_HASH_OUT_ELTS)
    }

    fn num_io() -> usize {
        NUM_HASH_OUT_ELTS
    }
}
