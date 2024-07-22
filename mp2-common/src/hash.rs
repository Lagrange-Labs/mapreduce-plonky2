use plonky2::{
    hash::hash_types::NUM_HASH_OUT_ELTS,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    poseidon::{H, P},
    D, F,
};

use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::plonk::config::AlgebraicHasher;

// maybe swap the first two elements and hashes the rest after with it
pub fn hash_maybe_first(
    c: &mut CircuitBuilder<F, D>,
    should_swap: BoolTarget,
    elem1: [Target; NUM_HASH_OUT_ELTS],
    elem2: [Target; NUM_HASH_OUT_ELTS],
    rest: &[Target],
) -> Vec<Target> {
    let zero = c.zero();
    let mut state = P::new(core::iter::repeat(zero));
    // absorb the first two inputs and do the swap
    state.set_from_slice(&[elem1, elem2].concat(), 0);
    state = H::permute_swapped(state, should_swap, c);
    // Absorb all the rest of the input chunks.
    let t = c._false();
    for input_chunk in rest.chunks(P::RATE) {
        state.set_from_slice(input_chunk, 0);
        state = H::permute_swapped(state, t, c);
    }

    // Squeeze until we have the desired number of outputs.
    let mut outputs = Vec::new();
    loop {
        for &item in state.squeeze() {
            outputs.push(item);
            if outputs.len() == NUM_HASH_OUT_ELTS {
                return outputs;
            }
        }
        state.permute();
    }
}

#[cfg(test)]
mod test {
    use crate::C;
    use plonky2::field::types::Sample;
    use plonky2::hash::hashing::hash_n_to_hash_no_pad;

    use plonky2::plonk::config::Hasher;
    use plonky2::{
        hash::hash_types::NUM_HASH_OUT_ELTS,
        iop::{
            target::{BoolTarget, Target},
            witness::WitnessWrite,
        },
        plonk::circuit_builder::CircuitBuilder,
    };

    use crate::{CHasher, D, F};
    use mp2_test::circuit::{run_circuit, UserCircuit};

    const REST: usize = 7;
    #[derive(Debug, Clone)]
    struct TestPartialSwap {
        elem1: Vec<F>,
        elem2: Vec<F>,
        should_swap: bool,
        rest: Vec<F>,
    }

    impl UserCircuit<F, D> for TestPartialSwap {
        type Wires = (Vec<Target>, Vec<Target>, BoolTarget, Vec<Target>);

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let elem1 = c.add_virtual_targets(NUM_HASH_OUT_ELTS);
            let elem2 = c.add_virtual_targets(NUM_HASH_OUT_ELTS);
            let cond = c.add_virtual_bool_target_safe();
            let rest = c.add_virtual_targets(REST);
            let hash = super::hash_maybe_first(
                c,
                cond,
                elem1.clone().try_into().unwrap(),
                elem2.clone().try_into().unwrap(),
                &rest,
            );
            c.register_public_inputs(&hash);
            (elem1, elem2, cond, rest)
        }

        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.0, &self.elem1);
            pw.set_target_arr(&wires.1, &self.elem2);
            pw.set_bool_target(wires.2, self.should_swap);
            pw.set_target_arr(&wires.3, &self.rest);
        }
    }

    #[test]
    fn test_partial_swap() {
        let elem1 = (0..NUM_HASH_OUT_ELTS)
            .map(|_| F::rand())
            .collect::<Vec<_>>();
        let elem2 = (0..NUM_HASH_OUT_ELTS)
            .map(|_| F::rand())
            .collect::<Vec<_>>();
        let rest = (0..REST).map(|_| F::rand()).collect::<Vec<_>>();
        for should_swap in [true, false] {
            let circuit = TestPartialSwap {
                elem1: elem1.clone(),
                elem2: elem2.clone(),
                should_swap,
                rest: rest.clone(),
            };
            let proof = run_circuit::<F, D, C, _>(circuit);
            let pi = proof.public_inputs;
            // do it outside circuit
            let tuple = match should_swap {
                false => [elem1.clone(), elem2.clone()].concat(),
                true => [elem2.clone(), elem1.clone()].concat(),
            };
            let inputs = tuple.iter().chain(rest.iter()).cloned().collect::<Vec<_>>();
            let hash = hash_n_to_hash_no_pad::<F, <CHasher as Hasher<F>>::Permutation>(&inputs);
            assert_eq!(&hash.elements.as_slice(), &pi.as_slice());
        }
    }
}
