use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    hash::{
        hash_types::{HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
        hashing::PlonkyPermutation,
        poseidon::PoseidonHash,
    },
    iop::target::{BoolTarget, Target},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

type H = PoseidonHash;
type P = <PoseidonHash as AlgebraicHasher<GoldilocksField>>::AlgebraicPermutation;

/// Hash the concatenation of the two provided 4-wide inputs, swapping them if specified.
pub fn hash_maybe_swap<F, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    inputs: &[[Target; NUM_HASH_OUT_ELTS]; 2],
    do_swap: BoolTarget,
) -> HashOutTarget
where
    F: RichField + Extendable<D>,
{
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

#[cfg(test)]
mod tests {
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::types::Field,
        hash::{hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::config::PoseidonGoldilocksConfig,
    };

    use super::*;

    #[test]
    fn hash_maybe_swap_is_equivalent_to_hash_n_false() {
        let a = [GoldilocksField::ZERO; NUM_HASH_OUT_ELTS];
        let b = [GoldilocksField::ONE; NUM_HASH_OUT_ELTS];

        let preimage: Vec<_> = a.iter().chain(b.iter()).copied().collect();
        let h = hash_n_to_hash_no_pad::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(
            preimage.as_slice(),
        );

        let circuit = TestHashSwapCircuit {
            a,
            b,
            do_swap: false,
        };
        let proof = run_circuit::<_, _, PoseidonGoldilocksConfig, _>(circuit);

        assert_eq!(&h.elements[..], proof.public_inputs.as_slice());
    }

    #[test]
    fn hash_maybe_swap_is_equivalent_to_hash_n_true() {
        let a = [GoldilocksField::ZERO; NUM_HASH_OUT_ELTS];
        let b = [GoldilocksField::ONE; NUM_HASH_OUT_ELTS];

        let preimage: Vec<_> = a.iter().chain(b.iter()).copied().collect();
        let h = hash_n_to_hash_no_pad::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(
            preimage.as_slice(),
        );

        let circuit = TestHashSwapCircuit {
            a: b,
            b: a,
            do_swap: true,
        };
        let proof = run_circuit::<_, _, PoseidonGoldilocksConfig, _>(circuit);

        assert_eq!(&h.elements[..], proof.public_inputs.as_slice());
    }

    #[derive(Clone)]
    struct TestHashSwapWires {
        pub a: HashOutTarget,
        pub b: HashOutTarget,
        pub do_swap: BoolTarget,
    }

    #[derive(Debug, Clone)]
    struct TestHashSwapCircuit {
        pub a: [GoldilocksField; NUM_HASH_OUT_ELTS],
        pub b: [GoldilocksField; NUM_HASH_OUT_ELTS],
        pub do_swap: bool,
    }

    impl UserCircuit<GoldilocksField, 2> for TestHashSwapCircuit {
        type Wires = TestHashSwapWires;

        fn build(cb: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
            let a = cb.add_virtual_hash();
            let b = cb.add_virtual_hash();
            let do_swap = cb.add_virtual_bool_target_safe();
            let h = hash_maybe_swap(cb, &[a.elements, b.elements], do_swap);

            cb.register_public_inputs(&h.elements);

            TestHashSwapWires { a, b, do_swap }
        }

        fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
            pw.set_target(
                wires.do_swap.target,
                GoldilocksField::from_bool(self.do_swap),
            );

            for i in 0..NUM_HASH_OUT_ELTS {
                pw.set_target(wires.a.elements[i], self.a[i]);
                pw.set_target(wires.b.elements[i], self.b[i]);
            }
        }

        fn name() -> &'static str {
            concat!(module_path!(), "::SwapHash::ignore")
        }
    }
}
