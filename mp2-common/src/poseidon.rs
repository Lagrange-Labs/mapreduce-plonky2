use crate::types::CBuilder;
use crate::F;
use num::BigUint;
use plonky2::field::types::PrimeField64;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
        hashing::PlonkyPermutation,
        poseidon::PoseidonHash,
    },
    iop::target::{BoolTarget, Target},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecdsa::gadgets::biguint::BigUintTarget;
use std::sync::OnceLock;

pub type H = PoseidonHash;
type P = <PoseidonHash as AlgebraicHasher<GoldilocksField>>::AlgebraicPermutation;

/// The static variable of Empty Poseidon hash
static EMPTY_POSEIDON_HASH: OnceLock<HashOut<GoldilocksField>> = OnceLock::new();

/// Get the static empty Poseidon hash.
pub fn empty_poseidon_hash() -> &'static HashOut<GoldilocksField> {
    EMPTY_POSEIDON_HASH.get_or_init(|| H::hash_no_pad(&[]))
}

/// Convert the hash target into a big integer target.
pub fn hash_to_int_target(b: &mut CBuilder, h: HashOutTarget) -> BigUintTarget {
    let limbs = h
        .elements
        .into_iter()
        .flat_map(|t| {
            // Split the hash element into low and high of Uint32. The `split_low_high`
            // function handles the range check in internal.
            let (low, high) = b.split_low_high(t, 32, 64);
            [low, high].map(U32Target)
        })
        .collect();

    BigUintTarget { limbs }
}

/// Convert the hash value into a big integer.
pub fn hash_to_int_value(h: HashOut<F>) -> BigUint {
    BigUint::from_slice(
        &h.elements
            .iter()
            .flat_map(|f| {
                let u = f.to_canonical_u64();
                [u & u32::MAX as u64, u >> 32].map(|u| u as u32)
            })
            .collect::<Vec<_>>(),
    )
}

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
    use crate::default_config;
    use crate::utils::ToFields;
    use crate::C;
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use mp2_test::utils::random_vector;
    use plonky2::{
        field::types::Field,
        hash::{hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::config::PoseidonGoldilocksConfig,
    };
    use plonky2_ecdsa::gadgets::biguint::CircuitBuilderBiguint;

    use super::*;

    #[test]
    fn test_hash_to_int() {
        // Generate the test hash.
        let hash = HashOut::from_vec(random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields());

        // Convert to an integer.
        let exp_int = hash_to_int_value(hash);

        let config = default_config();
        let mut b = CBuilder::new(config);

        // Convert the hash target to an integer target.
        let hash = b.constant_hash(hash);
        let int = hash_to_int_target(&mut b, hash);

        // Check if the integer is the expected one.
        let exp_int = b.constant_biguint(&exp_int);
        b.connect_biguint(&int, &exp_int);

        let cd = b.build::<C>();
        let mut pw = PartialWitness::new();
        cd.prove(pw).unwrap();
    }

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
    }
}
