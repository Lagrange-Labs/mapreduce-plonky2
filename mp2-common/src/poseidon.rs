use crate::types::CBuilder;
use crate::utils::ToFields;
use crate::utils::ToTargets;
use crate::C;
use crate::D;
use crate::F;
use itertools::Itertools;
use num::BigUint;
use plonky2::field::types::Field;
use plonky2::field::types::PrimeField64;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::config::GenericHashOut;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
        hashing::PlonkyPermutation,
    },
    iop::target::{BoolTarget, Target},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecdsa::gadgets::biguint::BigUintTarget;
use poseidon2_plonky2::poseidon2_hash::Poseidon2;
use std::sync::OnceLock;

pub trait HashableField: RichField + Poseidon2 {}

impl<T: RichField + Poseidon2> HashableField for T {}

pub type H = <C as GenericConfig<D>>::Hasher;
pub type P = <H as AlgebraicHasher<GoldilocksField>>::AlgebraicPermutation;
pub type HashPermutation = <H as Hasher<F>>::Permutation;

/// The result of hash to integer has 4 Uint32 (128 bits).
pub const HASH_TO_INT_LEN: usize = 4;

/// The flattened length of Poseidon hash, each original field is splitted from an
/// Uint64 into two Uint32.
pub const FLATTEN_POSEIDON_LEN: usize = NUM_HASH_OUT_ELTS * 2;

/// The static variable of Empty Poseidon hash
static EMPTY_POSEIDON_HASH: OnceLock<HashOut<GoldilocksField>> = OnceLock::new();

/// Get the static empty Poseidon hash.
pub fn empty_poseidon_hash() -> &'static HashOut<GoldilocksField> {
    EMPTY_POSEIDON_HASH.get_or_init(|| H::hash_no_pad(&[]))
}

/// Get the static empty Poseidon hash.
pub fn empty_poseidon_hash_as_vec() -> Vec<u8> {
    empty_poseidon_hash().to_bytes()
}

// Split the hash element into low and high of Uint32.
fn split_hash_element_to_low_high(b: &mut CBuilder, element: Target) -> [Target; 2] {
    let ttrue = b._true();
    let zero = b.zero();
    let p1 = b.constant(F::from_canonical_u32(u32::MAX));

    let (low, high) = b.split_low_high(element, 32, 64);
    let low_zero = b.is_equal(low, zero);
    let high_high = b.is_equal(high, p1);
    let not_high_high = b.not(high_high);
    let valid = b.or(low_zero, not_high_high);
    b.connect(valid.target, ttrue.target);

    [low, high]
}

/// Flatten the hash target to construct a big-endian Uint32 array.
pub fn flatten_poseidon_hash_target(
    b: &mut CBuilder,
    h: HashOutTarget,
) -> [Target; FLATTEN_POSEIDON_LEN] {
    h.to_targets()
        .into_iter()
        .flat_map(|t| {
            let [low, high] = split_hash_element_to_low_high(b, t);
            // Follow big-endian.
            [high, low]
        })
        .collect_vec()
        .try_into()
        .unwrap()
}

/// Flatten the hash value to construct a big-endian Uint32 array.
pub fn flatten_poseidon_hash_value(h: HashOut<F>) -> [F; FLATTEN_POSEIDON_LEN] {
    h.to_fields()
        .iter()
        .flat_map(|f| {
            let u = f.to_canonical_u64();
            // [high, low] for big-endian.
            [u >> 32, u & u32::MAX as u64].map(|u| F::from_canonical_u32(u as u32))
        })
        .collect_vec()
        .try_into()
        .unwrap()
}

/// Convert the hash target into a big integer target.
pub fn hash_to_int_target(b: &mut CBuilder, h: HashOutTarget) -> BigUintTarget {
    let limbs = h
        .to_targets()
        .into_iter()
        // reason to take 2 is because 128 bit  width scalar is enough
        // when it comes from a random oracle to do scalar mul
        .take(2)
        .flat_map(|t| split_hash_element_to_low_high(b, t).map(U32Target))
        .collect();

    BigUintTarget { limbs }
}

/// Convert the hash value into a big integer.
pub fn hash_to_int_value(h: HashOut<F>) -> BigUint {
    BigUint::from_slice(
        // We only consider two field elements to get a 128 bit witdth scalar
        // since this is sufficient for the purpose of scalar multiplication by
        // random vector , i.e. dlog is still secure at that level.
        &h.elements[0..2]
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
    F: HashableField + Extendable<D>,
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
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::field::types::Sample;
    use plonky2::{
        field::types::Field,
        hash::hashing::hash_n_to_hash_no_pad,
        iop::witness::{PartialWitness, WitnessWrite},
    };
    use plonky2_ecdsa::gadgets::biguint::CircuitBuilderBiguint;

    use super::*;

    #[test]
    fn test_poseidon_hash_flattening() {
        // Generate the test hash.
        let hash = HashOut::from(F::rand_array());

        // Flatten the hash values.
        let fields = flatten_poseidon_hash_value(hash);

        let config = default_config();
        let mut b = CBuilder::new(config);

        // Flatten the hash targets.
        let hash = b.constant_hash(hash);
        let targets = flatten_poseidon_hash_target(&mut b, hash);

        // Check if as expected.
        fields.into_iter().zip_eq(targets).for_each(|(f, t)| {
            let exp = b.constant(f);
            b.connect(t, exp);
        });

        let cd = b.build::<C>();
        let pw = PartialWitness::new();
        cd.prove(pw).unwrap();
    }

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
        let pw = PartialWitness::new();
        cd.prove(pw).unwrap();
    }

    #[test]
    fn hash_maybe_swap_is_equivalent_to_hash_n_false() {
        let a = [F::ZERO; NUM_HASH_OUT_ELTS];
        let b = [F::ONE; NUM_HASH_OUT_ELTS];

        let preimage: Vec<_> = a.iter().chain(b.iter()).copied().collect();
        let h = hash_n_to_hash_no_pad::<F, HashPermutation>(preimage.as_slice());

        let circuit = TestHashSwapCircuit {
            a,
            b,
            do_swap: false,
        };
        let proof = run_circuit::<_, _, C, _>(circuit);

        assert_eq!(&h.elements[..], proof.public_inputs.as_slice());
    }

    #[test]
    fn hash_maybe_swap_is_equivalent_to_hash_n_true() {
        let a = [F::ZERO; NUM_HASH_OUT_ELTS];
        let b = [F::ONE; NUM_HASH_OUT_ELTS];

        let preimage: Vec<_> = a.iter().chain(b.iter()).copied().collect();
        let h = hash_n_to_hash_no_pad::<F, HashPermutation>(preimage.as_slice());

        let circuit = TestHashSwapCircuit {
            a: b,
            b: a,
            do_swap: true,
        };
        let proof = run_circuit::<_, _, C, _>(circuit);

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
