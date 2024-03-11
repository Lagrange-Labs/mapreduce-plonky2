use plonky2::{
    field::types::Field,
    hash::{hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
    plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
};

use crate::{circuit::test::run_circuit, eth::left_pad32, group_hashing::map_to_curve_point};

use super::{
    leaf::{str_to_gl, LeafCircuit, LEAF_STR},
    PublicInputs,
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

#[test]
fn test_whatever() {
    test_kv("deadbeef", "0badf00d");
}

#[test]
fn test_all0() {
    test_kv("", "");
}

#[test]
fn test_0_nonzero() {
    test_kv("", "a278bf");
}

#[test]
fn test_nonzero_zero() {
    test_kv("1235", "00");
}

fn test_kv(k: &str, v: &str) {
    let key = left_pad32(hex::decode(k).unwrap().as_slice());

    let key_gl = key
        .iter()
        .map(|x| F::from_canonical_u8(*x))
        .collect::<Vec<_>>();

    let value = left_pad32(hex::decode(v).unwrap().as_slice());
    let value_gl = value
        .iter()
        .map(|x| F::from_canonical_u8(*x))
        .collect::<Vec<_>>();

    let circuit = LeafCircuit {
        key: key.try_into().unwrap(),
        value: value.try_into().unwrap(),
    };

    let proof = run_circuit::<F, D, C, _>(circuit);
    let pi = PublicInputs::<F>::from(proof.public_inputs.as_slice());

    {
        let exp_digest = map_to_curve_point(&value_gl).to_weierstrass();
        let found_digest = pi.digest();
        assert_eq!(exp_digest, found_digest);
    }

    {
        let to_hash = std::iter::once(*LEAF_STR.get_or_init(|| str_to_gl("LEAF")))
            .chain(key_gl.iter().copied())
            .chain(value_gl.iter().copied())
            .collect::<Vec<_>>();
        let exp_root = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(to_hash.as_slice());
        let found_root = pi.root();
        assert!(exp_root.elements.len() == found_root.len());
        assert!(exp_root
            .elements
            .iter()
            .zip(found_root.iter())
            .all(|xs| xs.0 == xs.1));
    }
}
