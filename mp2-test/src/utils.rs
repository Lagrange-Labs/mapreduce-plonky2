use alloy::primitives::U256;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2_ecgfp5::curve::curve::{Point, WeierstrassPoint};
use rand::{
    distributions::{Distribution, Standard},
    thread_rng, Rng,
};

/// Generate a random vector.
pub fn random_vector<T>(size: usize) -> Vec<T>
where
    Standard: Distribution<T>,
{
    (0..size).map(|_| thread_rng().gen::<T>()).collect()
}

pub fn weierstrass_to_point(w: &WeierstrassPoint) -> Point {
    let p = Point::decode(w.encode()).expect("input weierstrass point invalid");
    assert_eq!(&p.to_weierstrass(), w);
    p
}

/// Generate a random Uint256.
pub fn gen_random_u256<R: Rng>(rng: &mut R) -> U256 {
    U256::from_limbs(rng.gen())
}

pub fn gen_random_field_hash<F: RichField>() -> HashOut<F> {
    HashOut::from(F::rand_array())
}
