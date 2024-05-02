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
