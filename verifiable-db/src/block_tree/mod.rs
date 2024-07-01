mod api;
mod leaf;
mod membership;
mod parent;
mod public_inputs;

pub use api::{CircuitInput, PublicParameters};
pub use public_inputs::PublicInputs;

#[cfg(test)]
pub(crate) mod tests {
    use ethers::prelude::U256;
    use mp2_common::{keccak::PACKED_HASH_LEN, utils::ToFields, F};
    use mp2_test::utils::random_vector;
    use plonky2::{field::types::Sample, hash::hash_types::NUM_HASH_OUT_ELTS};
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{rngs::ThreadRng, Rng};

    /// Generate a random block index public inputs (of current module).
    pub(crate) fn random_block_index_pi(
        rng: &mut ThreadRng,
        min: U256,
        max: U256,
        block_number: U256,
    ) -> Vec<F> {
        let [h_new, h_old, metadata_hash] =
            [0; 3].map(|_| random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields());
        let [min, max, block_number] = [min, max, block_number].map(|u| u.to_fields());
        let [block_hash, prev_block_hash] =
            [0; 2].map(|_| random_vector::<u32>(PACKED_HASH_LEN).to_fields());
        let new_node_digest = Point::sample(rng).to_weierstrass().to_fields();

        h_new
            .into_iter()
            .chain(h_old)
            .chain(min)
            .chain(max)
            .chain(block_number)
            .chain(block_hash)
            .chain(prev_block_hash)
            .chain(metadata_hash)
            .chain(new_node_digest)
            .collect()
    }

    /// Generate a random rows tree public inputs.
    pub(crate) fn random_rows_tree_pi(rng: &mut ThreadRng, row_digest: &[F]) -> Vec<F> {
        let h = random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields();
        let [min, max] = [0; 2].map(|_| U256(rng.gen::<[u64; 4]>()).to_fields());

        h.into_iter()
            .chain(row_digest.iter().cloned())
            .chain(min)
            .chain(max)
            .collect()
    }

    /// Generate a random extraction public inputs.
    pub(crate) fn random_extraction_pi(
        rng: &mut ThreadRng,
        block_number: U256,
        value_digest: &[F],
    ) -> Vec<F> {
        let [h, ph] = [0; 2].map(|_| random_vector::<u32>(PACKED_HASH_LEN).to_fields());
        let dm = Point::sample(rng).to_weierstrass().to_fields();

        h.into_iter()
            .chain(ph)
            .chain(value_digest.iter().cloned())
            .chain(dm)
            .chain(block_number.to_fields())
            .collect()
    }
}
