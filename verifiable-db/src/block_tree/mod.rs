//mod api;
mod leaf;
//mod membership;
//mod parent;
mod public_inputs;

//pub use api::{CircuitInput, PublicParameters};
use mp2_common::{poseidon::hash_to_int_target, CHasher, C, D, F};
use plonky2::{iop::target::Target, plonk::circuit_builder::CircuitBuilder};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;

use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget};
pub use public_inputs::PublicInputs;

/// Common function to compute the digest of the block tree which uses a special format using
/// scalar1 multiplication
pub(crate) fn compute_index_digest(
    b: &mut CircuitBuilder<F, D>,
    inputs: Vec<Target>,
    base: CurveTarget,
) -> CurveTarget {
    let hash = b.hash_n_to_hash_no_pad::<CHasher>(inputs);
    let int = hash_to_int_target(b, hash);
    let scalar = b.biguint_to_nonnative(&int);
    b.curve_scalar_mul(base, &scalar)
}

#[cfg(test)]
pub(crate) mod tests {
    use ethers::prelude::U256;
    use mp2_common::{keccak::PACKED_HASH_LEN, utils::ToFields, F};
    use mp2_test::utils::random_vector;
    use plonky2::{field::types::Sample, hash::hash_types::NUM_HASH_OUT_ELTS};
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{rngs::ThreadRng, Rng};

    use crate::row_tree;

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
        super::PublicInputs::new(
            &h_new,
            &h_old,
            &min,
            &max,
            &block_number,
            &block_hash,
            &prev_block_hash,
            &metadata_hash,
            &new_node_digest,
        )
        .to_vec()
    }

    /// Generate a random rows tree public inputs.
    pub(crate) fn random_rows_tree_pi(rng: &mut ThreadRng, row_digest: &[F]) -> Vec<F> {
        let h = random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields();
        let [min, max] = [0; 2].map(|_| U256(rng.gen::<[u64; 4]>()).to_fields());
        row_tree::PublicInputs::new(&h, row_digest, &min, &max).to_vec()
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
