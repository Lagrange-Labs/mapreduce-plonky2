use mp2_common::F;
use public_inputs::PublicInputs;

pub(crate) mod intermediate_full_node;
pub(crate) mod intermediate_partial_node;
pub(crate) mod public_inputs;
pub(crate) mod record;

// Without this skipping config, the generic parameter was deleted when `cargo fmt`.
#[rustfmt::skip]
pub(crate) const PI_LEN<const S: usize>: usize = PublicInputs::<F, S>::total_len();

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloy::primitives::U256;
    use itertools::Itertools;
    use mp2_common::utils::ToFields;
    use mp2_test::utils::random_vector;
    use plonky2::field::types::{Field, Sample};
    use plonky2_ecgfp5::curve::curve::Point;
    use public_inputs::{PublicInputs, ResultsExtractionPublicInputs};
    use rand::{prelude::SliceRandom, thread_rng, Rng};
    use std::array;

    /// Generate N number of proof public input slices. The each returned proof public inputs
    /// could be constructed by `PublicInputs::from_slice` function.
    pub(crate) fn random_results_extraction_public_inputs<const N: usize, const S: usize>(
    ) -> [Vec<F>; N] {
        let mut rng = thread_rng();

        let index_ids: [F; 2] = F::rand_array();
        let [idx_ids_range, acc_range] = [
            ResultsExtractionPublicInputs::IndexIds,
            ResultsExtractionPublicInputs::Accumulator,
        ]
        .map(PublicInputs::<F, S>::to_range);

        array::from_fn(|_| {
            let mut pi = random_vector::<u32>(PI_LEN::<S>).to_fields();

            // Set the index IDs.
            pi[idx_ids_range.clone()].copy_from_slice(&index_ids);

            // Set a random point to Accumulator.
            let acc = Point::sample(&mut rng).to_weierstrass().to_fields();
            pi[acc_range.clone()].copy_from_slice(&acc);

            pi
        })
    }

    /// Assign the subtree proof to make consistent.
    pub(crate) fn unify_subtree_proof<const S: usize>(proof: &mut [F]) {
        let [min_cnt_range, max_cnt_range] = [
            ResultsExtractionPublicInputs::MinCounter,
            ResultsExtractionPublicInputs::MaxCounter,
        ]
        .map(PublicInputs::<F, S>::to_range);
    }

    /// Assign the child proof to make consistent.
}
