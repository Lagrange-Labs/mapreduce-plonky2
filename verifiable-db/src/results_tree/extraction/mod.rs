use mp2_common::F;
use public_inputs::PublicInputs;

pub(crate) mod child_included_single_path_node;
pub(crate) mod full_node;
pub(crate) mod no_child_included_single_path_node;
pub(crate) mod no_results_in_chunk;
pub(crate) mod partial_node;
pub(crate) mod public_inputs;
pub(crate) mod record;

// Without this skipping config, the generic parameter was deleted when `cargo fmt`.
#[rustfmt::skip]
pub(crate) const PI_LEN: usize = PublicInputs::<F>::total_len();

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use mp2_common::utils::ToFields;
    use mp2_test::utils::random_vector;
    use plonky2::field::types::{Field, Sample};
    use plonky2_ecgfp5::curve::curve::Point;
    use public_inputs::{PublicInputs, ResultsExtractionPublicInputs};
    use rand::{thread_rng, Rng};
    use std::array;

    /// Generate N number of proof public input slices. The each returned proof public inputs
    /// could be constructed by `PublicInputs::from_slice` function.
    pub(crate) fn random_results_extraction_public_inputs<const N: usize>() -> [Vec<F>; N] {
        let mut rng = thread_rng();

        let index_ids: [F; 2] = F::rand_array();

        let [idx_ids_range, acc_range] = [
            ResultsExtractionPublicInputs::IndexIds,
            ResultsExtractionPublicInputs::Accumulator,
        ]
        .map(PublicInputs::<F>::to_range);

        array::from_fn(|_| {
            let mut pi = random_vector::<u32>(PI_LEN).to_fields();

            // Set the Index IDs.
            pi[idx_ids_range.clone()].copy_from_slice(&index_ids);

            // Set a random point to Accumulator.
            let acc = Point::sample(&mut rng).to_weierstrass().to_fields();
            pi[acc_range.clone()].copy_from_slice(&acc);

            pi
        })
    }

    /// Assign the subtree proof to make consistent.
    pub(crate) fn unify_subtree_proof(proof: &mut [F]) {
        // offset_range_min <= min_counter <= max_counter <= offset_range_max
        let mut rng = thread_rng();
        let min_counter = F::from_canonical_u32(rng.gen());
        let max_counter = min_counter + F::from_canonical_u32(100);
        let [min_cnt_range, max_cnt_range, offset_rng_min_range, offset_rng_max_range] = [
            ResultsExtractionPublicInputs::MinCounter,
            ResultsExtractionPublicInputs::MaxCounter,
            ResultsExtractionPublicInputs::OffsetRangeMin,
            ResultsExtractionPublicInputs::OffsetRangeMax,
        ]
        .map(PublicInputs::<F>::to_range);

        // Set the Min/Max counters.
        proof[min_cnt_range].copy_from_slice(&[min_counter]);
        proof[max_cnt_range].copy_from_slice(&[max_counter]);
        proof[offset_rng_min_range].copy_from_slice(&[min_counter]);
        proof[offset_rng_max_range].copy_from_slice(&[max_counter]);
    }

    /// Assign the child proof to make consistent.
    pub(crate) fn unify_child_proof(
        proof: &mut [F],
        is_rows_tree: bool,
        is_left_child: bool,
        subtree_pi: &PublicInputs<F>,
    ) {
        let [pri_idx_val_range, min_cnt_range, max_cnt_range, offset_rng_min_range, offset_rng_max_range] =
            [
                ResultsExtractionPublicInputs::PrimaryIndexValue,
                ResultsExtractionPublicInputs::MinCounter,
                ResultsExtractionPublicInputs::MaxCounter,
                ResultsExtractionPublicInputs::OffsetRangeMin,
                ResultsExtractionPublicInputs::OffsetRangeMax,
            ]
            .map(PublicInputs::<F>::to_range);

        if is_rows_tree {
            // pC.I == pR.I
            proof[pri_idx_val_range].copy_from_slice(subtree_pi.to_primary_index_value_raw());
        }

        if is_left_child {
            let left_min_counter = subtree_pi.min_counter() - F::ONE;

            // pC.max_counter = pR.min_counter - 1
            proof[max_cnt_range].copy_from_slice(&[left_min_counter]);

            // pC.offset_range_max < pR.min_counter
            proof[offset_rng_max_range].copy_from_slice(&[left_min_counter]);
        } else {
            let right_max_counter = subtree_pi.max_counter() + F::ONE;
            // pC.min_counter = pR.max_counter + 1
            proof[min_cnt_range].copy_from_slice(&[right_max_counter]);

            // pC.offset_range_min > pR.max_counter
            proof[offset_rng_min_range].copy_from_slice(&[right_max_counter]);
        }
    }
}
