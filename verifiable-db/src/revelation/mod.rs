//! Module including the revelation circuits for query

use mp2_common::F;

mod placeholders_check;
mod public_inputs;
mod revelation_without_results_tree;

pub use public_inputs::PublicInputs;

// L: maximum number of results
// S: maximum number of items in each result
// PH: maximum number of unique placeholder IDs and values bound for query
// Without this skipping config, the generic parameter was deleted when `cargo fmt`.
#[rustfmt::skip]
pub(crate) const PI_LEN<const L: usize, const S: usize, const PH: usize>: usize =
    PublicInputs::<F, L, S, PH>::total_len();

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::query::computational_hash_ids::PlaceholderIdentifier;
    use alloy::primitives::U256;
    use itertools::Itertools;
    use mp2_common::{
        array::ToField,
        poseidon::{empty_poseidon_hash, H},
        utils::ToFields,
    };
    use plonky2::{hash::hash_types::HashOut, plonk::config::Hasher};
    use rand::{thread_rng, Rng};
    use std::{array, iter::once};

    // Placeholders for testing
    // PH: maximum number of unique placeholder IDs and values bound for query
    // PP: maximum number of placeholders present in query (may be duplicate, PP >= PH)
    #[derive(Clone, Debug)]
    pub(crate) struct TestPlaceholders<const PH: usize, const PP: usize> {
        // Input arguments for `check_placeholders` function
        pub(crate) num_placeholders: usize,
        pub(crate) placeholder_ids: [F; PH],
        pub(crate) placeholder_values: [U256; PH],
        pub(crate) placeholder_pos: [usize; PP],
        pub(crate) placeholder_pairs: [(F, U256); PP],
        pub(crate) final_placeholder_hash: HashOut<F>,
        // Output result for `check_placeholders` function
        pub(crate) placeholder_ids_hash: HashOut<F>,
        // Expected data from query proof
        pub(crate) query_placeholder_hash: HashOut<F>,
        pub(crate) min_query: U256,
        pub(crate) max_query: U256,
    }

    impl<const PH: usize, const PP: usize> TestPlaceholders<PH, PP> {
        /// Create the testing placeholders. It has the similar logic as
        /// `check_placeholders` for building the testing data.
        pub(crate) fn sample(num_placeholders: usize) -> Self {
            let rng = &mut thread_rng();

            // Create an array of sample placeholder identifiers,
            // will set the first 4 to the query bounds as below.
            let mut placeholder_ids: [F; PH] =
                array::from_fn(|_| PlaceholderIdentifier::GenericPlaceholder(rng.gen()).to_field());
            let mut placeholder_values = array::from_fn(|_| U256::from_limbs(rng.gen()));
            let placeholder_pos = array::from_fn(|_| rng.gen_range(0..PH));
            let mut placeholder_pairs: [_; PP] =
                array::from_fn(|_| (rng.gen::<u32>().to_field(), U256::from_limbs(rng.gen())));

            // Set the first 4 placeholder identifiers as below constants.
            [
                PlaceholderIdentifier::MinQueryOnIdx1,
                PlaceholderIdentifier::MaxQueryOnIdx1,
                PlaceholderIdentifier::MinQueryOnIdx2,
                PlaceholderIdentifier::MaxQueryOnIdx2,
            ]
            .iter()
            .enumerate()
            .for_each(|(i, id)| placeholder_ids[i] = id.to_field());

            // Set the last invalid items found in placeholder_ids and
            // placeholder_values to placeholder_ids[0] and
            // placeholder_values[0] respectively.
            for i in num_placeholders..PH {
                placeholder_ids[i] = placeholder_ids[0];
                placeholder_values[i] = placeholder_values[0];
            }

            // Compute the hash of placeholder identifiers.
            let placeholder_ids_hash = placeholder_ids[0..num_placeholders].iter().fold(
                *empty_poseidon_hash(),
                |acc, id| {
                    let inputs = acc.to_fields().into_iter().chain(once(*id)).collect_vec();
                    H::hash_no_pad(&inputs)
                },
            );

            let mut placeholder_hash_payload = vec![];
            for i in 0..PP {
                // Set the entry of placeholder_pairs to
                // (placeholder_ids[placeholder_pos[i]], placeholder_values[placeholder_pos[i]]).
                let pos = placeholder_pos[i];
                let id = placeholder_ids[pos];
                let value = placeholder_values[pos];
                placeholder_pairs[i] = (id, value);

                // Accumulate the placeholder identifiers and values for computing the
                // placeholder hash.
                let mut payload = once(id).chain(value.to_fields()).collect_vec();
                placeholder_hash_payload.append(&mut payload);
            }

            // Re-compute the placeholder hash from placeholder_pairs and minmum,
            // maximum query bounds. Then check it should be same with the specified
            // final placeholder hash.
            let [min_i1, max_i1, min_i2, max_i2] = array::from_fn(|i| &placeholder_values[i]);
            let placeholder_hash = H::hash_no_pad(&placeholder_hash_payload);
            // query_placeholder_hash = H(placeholder_hash || min_i2 || max_i2)
            let inputs = placeholder_hash
                .to_fields()
                .into_iter()
                .chain(min_i2.to_fields())
                .chain(max_i2.to_fields())
                .collect_vec();
            let query_placeholder_hash = H::hash_no_pad(&inputs);
            // final_placeholder_hash = H(query_placeholder_hash || min_i1 || max_i1)
            let inputs = query_placeholder_hash
                .to_fields()
                .into_iter()
                .chain(min_i1.to_fields())
                .chain(max_i1.to_fields())
                .collect_vec();
            let final_placeholder_hash = H::hash_no_pad(&inputs);

            let [min_query, max_query] = [*min_i1, *max_i1];

            Self {
                num_placeholders,
                placeholder_ids,
                placeholder_values,
                placeholder_pos,
                placeholder_pairs,
                final_placeholder_hash,
                placeholder_ids_hash,
                query_placeholder_hash,
                min_query,
                max_query,
            }
        }
    }
}
