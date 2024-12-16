//! Module including the revelation circuits for query

use crate::ivc::NUM_IO;
use mp2_common::F;

pub mod api;
pub(crate) mod placeholders_check;
mod public_inputs;
mod revelation_unproven_offset;
mod revelation_without_results_tree;

pub use public_inputs::PublicInputs;
pub use revelation_unproven_offset::RowPath;

/// L: maximum number of results
/// S: maximum number of items in each result
/// PH: maximum number of unique placeholder IDs and values bound for query
pub const fn pi_len<const L: usize, const S: usize, const PH: usize>() -> usize {
    PublicInputs::<F, L, S, PH>::total_len()
}
pub const NUM_PREPROCESSING_IO: usize = NUM_IO;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::query::{
        computational_hash_ids::{AggregationOperation, PlaceholderIdentifier},
        universal_circuit::universal_query_gadget::OutputValues,
    };
    use alloy::primitives::U256;
    use itertools::Itertools;
    use mp2_common::{array::ToField, poseidon::H, utils::ToFields, F};
    use mp2_test::utils::gen_random_u256;
    use placeholders_check::{placeholder_ids_hash, CheckPlaceholderGadget, CheckedPlaceholder};
    use plonky2::{field::types::PrimeField64, hash::hash_types::HashOut, plonk::config::Hasher};
    use rand::{thread_rng, Rng};
    use std::{array, iter::once};

    // Placeholders for testing
    // PH: maximum number of unique placeholder IDs and values bound for query
    // PP: maximum number of placeholders present in query (may be duplicate, PP >= PH)
    #[derive(Clone, Debug)]
    pub(crate) struct TestPlaceholders<const PH: usize, const PP: usize> {
        // Input arguments for `check_placeholders` function
        pub(crate) check_placeholder_inputs: CheckPlaceholderGadget<PH, PP>,
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
            let mut placeholder_ids: [PlaceholderIdentifier; PH] =
                array::from_fn(|_| PlaceholderIdentifier::Generic(rng.gen()));
            let mut placeholder_values = array::from_fn(|_| U256::from_limbs(rng.gen()));

            // ensure that min_query <= max_query
            while placeholder_values[0] > placeholder_values[1] {
                placeholder_values[0] = gen_random_u256(rng);
                placeholder_values[1] = gen_random_u256(rng);
            }

            // Set the first 2 placeholder identifiers as below constants.
            [
                PlaceholderIdentifier::MinQueryOnIdx1,
                PlaceholderIdentifier::MaxQueryOnIdx1,
            ]
            .iter()
            .enumerate()
            .for_each(|(i, id)| placeholder_ids[i] = *id);

            // Compute the hash of placeholder identifiers.
            let placeholder_ids_hash =
                placeholder_ids_hash(placeholder_ids[..num_placeholders].to_vec());

            // Re-compute placeholder hash

            // Set the last invalid items found in placeholder_ids and
            // placeholder_values to placeholder_ids[0] and
            // placeholder_values[0] respectively.
            for i in num_placeholders..PH {
                placeholder_ids[i] = placeholder_ids[0];
                placeholder_values[i] = placeholder_values[0];
            }
            let placeholder_ids: [F; PH] = placeholder_ids
                .into_iter()
                .map(|id| id.to_field())
                .collect_vec()
                .try_into()
                .unwrap();

            let mut placeholder_hash_payload = vec![];
            let to_be_checked_placeholders = array::from_fn(|_| {
                let pos = rng.gen_range(0..PH);
                // Set the current `CheckedPlaceholder` to
                // (placeholder_ids[pos], placeholder_values[pos]).
                let id = placeholder_ids[pos];
                let value = placeholder_values[pos];

                // Accumulate the placeholder identifiers and values for computing the
                // placeholder hash.
                let mut payload = once(id).chain(value.to_fields()).collect_vec();
                placeholder_hash_payload.append(&mut payload);
                CheckedPlaceholder {
                    id,
                    value,
                    pos: pos.to_field(),
                }
            });

            let secondary_query_bound_placeholders = array::from_fn(|_| {
                let pos = rng.gen_range(0..PH);
                let id = placeholder_ids[pos];
                let value = placeholder_values[pos];

                CheckedPlaceholder {
                    id,
                    value,
                    pos: pos.to_field(),
                }
            });

            let check_placeholder_inputs = CheckPlaceholderGadget::<PH, PP> {
                num_placeholders,
                placeholder_ids,
                placeholder_values,
                to_be_checked_placeholders,
                secondary_query_bound_placeholders,
            };

            // Re-compute the placeholder hash from placeholder_pairs and minmum,
            // maximum query bounds. Then check it should be same with the specified
            // final placeholder hash.
            let (min_i1, max_i1) = check_placeholder_inputs.primary_query_bounds();
            let placeholder_hash = H::hash_no_pad(&placeholder_hash_payload);
            // query_placeholder_hash = H(placeholder_hash || min_i2 || max_i2)
            let inputs = placeholder_hash
                .to_fields()
                .into_iter()
                .chain(
                    secondary_query_bound_placeholders
                        .iter()
                        .flat_map(|placeholder| {
                            let mut placeholder_fes = vec![placeholder.id];
                            placeholder_fes.extend_from_slice(&placeholder.value.to_fields());
                            placeholder_fes
                        }),
                )
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

            let [min_query, max_query] = [min_i1, max_i1];

            Self {
                check_placeholder_inputs,
                final_placeholder_hash,
                placeholder_ids_hash,
                query_placeholder_hash,
                min_query,
                max_query,
            }
        }
    }

    /// Compute the query results from the query proof outputs, and it returns the results.
    pub(crate) fn compute_results_from_query_proof_outputs<const S: usize>(
        entry_count: F,
        output_values: OutputValues<S>,
        ops: &[F; S],
    ) -> [U256; S]
    where
        [(); S - 1]:,
    {
        // Convert the entry count to an Uint256.
        let entry_count = U256::from(entry_count.to_canonical_u64());

        let [op_avg, op_count] =
            [AggregationOperation::AvgOp, AggregationOperation::CountOp].map(|op| op.to_field());

        // Compute the results array, and deal with AVG and COUNT operations if any.
        array::from_fn(|i| {
            let value = output_values.value_at_index(i);

            let op = ops[i];
            if op == op_avg {
                value.checked_div(entry_count).unwrap_or(U256::ZERO)
            } else if op == op_count {
                entry_count
            } else {
                value
            }
        })
    }
}
