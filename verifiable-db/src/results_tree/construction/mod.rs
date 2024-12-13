pub(crate) mod leaf_node;
pub(crate) mod node_with_one_child;
pub(crate) mod node_with_two_children;
pub(crate) mod public_inputs;
pub(crate) mod results_tree_with_duplicates;
pub(crate) mod results_tree_without_duplicates;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloy::primitives::U256;
    use itertools::Itertools;
    use mp2_common::{utils::ToFields, F};
    use mp2_test::utils::random_vector;
    use plonky2::field::types::{Field, Sample};
    use plonky2_ecgfp5::curve::curve::Point;
    use public_inputs::{PublicInputs, ResultsConstructionPublicInputs};
    use rand::{prelude::SliceRandom, thread_rng, Rng};
    use std::array;

    /// Constant function that returns the length of [`PublicInputs`] based on
    /// some constant value [`S`].
    pub(crate) const fn pi_len<const S: usize>() -> usize {
        public_inputs::PublicInputs::<F, S>::total_len()
    }

    /// Generate S number of proof public input slices. The each returned proof public inputs
    /// could be constructed by `PublicInputs::from_slice` function.
    pub(crate) fn random_results_construction_public_inputs<const N: usize, const S: usize>(
    ) -> [Vec<F>; N] {
        let mut rng = thread_rng();

        // The no duplicates flags and index IDs are same for a series of proofs.
        let no_dup_flag = F::from_bool(rng.gen());

        let index_ids: [F; 2] = F::rand_array();
        let [no_dup_range, idx_ids_range, acc_range] = [
            ResultsConstructionPublicInputs::NoDuplicates,
            ResultsConstructionPublicInputs::IndexIds,
            ResultsConstructionPublicInputs::Accumulator,
        ]
        .map(PublicInputs::<F, S>::to_range);

        array::from_fn(|_| {
            let mut pi = random_vector::<u32>(pi_len::<S>()).to_fields();

            // Set no duplicates flag.
            pi[no_dup_range.clone()].copy_from_slice(&[no_dup_flag]);

            // Set the index IDs.
            pi[idx_ids_range.clone()].copy_from_slice(&index_ids);

            // Set a random point to Accumulator.
            let acc = Point::sample(&mut rng).to_weierstrass().to_fields();
            pi[acc_range.clone()].copy_from_slice(&acc);

            pi
        })
    }

    /// Assign the subtree proof to make consistent.
    pub(crate) fn unify_subtree_proof<const S: usize>(proof: &mut [F], is_rows_tree_node: bool) {
        let [min_cnt_range, max_cnt_range] = [
            ResultsConstructionPublicInputs::MinCounter,
            ResultsConstructionPublicInputs::MaxCounter,
        ]
        .map(PublicInputs::<F, S>::to_range);

        if is_rows_tree_node {
            // pR.min_counter == pR.max_counter
            let cnt = F::rand();
            proof[min_cnt_range].copy_from_slice(&[cnt]);
            proof[max_cnt_range].copy_from_slice(&[cnt]);
        }
    }

    /// Assign the child proof to make consistent.
    pub(crate) fn unify_child_proof<const S: usize>(
        proof: &mut [F],
        is_rows_tree_node: bool,
        is_left_child: bool,
        subtree_pi: &PublicInputs<F, S>,
    ) where
        [(); S - 2]:,
    {
        let one = U256::from(1);
        let mut rng = thread_rng();

        let [pri_idx_val_range, min_val_range, max_val_range, min_cnt_range, max_cnt_range, min_items_range, max_items_range] =
            [
                ResultsConstructionPublicInputs::PrimaryIndexValue,
                ResultsConstructionPublicInputs::MinValue,
                ResultsConstructionPublicInputs::MaxValue,
                ResultsConstructionPublicInputs::MinCounter,
                ResultsConstructionPublicInputs::MaxCounter,
                ResultsConstructionPublicInputs::MinItems,
                ResultsConstructionPublicInputs::MaxItems,
            ]
            .map(PublicInputs::<F, S>::to_range);

        if is_rows_tree_node {
            // pC.I == pR.I
            proof[pri_idx_val_range].copy_from_slice(subtree_pi.to_primary_index_value_raw());

            let node_value = subtree_pi.min_value();
            if is_left_child {
                // pC.max <= pR.min
                let max_value = *[node_value, node_value.checked_sub(one).unwrap_or_default()]
                    .choose(&mut rng)
                    .unwrap();
                proof[max_val_range].copy_from_slice(&max_value.to_fields());

                let mut items = subtree_pi.min_items();
                if subtree_pi.no_duplicates_flag() && max_value == node_value {
                    // pC.max_items < pR.min_items
                    items[0] = items[0].checked_sub(one).unwrap();
                } else {
                    //Set pC.max_items = pR.min_items or the random U256s for false case.
                    items = *[items, array::from_fn(|_| U256::from_limbs(rng.gen()))]
                        .choose(&mut rng)
                        .unwrap();
                }
                proof[max_items_range]
                    .copy_from_slice(&items.iter().flat_map(|item| item.to_fields()).collect_vec());
            } else {
                // pc.min >= pR.min
                let min_value = *[node_value, node_value.checked_add(one).unwrap_or_default()]
                    .choose(&mut rng)
                    .unwrap();
                proof[min_val_range].copy_from_slice(&min_value.to_fields());

                let mut items = subtree_pi.max_items();
                if subtree_pi.no_duplicates_flag() && min_value == node_value {
                    // pC.min_items > pR.max_items
                    items[0] = items[0].checked_add(one).unwrap();
                } else {
                    //Set pC.max_items = pR.min_items or the random U256s for false case.
                    items = *[items, array::from_fn(|_| U256::from_limbs(rng.gen()))]
                        .choose(&mut rng)
                        .unwrap();
                }
                proof[min_items_range]
                    .copy_from_slice(&items.iter().flat_map(|item| item.to_fields()).collect_vec());
            }
        } else {
            let node_value = subtree_pi.primary_index_value();
            if is_left_child {
                // pC.max < pR.I
                proof[max_val_range]
                    .copy_from_slice(&node_value.checked_sub(one).unwrap().to_fields());
            } else {
                // pc.min > pR.I
                proof[min_val_range]
                    .copy_from_slice(&node_value.checked_add(one).unwrap().to_fields());
            }
        }

        if is_left_child {
            // pC.max_counter = pR.min_counter - 1
            proof[max_cnt_range].copy_from_slice(&[subtree_pi.min_counter() - F::ONE]);
        } else {
            // pC.min_counter = pR.max_counter + 1
            proof[min_cnt_range].copy_from_slice(&[subtree_pi.max_counter() + F::ONE]);
        }
    }
}
