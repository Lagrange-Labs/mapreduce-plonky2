pub(crate) mod binding;
pub(crate) mod construction;
/// Old query public inputs, moved here because the circuits in this module still expects
/// these public inputs for now
pub(crate) mod old_public_inputs;

#[cfg(test)]
pub(crate) mod tests {
    use std::array;

    use mp2_common::{array::ToField, types::CURVE_TARGET_LEN, utils::ToFields, F};
    use plonky2::{
        field::types::{Field, Sample},
        hash::hash_types::NUM_HASH_OUT_ELTS,
    };
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{thread_rng, Rng};

    use crate::query::computational_hash_ids::{AggregationOperation, Identifiers};

    use super::old_public_inputs::{PublicInputs, QueryPublicInputs};

    /// Generate S number of proof public input slices by the specified operations for testing.
    /// The each returned proof public inputs could be constructed by
    /// `PublicInputs::from_slice` function.
    pub fn random_aggregation_public_inputs<const N: usize, const S: usize>(
        ops: &[F; S],
    ) -> [Vec<F>; N] {
        let [ops_range, overflow_range, index_ids_range, c_hash_range, p_hash_range] = [
            QueryPublicInputs::OpIds,
            QueryPublicInputs::Overflow,
            QueryPublicInputs::IndexIds,
            QueryPublicInputs::ComputationalHash,
            QueryPublicInputs::PlaceholderHash,
        ]
        .map(PublicInputs::<F, S>::to_range);

        let first_value_start =
            PublicInputs::<F, S>::to_range(QueryPublicInputs::OutputValues).start;
        let is_first_op_id =
            ops[0] == Identifiers::AggregationOperations(AggregationOperation::IdOp).to_field();

        // Generate the index ids, computational hash and placeholder hash,
        // they should be same for a series of public inputs.
        let mut rng = thread_rng();
        let index_ids = (0..2).map(|_| rng.gen()).collect::<Vec<u32>>().to_fields();
        let [computational_hash, placeholder_hash]: [Vec<_>; 2] = array::from_fn(|_| {
            (0..NUM_HASH_OUT_ELTS)
                .map(|_| rng.gen())
                .collect::<Vec<u32>>()
                .to_fields()
        });

        array::from_fn(|_| {
            let mut pi = (0..PublicInputs::<F, S>::total_len())
                .map(|_| rng.gen())
                .collect::<Vec<u32>>()
                .to_fields();

            // Copy the specified operations to the proofs.
            pi[ops_range.clone()].copy_from_slice(ops);

            // Set the overflow flag to a random boolean.
            let overflow = F::from_bool(rng.gen());
            pi[overflow_range.clone()].copy_from_slice(&[overflow]);

            // Set the index ids, computational hash and placeholder hash,
            pi[index_ids_range.clone()].copy_from_slice(&index_ids);
            pi[c_hash_range.clone()].copy_from_slice(&computational_hash);
            pi[p_hash_range.clone()].copy_from_slice(&placeholder_hash);

            // If the first operation is ID, set the value to a random point.
            if is_first_op_id {
                let first_value = Point::sample(&mut rng).to_weierstrass().to_fields();
                pi[first_value_start..first_value_start + CURVE_TARGET_LEN]
                    .copy_from_slice(&first_value);
            }

            pi
        })
    }
}
