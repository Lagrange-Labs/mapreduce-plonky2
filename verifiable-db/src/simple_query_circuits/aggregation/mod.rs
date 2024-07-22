mod child_proven_single_path_node;
mod full_node_index_leaf;
mod full_node_with_one_child;
mod full_node_with_two_children;
mod output_computation;

#[cfg(test)]
pub(crate) mod tests {
    use crate::simple_query_circuits::{
        computational_hash_ids::{AggregationOperation, Identifiers},
        public_inputs::{PublicInputs, QueryPublicInputs},
        PI_LEN,
    };
    use alloy::primitives::U256;
    use mp2_common::{
        array::ToField, group_hashing::add_curve_point, types::CURVE_TARGET_LEN, utils::ToFields, F,
    };
    use mp2_test::utils::random_vector;
    use plonky2::{
        field::types::{Field, Sample},
        hash::hash_types::NUM_HASH_OUT_ELTS,
    };
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{prelude::SliceRandom, thread_rng, Rng};
    use std::array;

    /// Generate a field array of S random aggregation operations.
    pub(crate) fn random_aggregation_operations<const S: usize>() -> [F; S] {
        let ops = [
            AggregationOperation::IdOp,
            AggregationOperation::SumOp,
            AggregationOperation::MinOp,
            AggregationOperation::MaxOp,
            AggregationOperation::AvgOp,
        ];

        let mut rng = thread_rng();
        array::from_fn(|_| {
            let op = *ops.choose(&mut rng).unwrap();
            Identifiers::AggregationOperations(op).to_field()
        })
    }

    /// Generate S number of proof public input slices by the specified operations.
    /// The each returned proof public inputs could be constructed by
    /// `PublicInputs::from_slice` function.
    pub(crate) fn random_aggregation_public_inputs<const N: usize, const S: usize>(
        ops: &[F; S],
    ) -> [Vec<F>; N] {
        let [ops_range, overflow_range, index_ids_range, c_hash_range, p_hash_range] = [
            QueryPublicInputs::OpIds,
            QueryPublicInputs::Overflow,
            QueryPublicInputs::IndexIds,
            QueryPublicInputs::ComputationalHash,
            QueryPublicInputs::PlaceholderHash,
        ]
        .map(|input| PublicInputs::<F, S>::to_range(input));

        let first_value_start =
            PublicInputs::<F, S>::to_range(QueryPublicInputs::OutputValues).start;
        let is_first_op_id =
            ops[0] == Identifiers::AggregationOperations(AggregationOperation::IdOp).to_field();

        // Generate the index ids, computational hash and placeholder hash,
        // they should be same for a series of public inputs.
        let mut rng = thread_rng();
        let index_ids: Vec<_> = random_vector::<u32>(2).to_fields();
        let [computational_hash, placeholder_hash]: [Vec<_>; 2] =
            array::from_fn(|_| random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields());

        array::from_fn(|_| {
            let mut pi = random_vector::<u32>(PI_LEN::<S>).to_fields();

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

    /// Compute the output values and the overflow number at the specified index by
    /// the proofs. It's the test function corresponding to `compute_output_item`.
    pub(crate) fn compute_output_item_value<const S: usize>(
        i: usize,
        proofs: &[&PublicInputs<F, S>],
    ) -> (Vec<F>, u32)
    where
        [(); S - 1]:,
    {
        let proof0 = &proofs[0];
        let op = proof0.operation_ids()[i];

        let [op_id, op_min, op_max, op_sum, op_avg] = [
            AggregationOperation::IdOp,
            AggregationOperation::MinOp,
            AggregationOperation::MaxOp,
            AggregationOperation::SumOp,
            AggregationOperation::AvgOp,
        ]
        .map(|op| Identifiers::AggregationOperations(op).to_field());

        let is_op_id = op == op_id;
        let is_op_min = op == op_min;
        let is_op_max = op == op_max;
        let is_op_sum = op == op_sum;
        let is_op_avg = op == op_avg;

        // Check that the all proofs are employing the same aggregation operation.
        proofs[1..]
            .iter()
            .for_each(|p| assert_eq!(p.operation_ids()[i], op));

        // Compute the SUM, MIN or MAX value.
        let mut sum_overflow = 0;
        let mut output = proof0.value_at_index(i);
        if i == 0 && is_op_id {
            // If it's the first proof and the operation is ID,
            // the value is a curve point not a Uint256.
            output = U256::ZERO;
        }
        for p in proofs[1..].iter() {
            // Get the current proof value.
            let mut value = p.value_at_index(i);
            if i == 0 && is_op_id {
                // If it's the first proof and the operation is ID,
                // the value is a curve point not a Uint256.
                value = U256::ZERO;
            }

            // Compute the MIN or MAX value.
            if is_op_min {
                output = output.min(value);
            } else if is_op_max {
                output = output.max(value);
            } else {
                // Compute the SUM value and the overflow.
                let (addition, overflow) = output.overflowing_add(value);
                output = addition;
                if overflow {
                    sum_overflow += 1;
                }
            }
        }

        let mut output = output.to_fields();
        if i == 0 {
            // We always accumulate order-agnostic digest of the proofs for the first item.
            output = if is_op_id {
                let points: Vec<_> = proofs
                    .iter()
                    .map(|p| Point::decode(p.first_value_as_curve_point().encode()).unwrap())
                    .collect();
                add_curve_point(&points).to_fields()
            } else {
                // Pad the current output to ``CURVE_TARGET_LEN` for the first item.
                PublicInputs::<_, S>::pad_slice_to_curve_len(&output)
            };
        }

        // Set the overflow if the operation is SUM or AVG:
        // overflow = op == SUM OR op == AVG ? sum_overflow : 0
        let overflow = if is_op_sum || is_op_avg {
            sum_overflow
        } else {
            0
        };

        (output, overflow)
    }
}
