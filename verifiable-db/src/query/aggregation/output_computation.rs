//! Compute each node output item by the input proofs

use crate::query::{
    computational_hash_ids::{AggregationOperation, Identifiers},
    public_inputs::PublicInputs,
};
use mp2_common::{
    array::ToField,
    group_hashing::CircuitBuilderGroupHashing,
    types::CBuilder,
    u256::CircuitBuilderU256,
    utils::{FromTargets, ToTargets},
};
use plonky2::iop::target::Target;
use plonky2_crypto::u32::arithmetic_u32::CircuitBuilderU32;
use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget};

/// Compute the node output item at the specified index by the proofs,
/// and return the output item with the overflow number.
pub(crate) fn compute_output_item<const S: usize>(
    b: &mut CBuilder,
    i: usize,
    proofs: &[&PublicInputs<Target, S>],
) -> (Vec<Target>, Target)
where
    [(); S - 1]:,
{
    let zero = b.zero();
    let u32_zero = b.zero_u32();
    let u256_zero = b.zero_u256();

    let proof0 = &proofs[0];
    let op = proof0.operation_ids_target()[i];

    let [op_id, op_min, op_max, op_sum, op_avg] = [
        AggregationOperation::IdOp,
        AggregationOperation::MinOp,
        AggregationOperation::MaxOp,
        AggregationOperation::SumOp,
        AggregationOperation::AvgOp,
    ]
    .map(|op| b.constant(Identifiers::AggregationOperations(op).to_field()));

    let is_op_id = b.is_equal(op, op_id);
    let is_op_min = b.is_equal(op, op_min);
    let is_op_max = b.is_equal(op, op_max);
    let is_op_sum = b.is_equal(op, op_sum);
    let is_op_avg = b.is_equal(op, op_avg);

    // Check that the all proofs are employing the same aggregation operation.
    proofs[1..]
        .iter()
        .for_each(|p| b.connect(p.operation_ids_target()[i], op));

    // Compute the SUM, MIN and MAX values.
    let mut sum_overflow = zero;
    let mut sum_value = proof0.value_target_at_index(i);
    if i == 0 {
        // If it's the first proof and the operation is ID, the value is a curve point,
        // which each field may be out of range of an Uint32 (to combine an Uint256).
        sum_value = b.select_u256(is_op_id, &u256_zero, &sum_value);
    }
    let mut min_value = sum_value.clone();
    let mut max_value = sum_value.clone();
    for p in proofs[1..].iter() {
        // Get the current proof value.
        let mut value = p.value_target_at_index(i);
        if i == 0 {
            // If it's the first proof and the operation is ID, the value is a curve point,
            // which each field may be out of range of an Uint32 (to combine an Uint256).
            value = b.select_u256(is_op_id, &u256_zero, &value);
        };

        // Compute the SUM value and the overflow.
        let (addition, overflow) = b.add_u256(&sum_value, &value);
        sum_value = addition;
        sum_overflow = b.add(sum_overflow, overflow.0);

        // Compute the MIN and MAX values.
        let (_, borrow) = b.sub_u256(&value, &min_value);
        let not_less_than = b.is_equal(borrow.0, u32_zero.0);
        min_value = b.select_u256(not_less_than, &min_value, &value);
        let (_, borrow) = b.sub_u256(&value, &max_value);
        let not_less_than = b.is_equal(borrow.0, u32_zero.0);
        max_value = b.select_u256(not_less_than, &value, &max_value);
    }

    // Compute the output item.
    let output = b.select_u256(is_op_min, &min_value, &sum_value);
    let output = b.select_u256(is_op_max, &max_value, &output);
    let mut output = output.to_targets();

    if i == 0 {
        // We always accumulate order-agnostic digest of the proofs for the first item.
        let points: Vec<_> = proofs
            .iter()
            .map(|p| p.first_value_as_curve_target())
            .collect();
        let digest = b.add_curve_point(&points);
        let a = b.curve_select(
            is_op_id,
            digest,
            // Pad the current output to `CURVE_TARGET_LEN` for the first item.
            CurveTarget::from_targets(&PublicInputs::<_, S>::pad_slice_to_curve_len(&output)),
        );
        output = a.to_targets();
    }

    // Set the overflow if the operation is SUM or AVG:
    // overflow = op == SUM OR op == AVG ? sum_overflow : 0
    let is_op_sum_or_avg = b.or(is_op_sum, is_op_avg);
    let overflow = b.mul(is_op_sum_or_avg.target, sum_overflow);

    (output, overflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{
        aggregation::tests::{
            compute_output_item_value, random_aggregation_operations,
            random_aggregation_public_inputs,
        },
        public_inputs::QueryPublicInputs,
        PI_LEN,
    };
    use mp2_common::{types::CURVE_TARGET_LEN, u256::NUM_LIMBS, utils::ToFields, C, D, F};
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::types::Field,
        iop::witness::{PartialWitness, WitnessWrite},
    };
    use std::array;

    #[derive(Clone, Debug)]
    struct TestOutput {
        output: Vec<F>,
        overflow: u32,
    }

    #[derive(Clone, Debug)]
    struct TestOutputWires {
        output: Vec<Target>,
        overflow: Target,
    }

    #[derive(Clone, Debug)]
    struct TestOutputComputationCircuit<const S: usize, const PROOF_NUM: usize> {
        proofs: [Vec<F>; PROOF_NUM],
        exp_outputs: [TestOutput; S],
    }

    impl<const S: usize, const PROOF_NUM: usize> UserCircuit<F, D>
        for TestOutputComputationCircuit<S, PROOF_NUM>
    where
        [(); S - 1]:,
        [(); { PI_LEN::<S> }]:,
    {
        // Proof public inputs + expected outputs
        type Wires = ([Vec<Target>; PROOF_NUM], [TestOutputWires; S]);

        fn build(b: &mut CBuilder) -> Self::Wires {
            // Initialize the proofs and the expected outputs.
            let proofs = array::from_fn(|_| b.add_virtual_target_arr::<{ PI_LEN::<S> }>().to_vec());
            let exp_outputs = array::from_fn(|i| {
                let output = if i == 0 {
                    b.add_virtual_target_arr::<CURVE_TARGET_LEN>().to_vec()
                } else {
                    b.add_virtual_target_arr::<NUM_LIMBS>().to_vec()
                };
                let overflow = b.add_virtual_target();

                TestOutputWires { output, overflow }
            });

            // Build the public inputs.
            let pis = [0; PROOF_NUM].map(|i| PublicInputs::<Target, S>::from_slice(&proofs[i]));
            let pis = [0; PROOF_NUM].map(|i| &pis[i]);

            // Check if the outputs as expected.
            exp_outputs.iter().enumerate().for_each(|(i, exp)| {
                let (output, overflow) = compute_output_item(b, i, &pis);

                exp.output
                    .iter()
                    .zip(output)
                    .for_each(|(l, r)| b.connect(*l, r));
                b.connect(overflow, exp.overflow);
            });

            (proofs, exp_outputs)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.proofs
                .iter()
                .zip(wires.0.iter())
                .for_each(|(v, t)| pw.set_target_arr(&t, v));
            self.exp_outputs
                .iter()
                .zip(wires.1.iter())
                .for_each(|(v, t)| {
                    pw.set_target_arr(&t.output, &v.output);
                    pw.set_target(t.overflow, F::from_canonical_u32(v.overflow));
                });
        }
    }

    impl<const S: usize, const PROOF_NUM: usize> TestOutputComputationCircuit<S, PROOF_NUM>
    where
        [(); S - 1]:,
    {
        fn new(proofs: [Vec<F>; PROOF_NUM]) -> Self {
            let pis = [0; PROOF_NUM].map(|i| PublicInputs::<F, S>::from_slice(&proofs[i]));
            let pis = [0; PROOF_NUM].map(|i| &pis[i]);

            let exp_outputs = array::from_fn(|i| {
                let (output, overflow) = compute_output_item_value(i, &pis);

                TestOutput { output, overflow }
            });

            Self {
                proofs,
                exp_outputs,
            }
        }
    }

    #[test]
    fn test_query_aggregation_output_computation_for_random_ops() {
        const S: usize = 10;
        const PROOF_NUM: usize = 2;

        // Generate the random operations.
        let ops: [_; S] = random_aggregation_operations();

        // Build the input proofs.
        let inputs = random_aggregation_public_inputs(&ops);

        // Construct the test circuit.
        let test_circuit = TestOutputComputationCircuit::<S, PROOF_NUM>::new(inputs);

        // Prove for the test circuit.
        run_circuit::<F, D, C, _>(test_circuit);
    }

    #[test]
    fn test_query_aggregation_output_computation_for_first_op_id() {
        const S: usize = 20;
        const PROOF_NUM: usize = 3;

        // Generate the random operations.
        let mut ops: [_; S] = random_aggregation_operations();

        // Set the first operation to ID for testing the digest computation.
        ops[0] = Identifiers::AggregationOperations(AggregationOperation::IdOp).to_field();

        // Build the input proofs.
        let inputs = random_aggregation_public_inputs(&ops);

        // Construct the test circuit.
        let test_circuit = TestOutputComputationCircuit::<S, PROOF_NUM>::new(inputs);

        // Prove for the test circuit.
        run_circuit::<F, D, C, _>(test_circuit);
    }
}