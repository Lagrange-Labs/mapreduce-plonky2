//! Module handling the circuit for binding results tree to the original tree

use crate::{
    query::{
        computational_hash_ids::{AggregationOperation, ResultIdentifier},
        public_inputs::PublicInputs as QueryProofPI,
        universal_circuit::ComputationalHashTarget,
    },
    results_tree::{
        binding::public_inputs::PublicInputs,
        construction::public_inputs::PublicInputs as ResultsConstructionProofPI,
    },
};
use mp2_common::{
    array::ToField, group_hashing::CircuitBuilderGroupHashing, public_inputs::PublicInputCommon,
    types::CBuilder, utils::ToTargets, CHasher,
};
use plonky2::iop::target::Target;
use serde::{Deserialize, Serialize};
use std::slice;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BindingResultsWires<const S: usize>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BindingResultsCircuit<const S: usize>;

impl<const S: usize> BindingResultsCircuit<S> {
    pub fn build(
        b: &mut CBuilder,
        query_proof: &QueryProofPI<Target, S>,
        results_construction_proof: &ResultsConstructionProofPI<Target, S>,
    ) -> BindingResultsWires<S> {
        let one = b.one();

        // Enforce values accumulated from the original tree are the same values
        // employed to build the results tree:
        // assert pQ.V[0] == pR.D
        b.connect_curve_points(
            query_proof.first_value_as_curve_target(),
            results_construction_proof.accumulator_target(),
        );

        // Enforce we are using this circuit for a proof without result aggreggation:
        // assert pQ.ops[0] == "ID"
        let op_id = b.constant(AggregationOperation::IdOp.to_field());
        b.connect(query_proof.operation_ids_target()[0], op_id);

        // Enforce that the counters assigned to nodes while building the results
        // tree started from 1:
        // assert pR.min_counter == 1
        b.connect(results_construction_proof.min_counter_target(), one);

        // Keep track in the computational hash whether we built the result tree
        // enforcing that there are no duplicates or not
        // if pR.no_duplicates:
        //     res_id = "RESULT_DISTINCT"
        // else:
        //     res_id = "RESULT"
        let computational_hash = ResultIdentifier::result_id_hash_circuit(
            b,
            ComputationalHashTarget::from_vec(query_proof.to_computational_hash_raw().to_vec()),
            &results_construction_proof.no_duplicates_flag_target(),
        );

        // Compute the placeholder hash:
        // H(pQ.H_p || pQ.MIN_I || pQ.MAX_I)
        let inputs = query_proof
            .to_placeholder_hash_raw()
            .iter()
            .chain(query_proof.to_min_query_raw())
            .chain(query_proof.to_max_query_raw())
            .cloned()
            .collect();
        let placeholder_hash = b.hash_n_to_hash_no_pad::<CHasher>(inputs);

        // Register the public inputs.
        PublicInputs::new(
            results_construction_proof.to_tree_hash_raw(),
            query_proof.to_hash_raw(),
            &computational_hash.to_targets(),
            &placeholder_hash.to_targets(),
            // count = COUNT(DISTINCT *)
            slice::from_ref(results_construction_proof.to_max_counter_raw()),
            slice::from_ref(query_proof.to_overflow_raw()),
        )
        .register(b);

        BindingResultsWires
    }
}

// TODO: implment `CircuitLogicWires` for API which should use the query
// aggregation and results construction circuit sets.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        results_tree::construction::{
            public_inputs::ResultsConstructionPublicInputs,
            tests::random_results_construction_public_inputs,
        },
        test_utils::{random_aggregation_operations, random_aggregation_public_inputs},
    };
    use itertools::Itertools;
    use mp2_common::{poseidon::H, utils::ToFields, C, D, F};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::types::Field,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::config::Hasher,
    };

    const S: usize = 20;

    const QUERY_PI_LEN: usize = crate::query::PI_LEN::<S>;
    const RESULTS_CONSTRUCTION_PI_LEN: usize = crate::results_tree::construction::PI_LEN::<S>;

    #[derive(Clone, Debug)]
    struct TestBindingResultsCircuit<'a> {
        query_proof: &'a [F],
        results_construction_proof: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestBindingResultsCircuit<'a> {
        // Query proof + results construction proof
        type Wires = (Vec<Target>, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let query_proof = b.add_virtual_target_arr::<QUERY_PI_LEN>().to_vec();
            let results_construction_proof = b
                .add_virtual_target_arr::<RESULTS_CONSTRUCTION_PI_LEN>()
                .to_vec();
            let query_pi = QueryProofPI::<Target, S>::from_slice(&query_proof);
            let results_construction_pi =
                ResultsConstructionProofPI::<Target, S>::from_slice(&results_construction_proof);

            BindingResultsCircuit::build(b, &query_pi, &results_construction_pi);

            (query_proof, results_construction_proof)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.0, self.query_proof);
            pw.set_target_arr(&wires.1, self.results_construction_proof);
        }
    }

    fn test_results_binding_circuit(is_distinct: bool) {
        // Generate the input proofs.
        let mut ops = random_aggregation_operations();
        // Set the first operation to ID.
        ops[0] = AggregationOperation::IdOp.to_field();
        let [query_proof] = random_aggregation_public_inputs::<1, S>(&ops);
        let query_pi = QueryProofPI::<_, S>::from_slice(&query_proof);
        let [mut results_construction_proof] = random_results_construction_public_inputs::<1, S>();

        let [min_cnt_range, no_dup_range, acc_range] = [
            ResultsConstructionPublicInputs::MinCounter,
            ResultsConstructionPublicInputs::NoDuplicates,
            ResultsConstructionPublicInputs::Accumulator,
        ]
        .map(ResultsConstructionProofPI::<F, S>::to_range);

        // Set the accumulator of results construction proof to the first output value of query proof.
        results_construction_proof[acc_range]
            .copy_from_slice(&query_pi.first_value_as_curve_point().to_fields());
        // Set the minimum counter to 1.
        results_construction_proof[min_cnt_range].copy_from_slice(&[F::ONE]);
        // Set the no duplicates flag.
        let no_duplicates = if is_distinct { F::ONE } else { F::ZERO };
        results_construction_proof[no_dup_range].copy_from_slice(&[no_duplicates]);

        let results_construction_pi =
            ResultsConstructionProofPI::<_, S>::from_slice(&results_construction_proof);

        // Construct the test circuit.
        let test_circuit = TestBindingResultsCircuit {
            query_proof: &query_proof,
            results_construction_proof: &results_construction_proof,
        };

        // Prove for the test circuit.
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);

        // Check the public inputs.
        // Results tree hash
        assert_eq!(pi.results_tree_hash(), results_construction_pi.tree_hash());
        // Original tree hash
        assert_eq!(pi.original_tree_hash(), query_pi.tree_hash());
        // Computational hash
        {
            let res_id = if is_distinct {
                ResultIdentifier::ResultWithDistinct
            } else {
                ResultIdentifier::ResultNoDistinct
            };

            // H(res_id || pQ.C)
            let inputs = once(&res_id.to_field())
                .chain(query_pi.to_computational_hash_raw())
                .cloned()
                .collect_vec();
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.computational_hash(), exp_hash);
        }
        // Placeholder hash
        {
            // H(pQ.H_p || pQ.MIN_I || pQ.MAX_I)
            let inputs = query_pi
                .to_placeholder_hash_raw()
                .iter()
                .chain(query_pi.to_min_query_raw())
                .chain(query_pi.to_max_query_raw())
                .cloned()
                .collect_vec();
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.placeholder_hash(), exp_hash);
        }
        // Entry count
        assert_eq!(pi.entry_count(), results_construction_pi.max_counter());
        // Overflow flag
        assert_eq!(pi.overflow_flag(), query_pi.overflow_flag());
    }

    #[test]
    fn test_results_binding_no_distinct() {
        test_results_binding_circuit(false);
    }

    #[test]
    fn test_results_binding_with_distinct() {
        test_results_binding_circuit(true);
    }
}
