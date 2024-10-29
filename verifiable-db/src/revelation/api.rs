use anyhow::{ensure, Result};
use std::iter::repeat;

use itertools::Itertools;
use mp2_common::{
    array::ToField,
    default_config,
    poseidon::H,
    proof::{deserialize_proof, ProofWithVK},
    utils::FromFields,
    C, D, F,
};
use plonky2::plonk::{
    circuit_data::VerifierOnlyCircuitData, config::Hasher, proof::ProofWithPublicInputs,
};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{
        prepare_recursive_circuit_for_circuit_set, RecursiveCircuitInfo, RecursiveCircuits,
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    query::{
        aggregation::QueryBounds,
        computational_hash_ids::PlaceholderIdentifier,
        universal_circuit::{
            universal_circuit_inputs::{PlaceholderId, Placeholders},
            universal_query_circuit::QueryBound,
        },
    },
    revelation::placeholders_check::CheckedPlaceholder,
};

use super::{
    revelation_without_results_tree::{
        CircuitBuilderParams, RecursiveCircuitInputs, RecursiveCircuitWires,
        RevelationWithoutResultsTreeCircuit,
    },
    NUM_QUERY_IO, PI_LEN,
};

#[derive(Debug, Serialize, Deserialize)]
/// Parameters for revelation circuits. The following const generic values need to be specified:
/// - `MAX_NUM_OUTPUTS`: upper bound on the number of output rows which can be exposed as public outputs of the circuit
/// - `MAX_NUM_ITEMS_PER_OUTPUT`: upper bound on the number of items per output row; should correspond to the
///     upper bound on the number of items being found in `SELECT` statement of the query
/// - `MAX_NUM_PLACEHOLDERS`: upper bound on the number of placeholders we allow in a query
/// - `NUM_PLACEHOLDERS_HASHED`: number of placeholders being hashed in the placeholder hash
pub struct Parameters<
    const MAX_NUM_OUTPUTS: usize,
    const MAX_NUM_ITEMS_PER_OUTPUT: usize,
    const MAX_NUM_PLACEHOLDERS: usize,
    const NUM_PLACEHOLDERS_HASHED: usize,
> where
    [(); MAX_NUM_ITEMS_PER_OUTPUT - 1]:,
    [(); NUM_QUERY_IO::<MAX_NUM_ITEMS_PER_OUTPUT>]:,
{
    revelation_no_results_tree: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        0,
        RecursiveCircuitWires<
            MAX_NUM_OUTPUTS,
            MAX_NUM_ITEMS_PER_OUTPUT,
            MAX_NUM_PLACEHOLDERS,
            NUM_PLACEHOLDERS_HASHED,
        >,
    >,
    //ToDo: add revelation circuit with results tree
    circuit_set: RecursiveCircuits<F, C, D>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Circuit inputs for revelation circuits. The following const generic values need to be specified:
/// - `MAX_NUM_OUTPUTS`: upper bound on the number of output rows which can be exposed as public outputs of the circuit
/// - `MAX_NUM_ITEMS_PER_OUTPUT`: upper bound on the number of items per output row; should correspond to the
///     upper bound on the number of items being found in `SELECT` statement of the query
/// - `MAX_NUM_PLACEHOLDERS`: upper bound on the number of placeholders we allow in a query
/// - `NUM_PLACEHOLDERS_HASHED`: number of placeholders being hashed in the placeholder hash
pub enum CircuitInput<
    const MAX_NUM_OUTPUTS: usize,
    const MAX_NUM_ITEMS_PER_OUTPUT: usize,
    const MAX_NUM_PLACEHOLDERS: usize,
    const NUM_PLACEHOLDERS_HASHED: usize,
> {
    NoResultsTree {
        query_proof: ProofWithVK,
        preprocessing_proof: ProofWithPublicInputs<F, C, D>,
        revelation_circuit: RevelationWithoutResultsTreeCircuit<
            MAX_NUM_OUTPUTS,
            MAX_NUM_ITEMS_PER_OUTPUT,
            MAX_NUM_PLACEHOLDERS,
            NUM_PLACEHOLDERS_HASHED,
        >,
    },
    //ToDo: add circuit input for revelation circuit with results tree
}

impl<
        const MAX_NUM_OUTPUTS: usize,
        const MAX_NUM_ITEMS_PER_OUTPUT: usize,
        const MAX_NUM_PLACEHOLDERS: usize,
        const NUM_PLACEHOLDERS_HASHED: usize,
    >
    CircuitInput<
        MAX_NUM_OUTPUTS,
        MAX_NUM_ITEMS_PER_OUTPUT,
        MAX_NUM_PLACEHOLDERS,
        NUM_PLACEHOLDERS_HASHED,
    >
{
    /// Initialize circuit inputs for the revelation circuit for queries without a results tree.
    /// The method requires the following inputs:
    /// - `query_proof`: Proof computing the results of the query, generated with circuit set in `query::api::Paramaters`
    /// - `preprocessing_proof`: Proof of construction of the tree over which the query was performed, generated with the
    ///     IVC set of circuit
    /// - `query_bounds`: bounds on values of primary and secondary indexes specified in the query
    /// - `placeholders`: set of placeholders employed in the query. They must be less than `MAX_NUM_PLACEHOLDERS`
    /// - `placeholder_hash_ids`: Identifiers of the placeholders employed to compute the placeholder hash; they can be
    ///     obtained by the method `ids_for_placeholder_hash` of `query::api::Parameters`
    pub fn new_revelation_no_results_tree(
        query_proof: Vec<u8>,
        preprocessing_proof: Vec<u8>,
        query_bounds: &QueryBounds,
        placeholders: &Placeholders,
        placeholder_hash_ids: [PlaceholderId; NUM_PLACEHOLDERS_HASHED],
    ) -> Result<Self> {
        let query_proof = ProofWithVK::deserialize(&query_proof)?;
        let preprocessing_proof = deserialize_proof(&preprocessing_proof)?;
        let num_placeholders = placeholders.len();
        ensure!(
            num_placeholders <= MAX_NUM_PLACEHOLDERS,
            "number of placeholders provided is more than the maximum number of placeholders"
        );
        // get placeholder ids from `placeholders` in the order expected by the circuit
        let placeholder_ids = placeholders.ids();
        let (padded_placeholder_ids, padded_placeholder_values): (Vec<F>, Vec<_>) = placeholder_ids
            .iter()
            .map(|id| (*id, placeholders.get(id).unwrap()))
            // pad placeholder ids and values with the first items in the arrays, as expected by the circuit
            .chain(repeat((
                PlaceholderIdentifier::MinQueryOnIdx1,
                placeholders
                    .get(&PlaceholderIdentifier::MinQueryOnIdx1)
                    .unwrap(),
            )))
            .take(MAX_NUM_PLACEHOLDERS)
            .map(|(id, value)| {
                let id: F = id.to_field();
                (id, value)
            })
            .unzip();
        let compute_checked_placeholder_for_id = |placeholder_id: PlaceholderIdentifier| {
            let value = placeholders.get(&placeholder_id)?;
            // locate placeholder with id `placeholder_id` in `padded_placeholder_ids`
            let pos = padded_placeholder_ids
                .iter()
                .find_position(|&&id| id == placeholder_id.to_field());
            ensure!(
                pos.is_some(),
                "placeholder with id {:?} not found in padded placeholder ids",
                placeholder_id
            );
            // sanity check: `padded_placeholder_values[pos] = value`
            assert_eq!(
                padded_placeholder_values[pos.unwrap().0],
                value,
                "placehoder values doesn't match for id {:?}",
                placeholder_id
            );
            Ok(CheckedPlaceholder {
                id: placeholder_id.to_field(),
                value,
                pos: pos.unwrap().0.to_field(),
            })
        };
        let to_be_checked_placeholders = placeholder_hash_ids
            .into_iter()
            .map(&compute_checked_placeholder_for_id)
            .collect::<Result<Vec<_>>>()?;
        // compute placeholders data to be hashed for secondary query bounds
        let min_query_secondary =
            QueryBound::new_secondary_index_bound(placeholders, query_bounds.min_query_secondary())
                .unwrap();
        let max_query_secondary =
            QueryBound::new_secondary_index_bound(placeholders, query_bounds.max_query_secondary())
                .unwrap();
        let secondary_query_bound_placeholders = [min_query_secondary, max_query_secondary]
            .into_iter()
            .flat_map(|query_bound| {
                [
                    compute_checked_placeholder_for_id(PlaceholderId::from_fields(&[query_bound
                        .operation
                        .placeholder_ids[0]])),
                    compute_checked_placeholder_for_id(PlaceholderId::from_fields(&[query_bound
                        .operation
                        .placeholder_ids[1]])),
                ]
            })
            .collect::<Result<Vec<_>>>()?;
        let revelation_circuit = RevelationWithoutResultsTreeCircuit {
            num_placeholders,
            placeholder_ids: padded_placeholder_ids.try_into().unwrap(),
            placeholder_values: padded_placeholder_values.try_into().unwrap(),
            to_be_checked_placeholders: to_be_checked_placeholders.try_into().unwrap(),
            secondary_query_bound_placeholders: secondary_query_bound_placeholders
                .try_into()
                .unwrap(),
        };

        Ok(CircuitInput::NoResultsTree {
            query_proof,
            preprocessing_proof,
            revelation_circuit,
        })
    }
}

const REVELATION_CIRCUIT_SET_SIZE: usize = 1;
impl<
        const MAX_NUM_OUTPUTS: usize,
        const MAX_NUM_ITEMS_PER_OUTPUT: usize,
        const MAX_NUM_PLACEHOLDERS: usize,
        const NUM_PLACEHOLDERS_HASHED: usize,
    >
    Parameters<
        MAX_NUM_OUTPUTS,
        MAX_NUM_ITEMS_PER_OUTPUT,
        MAX_NUM_PLACEHOLDERS,
        NUM_PLACEHOLDERS_HASHED,
    >
where
    [(); MAX_NUM_ITEMS_PER_OUTPUT - 1]:,
    [(); NUM_QUERY_IO::<MAX_NUM_ITEMS_PER_OUTPUT>]:,
    [(); <H as Hasher<F>>::HASH_SIZE]:,
    [(); PI_LEN::<MAX_NUM_OUTPUTS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_PLACEHOLDERS>]:,
{
    pub fn build(
        query_circuit_set: &RecursiveCircuits<F, C, D>,
        preprocessing_circuit_set: &RecursiveCircuits<F, C, D>,
        preprocessing_vk: &VerifierOnlyCircuitData<C, D>,
    ) -> Self {
        let builder = CircuitWithUniversalVerifierBuilder::<
            F,
            D,
            { PI_LEN::<MAX_NUM_OUTPUTS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_PLACEHOLDERS> },
        >::new::<C>(default_config(), REVELATION_CIRCUIT_SET_SIZE);
        let build_parameters = CircuitBuilderParams {
            query_circuit_set: query_circuit_set.clone(),
            preprocessing_circuit_set: preprocessing_circuit_set.clone(),
            preprocessing_vk: preprocessing_vk.clone(),
        };
        let revelation_no_results_tree = builder.build_circuit(build_parameters);

        let circuits = vec![prepare_recursive_circuit_for_circuit_set(
            &revelation_no_results_tree,
        )];

        let circuit_set = RecursiveCircuits::new(circuits);

        Self {
            revelation_no_results_tree,
            circuit_set,
        }
    }

    pub fn generate_proof(
        &self,
        input: CircuitInput<
            MAX_NUM_OUTPUTS,
            MAX_NUM_ITEMS_PER_OUTPUT,
            MAX_NUM_PLACEHOLDERS,
            NUM_PLACEHOLDERS_HASHED,
        >,
        query_circuit_set: &RecursiveCircuits<F, C, D>,
    ) -> Result<Vec<u8>> {
        let proof = ProofWithVK::from(match input {
            CircuitInput::NoResultsTree {
                query_proof,
                preprocessing_proof,
                revelation_circuit,
            } => {
                let input = RecursiveCircuitInputs {
                    inputs: revelation_circuit,
                    query_proof,
                    preprocessing_proof,
                    query_circuit_set: query_circuit_set.clone(),
                };
                (
                    self.circuit_set.generate_proof(
                        &self.revelation_no_results_tree,
                        [],
                        [],
                        input,
                    )?,
                    self.revelation_no_results_tree.get_verifier_data().clone(),
                )
            }
        });
        proof.serialize()
    }

    pub fn get_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        &self.circuit_set
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::{
        TestRevelationData, MAX_NUM_COLUMNS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_OUTPUTS,
        MAX_NUM_PLACEHOLDERS, MAX_NUM_PREDICATE_OPS, MAX_NUM_RESULT_OPS,
    };
    use itertools::Itertools;
    use mp2_common::{
        array::ToField,
        proof::{serialize_proof, ProofWithVK},
        types::HashOutput,
        C, D, F,
    };
    use mp2_test::log::init_logging;
    use plonky2::{
        field::types::PrimeField64, hash::hash_types::HashOut, plonk::config::GenericHashOut,
    };
    use recursion_framework::framework_testing::TestingRecursiveCircuits;

    use crate::{
        ivc::PublicInputs as PreprocessingPI,
        query::{
            api::CircuitInput as QueryInput,
            computational_hash_ids::{ColumnIDs, Identifiers},
            public_inputs::PublicInputs as QueryPI,
        },
        revelation::{
            api::{CircuitInput, Parameters},
            tests::compute_results_from_query_proof,
            PublicInputs, NUM_PREPROCESSING_IO, NUM_QUERY_IO,
        },
    };

    #[test]
    fn test_api() {
        init_logging();

        let query_circuits = TestingRecursiveCircuits::<
            F,
            C,
            D,
            { NUM_QUERY_IO::<MAX_NUM_ITEMS_PER_OUTPUT> },
        >::default();
        let preprocessing_circuits =
            TestingRecursiveCircuits::<F, C, D, NUM_PREPROCESSING_IO>::default();
        println!("building params");
        let params = Parameters::<
            MAX_NUM_OUTPUTS,
            MAX_NUM_ITEMS_PER_OUTPUT,
            MAX_NUM_PLACEHOLDERS,
            { 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS) },
        >::build(
            query_circuits.get_recursive_circuit_set(),
            preprocessing_circuits.get_recursive_circuit_set(),
            preprocessing_circuits
                .verifier_data_for_input_proofs::<1>()
                .last()
                .unwrap(),
        );

        // Generate the testing data for revalation circuit.
        let test_data = TestRevelationData::sample(42, 76);

        let placeholder_hash_ids = QueryInput::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_ITEMS_PER_OUTPUT,
        >::ids_for_placeholder_hash(
            test_data.predicate_operations(),
            test_data.results(),
            test_data.placeholders(),
            test_data.query_bounds(),
        )
        .unwrap();

        let query_pi = QueryPI::<F, MAX_NUM_ITEMS_PER_OUTPUT>::from_slice(test_data.query_pi_raw());

        // generate query proof
        let [query_proof] = query_circuits
            .generate_input_proofs::<1>([test_data.query_pi_raw().try_into().unwrap()])
            .unwrap();
        let [query_vk] = query_circuits.verifier_data_for_input_proofs::<1>();
        let query_proof = ProofWithVK::from((query_proof, query_vk.clone()))
            .serialize()
            .unwrap();
        // generate pre-processing proof
        let [preprocessing_proof] = preprocessing_circuits
            .generate_input_proofs::<1>([test_data.preprocessing_pi_raw().try_into().unwrap()])
            .unwrap();
        let preprocessing_pi = PreprocessingPI::from_slice(&preprocessing_proof.public_inputs);
        let preprocessing_proof = serialize_proof(&preprocessing_proof).unwrap();

        let input = CircuitInput::new_revelation_no_results_tree(
            query_proof,
            preprocessing_proof,
            test_data.query_bounds(),
            test_data.placeholders(),
            placeholder_hash_ids,
        )
        .unwrap();
        let proof = params
            .generate_proof(input, query_circuits.get_recursive_circuit_set())
            .unwrap();
        let (proof, _) = ProofWithVK::deserialize(&proof).unwrap().into();
        let pi = PublicInputs::<F, MAX_NUM_OUTPUTS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_PLACEHOLDERS>::from_slice(&proof.public_inputs);
        // check public inputs
        assert_eq!(
            pi.original_block_hash(),
            preprocessing_pi.block_hash_fields()
        );
        assert_eq!(
            pi.num_placeholders(),
            (test_data.placeholders().len()).to_field()
        );
        let expected_values = test_data.placeholders().placeholder_values();
        assert_eq!(
            pi.placeholder_values()[..test_data.placeholders().len()],
            expected_values,
        );
        // check entry count
        assert_eq!(query_pi.num_matching_rows(), pi.entry_count(),);
        // check results and overflow
        let (result, overflow) = compute_results_from_query_proof(&query_pi);
        assert_eq!(pi.num_results().to_canonical_u64(), 1,);
        assert_eq!(pi.result_values()[0], result,);
        assert_eq!(pi.overflow_flag(), overflow,);
        // check computational hash
        // first, compute the final computational hash
        let metadata_hash = HashOut::<F>::from_partial(preprocessing_pi.metadata_hash());
        let computational_hash = Identifiers::computational_hash(
            &ColumnIDs::new(
                test_data.column_cells()[0].id.to_canonical_u64(),
                test_data.column_cells()[1].id.to_canonical_u64(),
                test_data.column_cells()[2..]
                    .iter()
                    .map(|cell| cell.id.to_canonical_u64())
                    .collect_vec(),
            ),
            test_data.predicate_operations(),
            test_data.results(),
            &HashOutput::try_from(metadata_hash.to_bytes()).unwrap(),
            Some(test_data.query_bounds().min_query_secondary().into()),
            Some(test_data.query_bounds().max_query_secondary().into()),
        )
        .unwrap();
        // then, check that it is the same exposed by the proof
        assert_eq!(
            HashOutput::try_from(
                pi.flat_computational_hash()
                    .iter()
                    .flat_map(|f| u32::try_from(f.to_canonical_u64()).unwrap().to_be_bytes())
                    .collect_vec()
            )
            .unwrap(),
            computational_hash,
        )
    }
}
