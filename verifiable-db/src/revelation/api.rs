use alloy::primitives::U256;
use anyhow::{ensure, Result};
use std::{
    any::Any,
    collections::HashMap,
    iter::{once, repeat},
};

use itertools::Itertools;
use mp2_common::{
    array::ToField,
    default_config,
    proof::{deserialize_proof, ProofWithVK},
    types::HashOutput,
    C, D, F,
};
use plonky2::{
    hash::{hash_types::HashOut, hashing::hash_n_to_hash_no_pad, poseidon::PoseidonHash},
    plonk::{
        circuit_data::VerifierOnlyCircuitData,
        config::{GenericHashOut, Hasher},
        proof::ProofWithPublicInputs,
    },
};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{
        prepare_recursive_circuit_for_circuit_set, RecursiveCircuitInfo, RecursiveCircuits,
    },
};
use serde::{Deserialize, Serialize};

use crate::query::{
    aggregation::QueryBounds,
    computational_hash_ids::{HashPermutation, Identifiers, PlaceholderIdentifier},
    universal_circuit::{
        universal_circuit_inputs::{BasicOperation, Placeholder, PlaceholderId, ResultStructure},
        universal_query_circuit::dummy_placeholder,
        ComputationalHash,
    },
};

use super::{
    placeholders_check::placeholder_ids_hash,
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
    /// - `placeholder_values`: set of placeholder values employed for the placeholders found in the query. They must be
    ///     less than `MAX_NUM_PLACEHOLDERS`
    /// - `placeholder_hash_ids`: Identifiers of the placeholders employed to compute the placeholder hash; they can be
    ///     obtained by the method `ids_for_placeholder_hash` of `query::api::Parameters`
    pub fn new_revelation_no_results_tree(
        query_proof: Vec<u8>,
        preprocessing_proof: Vec<u8>,
        query_bounds: &QueryBounds,
        placeholder_values: &HashMap<PlaceholderId, U256>,
        placeholder_hash_ids: [PlaceholderId; NUM_PLACEHOLDERS_HASHED],
    ) -> Result<Self> {
        let query_proof = ProofWithVK::deserialize(&query_proof)?;
        let preprocessing_proof = deserialize_proof(&preprocessing_proof)?;
        let num_placeholders = placeholder_values.len() + 4;
        ensure!(
            num_placeholders <= MAX_NUM_PLACEHOLDERS,
            "number of placeholders provided is more than the maximum number of placeholders"
        );
        // get placeholder ids from `placeholder_values` map and sort them to ensure that they are provided
        // in the correct order to the circuit
        let mut sorted_placeholder_ids = placeholder_values.keys().cloned().collect_vec();
        sorted_placeholder_ids.sort();
        let (padded_placeholder_ids, padded_placeholder_values): (Vec<F>, Vec<_>) = [
            (
                &PlaceholderIdentifier::MinQueryOnIdx1,
                &query_bounds.min_query_primary,
            ),
            (
                &PlaceholderIdentifier::MaxQueryOnIdx1,
                &query_bounds.max_query_primary,
            ),
            (
                &PlaceholderIdentifier::MinQueryOnIdx2,
                &query_bounds.min_query_secondary,
            ),
            (
                &PlaceholderIdentifier::MaxQueryOnIdx2,
                &query_bounds.max_query_secondary,
            ),
        ]
        .into_iter()
        .chain(
            sorted_placeholder_ids
                .iter()
                .map(|id| (id, placeholder_values.get(id).unwrap())),
        )
        // pad placeholder ids and values with the first items in the arrays, as expected by the circuit
        .chain(repeat((
            &PlaceholderIdentifier::MinQueryOnIdx1,
            &query_bounds.min_query_primary,
        )))
        .take(MAX_NUM_PLACEHOLDERS)
        .map(|(id, value)| {
            let id: F = id.to_field();
            (id, *value)
        })
        .unzip();
        let dummy_placeholder = dummy_placeholder(query_bounds);
        let placeholder_pairs = placeholder_hash_ids
            .into_iter()
            .map(|id| {
                let value = if id == dummy_placeholder.id {
                    dummy_placeholder.value
                } else {
                    let value = placeholder_values.get(&id);
                    ensure!(value.is_some(), "no placeholder found for id {:?}", id);
                    *value.unwrap()
                };
                Ok((id.to_field(), value))
            })
            .collect::<Result<Vec<_>>>()?;

        let placeholder_pos = placeholder_pairs
            .iter()
            .map(|(lookup_id, value)| {
                // locate placeholder with id `lookup_id` in `padded_placeholder_ids`
                let pos = padded_placeholder_ids
                    .iter()
                    .find_position(|id| **id == *lookup_id);
                ensure!(
                    pos.is_some(),
                    "placeholder with id {:?} not found in padded placeholder ids",
                    lookup_id
                );
                // sanity check: `padded_placeholder_values[pos] = value`
                assert_eq!(&padded_placeholder_values[pos.unwrap().0], value,);
                Ok(pos.unwrap().0)
            })
            .collect::<Result<Vec<_>>>()?;
        let revelation_circuit = RevelationWithoutResultsTreeCircuit {
            num_placeholders,
            placeholder_ids: padded_placeholder_ids.try_into().unwrap(),
            placeholder_values: padded_placeholder_values.try_into().unwrap(),
            placeholder_pos: placeholder_pos.try_into().unwrap(),
            placeholder_pairs: placeholder_pairs.try_into().unwrap(),
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
    [(); <PoseidonHash as Hasher<F>>::HASH_SIZE]:,
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

    pub(crate) fn get_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        &self.circuit_set
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloy::primitives::U256;
    use itertools::Itertools;
    use mp2_common::{
        array::ToField,
        proof::{serialize_proof, ProofWithVK},
        types::HashOutput,
        utils::{Fieldable, ToFields},
        C, D, F,
    };
    use mp2_test::{log::init_logging, utils::gen_random_u256};
    use plonky2::{
        field::types::PrimeField64, hash::hash_types::HashOut, plonk::config::GenericHashOut,
    };
    use rand::{thread_rng, Rng};
    use recursion_framework::framework_testing::TestingRecursiveCircuits;

    use crate::{
        ivc::PublicInputs as PreprocessingPI,
        query::{
            aggregation::{
                tests::{random_aggregation_operations, random_aggregation_public_inputs},
                QueryBounds, QueryHashNonExistenceCircuits,
            },
            api::CircuitInput as QueryInput,
            computational_hash_ids::{
                AggregationOperation, Identifiers, Operation, PlaceholderIdentifier,
            },
            public_inputs::{PublicInputs as QueryPI, QueryPublicInputs},
            universal_circuit::{
                universal_circuit_inputs::{
                    BasicOperation, ColumnCell, InputOperand, OutputItem, ResultStructure,
                },
                universal_query_circuit::placeholder_hash,
                PlaceholderHash,
            },
        },
        revelation::{
            api::{CircuitInput, Parameters},
            tests::{compute_results_from_query_proof, random_original_tree_proof},
            PublicInputs, NUM_PREPROCESSING_IO, NUM_QUERY_IO,
        },
    };

    #[test]
    fn test_api() {
        init_logging();
        const MAX_NUM_OUTPUTS: usize = 3;
        const MAX_NUM_ITEMS_PER_OUTPUT: usize = 5;
        const MAX_NUM_PLACEHOLDERS: usize = 15;
        const MAX_NUM_COLUMNS: usize = 20;
        const MAX_NUM_PREDICATE_OPS: usize = 20;
        const MAX_NUM_RESULT_OPS: usize = 20;
        const NUM_COLUMNS: usize = 4;
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

        let rng = &mut thread_rng();

        // generate query proof public inputs. Employ a simple query for test:
        // SELECT AVG(C1*C2), COUNT(C3/$1) FROM T WHERE C4 < $2 AND C1 >= 42 AND C1 < 77
        let column_cells = (0..NUM_COLUMNS)
            .map(|_| ColumnCell::new(rng.gen(), gen_random_u256(rng)))
            .collect_vec();
        let placeholder_ids = [0, 1].map(|i| PlaceholderIdentifier::GenericPlaceholder(i));
        let predicate_operations = vec![
            // C4 < $2
            BasicOperation::new_binary_operation(
                InputOperand::Column(3),
                InputOperand::Placeholder(placeholder_ids[1]),
                Operation::LessThanOp,
            ),
        ];
        let result_operations = vec![
            // C1*C2
            BasicOperation::new_binary_operation(
                InputOperand::Column(0),
                InputOperand::Column(1),
                Operation::MulOp,
            ),
            // C3/$1
            BasicOperation::new_binary_operation(
                InputOperand::Column(2),
                InputOperand::Placeholder(placeholder_ids[0]),
                Operation::DivOp,
            ),
        ];
        let output_items = vec![OutputItem::ComputedValue(0), OutputItem::ComputedValue(1)];
        let aggregation_ops = vec![
            AggregationOperation::AvgOp.to_id() as u64,
            AggregationOperation::CountOp.to_id() as u64,
        ];
        let ops_ids = aggregation_ops
            .iter()
            .map(|id| id.to_field())
            .chain(random_aggregation_operations::<MAX_NUM_ITEMS_PER_OUTPUT>())
            .take(MAX_NUM_ITEMS_PER_OUTPUT)
            .collect_vec();
        let results = ResultStructure::new_for_query_with_aggregation(
            result_operations,
            output_items,
            aggregation_ops,
        );
        let placeholder_values = placeholder_ids
            .iter()
            .map(|id| (*id, gen_random_u256(rng)))
            .collect::<HashMap<_, _>>();
        let query_bounds = QueryBounds::new(U256::from(42), U256::from(76), None, None);

        let placeholder_hash_ids = QueryInput::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_ITEMS_PER_OUTPUT,
        >::ids_for_placeholder_hash(
            &column_cells,
            &predicate_operations,
            &results,
            &placeholder_values,
            &query_bounds,
        )
        .unwrap();

        // generate the computational hash and placeholder hash that should be exposed by query proofs
        let QueryHashNonExistenceCircuits {
            computational_hash,
            placeholder_hash,
        } = QueryHashNonExistenceCircuits::new::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_ITEMS_PER_OUTPUT,
        >(
            &column_cells,
            &predicate_operations,
            &results,
            &placeholder_values,
            &query_bounds,
            false, // we need to generate values as if we are in an index tree node
        )
        .unwrap();

        let [mut query_pi_raw] = random_aggregation_public_inputs::<1, MAX_NUM_ITEMS_PER_OUTPUT>(
            &ops_ids.try_into().unwrap(),
        );
        let [min_query_range, max_query_range, p_hash_range, c_hash_range] = [
            QueryPublicInputs::MinQuery,
            QueryPublicInputs::MaxQuery,
            QueryPublicInputs::PlaceholderHash,
            QueryPublicInputs::ComputationalHash,
        ]
        .map(QueryPI::<F, MAX_NUM_ITEMS_PER_OUTPUT>::to_range);

        // Set the minimum, maximum query, placeholder hash andn computational hash to expected values.
        [
            (min_query_range, query_bounds.min_query_primary.to_fields()),
            (max_query_range, query_bounds.max_query_primary.to_fields()),
            (p_hash_range, placeholder_hash.to_vec()),
            (c_hash_range, computational_hash.to_vec()),
        ]
        .into_iter()
        .for_each(|(range, fields)| query_pi_raw[range].copy_from_slice(&fields));

        let query_pi = QueryPI::<F, MAX_NUM_ITEMS_PER_OUTPUT>::from_slice(&query_pi_raw);
        // generate preprocessing proof public inputs
        let preprocessing_pi_raw = random_original_tree_proof(&query_pi);

        // generate query proof
        let [query_proof] = query_circuits
            .generate_input_proofs::<1>([query_pi_raw.clone().try_into().unwrap()])
            .unwrap();
        let [query_vk] = query_circuits.verifier_data_for_input_proofs::<1>();
        let query_proof = ProofWithVK::from((query_proof, query_vk.clone()))
            .serialize()
            .unwrap();
        // generate pre-processing proof
        let [preprocessing_proof] = preprocessing_circuits
            .generate_input_proofs::<1>([preprocessing_pi_raw.try_into().unwrap()])
            .unwrap();
        let preprocessing_pi = PreprocessingPI::from_slice(&preprocessing_proof.public_inputs);
        let preprocessing_proof = serialize_proof(&preprocessing_proof).unwrap();

        let input = CircuitInput::new_revelation_no_results_tree(
            query_proof,
            preprocessing_proof,
            &query_bounds,
            &placeholder_values,
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
            (placeholder_values.len() + 4).to_field(),
        );
        // check that each placeholder value in `pi.placeholder_values` is either found in placeholder values or it is a query bound
        let expected_values = [
            query_bounds.min_query_primary,
            query_bounds.max_query_primary,
            query_bounds.min_query_secondary,
            query_bounds.max_query_secondary,
        ]
        .into_iter()
        .chain(placeholder_values.values().cloned())
        .collect_vec();
        assert!(pi.placeholder_values().into_iter().all(|value| {
            expected_values
                .iter()
                .any(|expected_val| *expected_val == value)
        }));
        // check entry count
        assert_eq!(query_pi.num_matching_rows(), pi.entry_count(),);
        // check results and overflow
        let (result, overflow) = compute_results_from_query_proof(&query_pi);
        assert_eq!(pi.num_results().to_canonical_u64(), 1,);
        assert_eq!(pi.result_values()[0], result,);
        assert_eq!(pi.overflow_flag(), overflow,);
        // check computational hash
        // first, compute the final computational hash
        let column_ids = column_cells
            .iter()
            .map(|cell| cell.id.to_canonical_u64())
            .collect_vec();
        let metadata_hash = HashOut::<F>::from_partial(preprocessing_pi.metadata_hash());
        let computational_hash = Identifiers::computational_hash(
            &column_ids,
            &predicate_operations,
            &results,
            &HashOutput::try_from(metadata_hash.to_bytes()).unwrap(),
        )
        .unwrap();
        // then, check that it is the same exposed by the proof
        assert_eq!(
            HashOutput::try_from(pi.computational_hash().to_bytes()).unwrap(),
            computational_hash,
        )
    }
}
