use std::{array, cmp::Ordering, collections::BTreeSet, fmt::Debug, iter::repeat};

use alloy::primitives::U256;
use anyhow::{ensure, Result};

use itertools::Itertools;
use mp2_common::{
    default_config,
    poseidon::H,
    proof::{deserialize_proof, ProofWithVK},
    u256::is_less_than_or_equal_to_u256_arr,
    C, D, F,
};
use plonky2::{
    field::types::PrimeField64,
    plonk::{circuit_data::VerifierOnlyCircuitData, config::Hasher, proof::ProofWithPublicInputs},
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
        self,
        aggregation::QueryBounds,
        api::{CircuitInput as QueryCircuitInput, Parameters as QueryParams},
        computational_hash_ids::ColumnIDs,
        universal_circuit::universal_circuit_inputs::{
            BasicOperation, Placeholders, ResultStructure,
        },
        PI_LEN as QUERY_PI_LEN,
    },
    revelation::{
        placeholders_check::CheckPlaceholderGadget,
        revelation_unproven_offset::{
            generate_dummy_row_proof_inputs,
            RecursiveCircuitWires as RecursiveCircuitWiresUnprovenOffset,
        },
    },
};

use super::{
    revelation_unproven_offset::{
        RecursiveCircuitInputs as RecursiveCircuitInputsUnporvenOffset,
        RevelationCircuit as RevelationCircuitUnprovenOffset, RowPath,
    },
    revelation_without_results_tree::{
        CircuitBuilderParams, RecursiveCircuitInputs, RecursiveCircuitWires,
        RevelationWithoutResultsTreeCircuit,
    },
    NUM_QUERY_IO, PI_LEN,
};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Data structure employed to provide input data related to a matching row
/// for the revelation circuit with unproven offset
pub struct MatchingRow {
    proof: Vec<u8>,
    path: RowPath,
    result: Vec<U256>,
}

impl MatchingRow {
    /// Instantiate a new `MatchingRow` from the following inputs:
    /// - `proof`: proof for the matching row, generated with the universal query circuit
    /// - `path`: Data employed to verify the membership of the row in the tree
    /// - `result`: Set of results associated to this row, to be exposed as outputs of the query
    pub fn new(proof: Vec<u8>, path: RowPath, result: Vec<U256>) -> Self {
        Self {
            proof,
            path,
            result,
        }
    }
}

impl PartialOrd for MatchingRow {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MatchingRow {
    fn cmp(&self, other: &Self) -> Ordering {
        let (left, right) = match self.result.len().cmp(&other.result.len()) {
            Ordering::Less => {
                let target_len = other.result.len();
                (
                    self.result
                        .iter()
                        .chain(repeat(&U256::default()))
                        .take(target_len)
                        .cloned()
                        .collect_vec(),
                    other.result.clone(),
                )
            }
            Ordering::Equal => (self.result.clone(), other.result.clone()),
            Ordering::Greater => {
                let target_len = self.result.len();
                (
                    self.result.clone(),
                    other
                        .result
                        .iter()
                        .chain(repeat(&U256::default()))
                        .take(target_len)
                        .cloned()
                        .collect_vec(),
                )
            }
        };
        let (is_smaller, is_eq) = is_less_than_or_equal_to_u256_arr(&left, &right);
        if is_smaller {
            return Ordering::Less;
        }
        if is_eq {
            return Ordering::Equal;
        }
        Ordering::Greater
    }
}

#[derive(Debug, Serialize, Deserialize)]
/// Parameters for revelation circuits. The following const generic values need to be specified:
/// - `ROW_TREE_MAX_DEPTH`: upper bound on the depth of a rows tree for Lagrange DB tables
/// - `INDEX_TREE_MAX_DEPTH`: upper bound on the depth of an index tree for Lagrange DB tables
/// - `MAX_NUM_COLUMNS`: upper bound on the number of columns of a table
/// - `MAX_NUM_PREDICATE_OPS`: upper bound on the number of basic operations allowed in the `WHERE` clause of a query
/// - `MAX_NUM_RESULT_OPS`: upper bound on the number of basic operations allowed in the `SELECT` statement of a query
/// - `MAX_NUM_OUTPUTS`: upper bound on the number of output rows which can be exposed as public outputs of the circuit
/// - `MAX_NUM_ITEMS_PER_OUTPUT`: upper bound on the number of items per output row; should correspond to the
///     upper bound on the number of items being found in `SELECT` statement of a query
/// - `MAX_NUM_PLACEHOLDERS`: upper bound on the number of placeholders we allow in a query
/// - `NUM_PLACEHOLDERS_HASHED`: number of placeholders being hashed in the placeholder hash
pub struct Parameters<
    const ROW_TREE_MAX_DEPTH: usize,
    const INDEX_TREE_MAX_DEPTH: usize,
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_OUTPUTS: usize,
    const MAX_NUM_ITEMS_PER_OUTPUT: usize,
    const MAX_NUM_PLACEHOLDERS: usize,
> where
    [(); MAX_NUM_ITEMS_PER_OUTPUT - 1]:,
    [(); NUM_QUERY_IO::<MAX_NUM_ITEMS_PER_OUTPUT>]:,
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); MAX_NUM_ITEMS_PER_OUTPUT * MAX_NUM_OUTPUTS]:,
    [(); 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS)]:,
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
            { 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS) },
        >,
    >,
    revelation_unproven_offset: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        0,
        RecursiveCircuitWiresUnprovenOffset<
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_OUTPUTS,
            MAX_NUM_ITEMS_PER_OUTPUT,
            MAX_NUM_PLACEHOLDERS,
            { 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS) },
        >,
    >,
    //ToDo: add revelation circuit with results tree
    circuit_set: RecursiveCircuits<F, C, D>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Circuit inputs for revelation circuits. The following const generic values need to be specified:
/// - `ROW_TREE_MAX_DEPTH`: upper bound on the depth of a rows tree for Lagrange DB tables
/// - `INDEX_TREE_MAX_DEPTH`: upper bound on the depth of an index tree for Lagrange DB tables
/// - `MAX_NUM_COLUMNS`: upper bound on the number of columns of a table
/// - `MAX_NUM_PREDICATE_OPS`: upper bound on the number of basic operations allowed in the `WHERE` clause of a query
/// - `MAX_NUM_RESULT_OPS`: upper bound on the number of basic operations allowed in the `SELECT` statement of a query
/// - `MAX_NUM_OUTPUTS`: upper bound on the number of output rows which can be exposed as public outputs of the circuit
/// - `MAX_NUM_ITEMS_PER_OUTPUT`: upper bound on the number of items per output row; should correspond to the
///     upper bound on the number of items being found in `SELECT` statement of the query
/// - `MAX_NUM_PLACEHOLDERS`: upper bound on the number of placeholders we allow in a query
/// - `NUM_PLACEHOLDERS_HASHED`: number of placeholders being hashed in the placeholder hash
pub enum CircuitInput<
    const ROW_TREE_MAX_DEPTH: usize,
    const INDEX_TREE_MAX_DEPTH: usize,
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_OUTPUTS: usize,
    const MAX_NUM_ITEMS_PER_OUTPUT: usize,
    const MAX_NUM_PLACEHOLDERS: usize,
> where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); MAX_NUM_ITEMS_PER_OUTPUT * MAX_NUM_OUTPUTS]:,
    [(); 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS)]:,
{
    NoResultsTree {
        query_proof: ProofWithVK,
        preprocessing_proof: ProofWithPublicInputs<F, C, D>,
        revelation_circuit: RevelationWithoutResultsTreeCircuit<
            MAX_NUM_OUTPUTS,
            MAX_NUM_ITEMS_PER_OUTPUT,
            MAX_NUM_PLACEHOLDERS,
            { 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS) },
        >,
    },
    UnprovenOffset {
        row_proofs: Vec<ProofWithVK>,
        preprocessing_proof: ProofWithPublicInputs<F, C, D>,
        revelation_circuit: RevelationCircuitUnprovenOffset<
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_OUTPUTS,
            MAX_NUM_ITEMS_PER_OUTPUT,
            MAX_NUM_PLACEHOLDERS,
            { 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS) },
        >,
        dummy_row_proof_input: Option<
            QueryCircuitInput<
                MAX_NUM_COLUMNS,
                MAX_NUM_PREDICATE_OPS,
                MAX_NUM_RESULT_OPS,
                MAX_NUM_ITEMS_PER_OUTPUT,
            >,
        >,
    }, //ToDo: add circuit input for revelation circuit with results tree
}

impl<
        const ROW_TREE_MAX_DEPTH: usize,
        const INDEX_TREE_MAX_DEPTH: usize,
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_PREDICATE_OPS: usize,
        const MAX_NUM_RESULT_OPS: usize,
        const MAX_NUM_OUTPUTS: usize,
        const MAX_NUM_ITEMS_PER_OUTPUT: usize,
        const MAX_NUM_PLACEHOLDERS: usize,
    >
    CircuitInput<
        ROW_TREE_MAX_DEPTH,
        INDEX_TREE_MAX_DEPTH,
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_OUTPUTS,
        MAX_NUM_ITEMS_PER_OUTPUT,
        MAX_NUM_PLACEHOLDERS,
    >
where
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); MAX_NUM_ITEMS_PER_OUTPUT * MAX_NUM_OUTPUTS]:,
    [(); MAX_NUM_ITEMS_PER_OUTPUT - 1]:,
    [(); QUERY_PI_LEN::<MAX_NUM_ITEMS_PER_OUTPUT>]:,
    [(); 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS)]:,
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
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
    pub fn new_revelation_aggregated(
        query_proof: Vec<u8>,
        preprocessing_proof: Vec<u8>,
        query_bounds: &QueryBounds,
        placeholders: &Placeholders,
        predicate_operations: &[BasicOperation],
        results_structure: &ResultStructure,
    ) -> Result<Self> {
        let query_proof = ProofWithVK::deserialize(&query_proof)?;
        let preprocessing_proof = deserialize_proof(&preprocessing_proof)?;
        let placeholder_hash_ids = query::api::CircuitInput::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_ITEMS_PER_OUTPUT,
        >::ids_for_placeholder_hash(
            predicate_operations,
            results_structure,
            placeholders,
            query_bounds,
        )?;
        let revelation_circuit = RevelationWithoutResultsTreeCircuit {
            check_placeholder: CheckPlaceholderGadget::new(
                query_bounds,
                placeholders,
                placeholder_hash_ids,
            )?,
        };

        Ok(CircuitInput::NoResultsTree {
            query_proof,
            preprocessing_proof,
            revelation_circuit,
        })
    }

    /// Initialize circuit inputs for the revelation circuit for queries with unproven offset.
    /// The method requires the following inputs:
    /// - `preprocessing_proof`: Proof of construction of the tree over which the query was performed, generated with the
    ///     IVC set of circuit
    /// - `matching_rows`: Data about the matching rows employed to compute the results of the query; they have to be at
    ///     most `MAX_NUM_OUTPUTS`
    /// - `query_bounds`: bounds on values of primary and secondary indexes specified in the query
    /// - `placeholders`: set of placeholders employed in the query. They must be less than `MAX_NUM_PLACEHOLDERS`
    /// - `placeholder_hash_ids`: Identifiers of the placeholders employed to compute the placeholder hash; they can be
    ///     obtained by the method `ids_for_placeholder_hash` of `query::api::Parameters`
    /// - `column_ids`: Ids of the columns of the original table
    /// - `predicate_operations`: Operations employed in the query to compute the filtering predicate in the `WHERE` clause
    /// - `results_structure`: Data about the operations and items returned in the `SELECT` clause of the query
    /// - `limit, offset`: limit and offset values specified in the query
    /// - `distinct`: Flag specifying whether the DISTINCT keyword was specified in the query
    pub fn new_revelation_tabular(
        preprocessing_proof: Vec<u8>,
        matching_rows: Vec<MatchingRow>,
        query_bounds: &QueryBounds,
        placeholders: &Placeholders,
        column_ids: &ColumnIDs,
        predicate_operations: &[BasicOperation],
        results_structure: &ResultStructure,
        limit: u64,
        offset: u64,
    ) -> Result<Self>
    where
        [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
        [(); 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS)]:,
    {
        let preprocessing_proof = deserialize_proof(&preprocessing_proof)?;
        ensure!(
            matching_rows.len() <= MAX_NUM_OUTPUTS,
            "Number of matching rows bigger than the maximum number of outputs"
        );
        let dummy_row_proof_input = if matching_rows.len() < MAX_NUM_OUTPUTS {
            // we need to generate inputs to prove a dummy row, employed to pad the matching rows provided as input
            // to `MAX_NUM_OUTPUTS`
            Some(generate_dummy_row_proof_inputs(
                column_ids,
                predicate_operations,
                results_structure,
                placeholders,
                query_bounds,
            )?)
        } else {
            None
        };
        // sort matching rows according to result values, which is needed to enforce DISTINCT
        let matching_rows = matching_rows.into_iter().collect::<BTreeSet<_>>();
        let mut row_paths = array::from_fn(|_| RowPath::default());
        let mut result_values =
            array::from_fn(|_| vec![U256::default(); results_structure.output_ids.len()]);
        let row_proofs = matching_rows
            .iter()
            .enumerate()
            .map(|(i, row)| {
                row_paths[i] = row.path.clone();
                result_values[i] = row.result.clone();
                ProofWithVK::deserialize(&row.proof)
            })
            .collect::<Result<Vec<_>>>()?;
        let placeholder_hash_ids = query::api::CircuitInput::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_ITEMS_PER_OUTPUT,
        >::ids_for_placeholder_hash(
            predicate_operations,
            results_structure,
            placeholders,
            query_bounds,
        )?;
        let placeholder_inputs =
            CheckPlaceholderGadget::new(query_bounds, placeholders, placeholder_hash_ids)?;
        let index_ids = [
            column_ids.primary.to_canonical_u64(),
            column_ids.secondary.to_canonical_u64(),
        ];
        let revelation_circuit = RevelationCircuitUnprovenOffset::new(
            row_paths,
            index_ids,
            &results_structure.output_ids,
            result_values,
            limit,
            offset,
            results_structure.distinct.unwrap_or(false),
            placeholder_inputs,
        )?;

        Ok(Self::UnprovenOffset {
            row_proofs,
            preprocessing_proof,
            revelation_circuit,
            dummy_row_proof_input,
        })
    }
}

const REVELATION_CIRCUIT_SET_SIZE: usize = 2;
impl<
        const ROW_TREE_MAX_DEPTH: usize,
        const INDEX_TREE_MAX_DEPTH: usize,
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_PREDICATE_OPS: usize,
        const MAX_NUM_RESULT_OPS: usize,
        const MAX_NUM_OUTPUTS: usize,
        const MAX_NUM_ITEMS_PER_OUTPUT: usize,
        const MAX_NUM_PLACEHOLDERS: usize,
    >
    Parameters<
        ROW_TREE_MAX_DEPTH,
        INDEX_TREE_MAX_DEPTH,
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_OUTPUTS,
        MAX_NUM_ITEMS_PER_OUTPUT,
        MAX_NUM_PLACEHOLDERS,
    >
where
    [(); MAX_NUM_ITEMS_PER_OUTPUT - 1]:,
    [(); NUM_QUERY_IO::<MAX_NUM_ITEMS_PER_OUTPUT>]:,
    [(); <H as Hasher<F>>::HASH_SIZE]:,
    [(); PI_LEN::<MAX_NUM_OUTPUTS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_PLACEHOLDERS>]:,
    [(); ROW_TREE_MAX_DEPTH - 1]:,
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
    [(); MAX_NUM_ITEMS_PER_OUTPUT * MAX_NUM_OUTPUTS]:,
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
    [(); QUERY_PI_LEN::<MAX_NUM_ITEMS_PER_OUTPUT>]:,
    [(); 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS)]:,
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
        let revelation_no_results_tree = builder.build_circuit(build_parameters.clone());
        let revelation_unproven_offset = builder.build_circuit(build_parameters);

        let circuits = vec![
            prepare_recursive_circuit_for_circuit_set(&revelation_no_results_tree),
            prepare_recursive_circuit_for_circuit_set(&revelation_unproven_offset),
        ];

        let circuit_set = RecursiveCircuits::new(circuits);

        Self {
            revelation_no_results_tree,
            revelation_unproven_offset,
            circuit_set,
        }
    }

    pub fn generate_proof(
        &self,
        input: CircuitInput<
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_OUTPUTS,
            MAX_NUM_ITEMS_PER_OUTPUT,
            MAX_NUM_PLACEHOLDERS,
        >,
        query_circuit_set: &RecursiveCircuits<F, C, D>,
        query_params: Option<
            &QueryParams<
                MAX_NUM_COLUMNS,
                MAX_NUM_PREDICATE_OPS,
                MAX_NUM_RESULT_OPS,
                MAX_NUM_ITEMS_PER_OUTPUT,
            >,
        >,
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
            CircuitInput::UnprovenOffset {
                row_proofs,
                preprocessing_proof,
                revelation_circuit,
                dummy_row_proof_input,
            } => {
                let row_proofs = if let Some(input) = dummy_row_proof_input {
                    let proof = query_params.unwrap().generate_proof(input)?;
                    let proof = ProofWithVK::deserialize(&proof)?;
                    row_proofs
                        .into_iter()
                        .chain(repeat(proof))
                        .take(MAX_NUM_OUTPUTS)
                        .collect_vec()
                        .try_into()
                        .unwrap()
                } else {
                    row_proofs.try_into().unwrap()
                };
                let input = RecursiveCircuitInputsUnporvenOffset {
                    inputs: revelation_circuit,
                    row_proofs,
                    preprocessing_proof,
                    query_circuit_set: query_circuit_set.clone(),
                };
                (
                    self.circuit_set.generate_proof(
                        &self.revelation_unproven_offset,
                        [],
                        [],
                        input,
                    )?,
                    self.revelation_unproven_offset.get_verifier_data().clone(),
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

        const ROW_TREE_MAX_DEPTH: usize = 10;
        const INDEX_TREE_MAX_DEPTH: usize = 15;

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
            ROW_TREE_MAX_DEPTH,
            INDEX_TREE_MAX_DEPTH,
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_OUTPUTS,
            MAX_NUM_ITEMS_PER_OUTPUT,
            MAX_NUM_PLACEHOLDERS,
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

        let input = CircuitInput::new_revelation_aggregated(
            query_proof,
            preprocessing_proof,
            test_data.query_bounds(),
            test_data.placeholders(),
            test_data.predicate_operations(),
            test_data.results(),
        )
        .unwrap();
        let proof = params
            .generate_proof(input, query_circuits.get_recursive_circuit_set(), None)
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
