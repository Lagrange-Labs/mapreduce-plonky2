//! Generate the query proof for testing.

use super::{
    utils::{write_plonky2_proof, write_query_input, write_query_output},
    TestContext, TestQueryInput, TestQueryOutput, MAX_NUM_COLUMNS, MAX_NUM_ITEMS_PER_OUTPUT,
    MAX_NUM_OUTPUTS, MAX_NUM_PLACEHOLDERS, MAX_NUM_PREDICATE_OPS, MAX_NUM_RESULT_OPS,
    VALID_NUM_COLUMNS,
};
use alloy::primitives::{B256, U256};
use itertools::Itertools;
use mp2_common::{
    proof::{serialize_proof, ProofWithVK},
    utils::{Fieldable, ToFields},
    F,
};
use mp2_test::utils::gen_random_u256;
use plonky2::{field::types::PrimeField64, plonk::config::GenericHashOut};
use rand::{thread_rng, Rng};
use verifiable_db::{
    query::{
        aggregation::{
            random_aggregation_operations, random_aggregation_public_inputs, QueryBounds,
            QueryHashNonExistenceCircuits,
        },
        api::CircuitInput as QueryInput,
        computational_hash_ids::{AggregationOperation, Operation, PlaceholderIdentifier},
        public_inputs::{PublicInputs as QueryPI, QueryPublicInputs},
        universal_circuit::universal_circuit_inputs::{
            BasicOperation, ColumnCell, InputOperand, OutputItem, Placeholders, ResultStructure,
            RowCells,
        },
    },
    revelation::{api::CircuitInput, random_original_tree_proof, PublicInputs as RevelationPI},
};

impl TestContext {
    /// Generate a testing query proof.
    // The main code is copied from the revelation API test.
    pub(crate) fn generate_query_proof(&self, asset_dir: &str) -> Vec<u8> {
        let rng = &mut thread_rng();

        // Generate the query proof public inputs. Employ a simple query for test:
        // SELECT AVG(C1*C2), COUNT(C3/$1) FROM T WHERE C4 < $2 AND C1 >= 42 AND C1 < 77
        let [min_block_number, max_block_number] = [42, 77];
        let column_cells = (0..VALID_NUM_COLUMNS)
            .map(|_| ColumnCell::new(rng.gen(), gen_random_u256(rng)))
            .collect_vec();
        let row_cells = RowCells::new(&column_cells[0], &column_cells[1], &column_cells[2..]);
        let placeholder_ids = [0, 1].map(PlaceholderIdentifier::GenericPlaceholder);
        let user_placeholders = [0; 2].map(|_| gen_random_u256(rng)).to_vec();
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
        let placeholders = Placeholders::from((
            placeholder_ids
                .into_iter()
                .zip_eq(user_placeholders.iter().cloned())
                .collect(),
            U256::from(min_block_number),
            U256::from(max_block_number),
        ));
        let query_bounds = QueryBounds::new(&placeholders, None, None).unwrap();

        let placeholder_hash_ids = QueryInput::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_ITEMS_PER_OUTPUT,
        >::ids_for_placeholder_hash(
            &row_cells,
            &predicate_operations,
            &results,
            &placeholders,
            &query_bounds,
        )
        .unwrap();

        // Generate the computational hash and placeholder hash that should be exposed by query proofs.
        let QueryHashNonExistenceCircuits {
            computational_hash,
            placeholder_hash,
        } = QueryHashNonExistenceCircuits::new::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_ITEMS_PER_OUTPUT,
        >(
            &row_cells,
            &predicate_operations,
            &results,
            &placeholders,
            &query_bounds,
            // we need to generate values as if we are in an index tree node.
            false,
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

        // Generate the preprocessing proof public inputs.
        let preprocessing_pi_raw = random_original_tree_proof(&query_pi);

        // Generate the query proof.
        let [query_proof] = self
            .query_circuits
            .generate_input_proofs::<1>([query_pi_raw.clone().try_into().unwrap()])
            .unwrap();
        let [query_vk] = self.query_circuits.verifier_data_for_input_proofs::<1>();
        let query_proof = ProofWithVK::from((query_proof, query_vk.clone()))
            .serialize()
            .unwrap();

        // Generate the preprocessing proof.
        let [preprocessing_proof] = self
            .preprocessing_circuits
            .generate_input_proofs::<1>([preprocessing_pi_raw.try_into().unwrap()])
            .unwrap();
        let preprocessing_proof = serialize_proof(&preprocessing_proof).unwrap();

        // Generate the revelation proof.
        let input = CircuitInput::new_revelation_no_results_tree(
            query_proof,
            preprocessing_proof,
            &query_bounds,
            &placeholders,
            placeholder_hash_ids,
        )
        .unwrap();
        let revelation_proof = self
            .revelation_params
            .generate_proof(input, self.query_circuits.get_recursive_circuit_set())
            .unwrap();
        let revelation_proof = ProofWithVK::deserialize(&revelation_proof).unwrap();
        let (revelation_proof_with_pi, _) = revelation_proof.clone().into();
        let revelation_pi = RevelationPI::<
            F,
            MAX_NUM_OUTPUTS,
            MAX_NUM_ITEMS_PER_OUTPUT,
            MAX_NUM_PLACEHOLDERS,
        >::from_slice(&revelation_proof_with_pi.public_inputs);

        // Generate and save the final wrapped proof.
        let final_proof = self
            .wrap_circuit
            .generate_proof(self.revelation_params.get_circuit_set(), &revelation_proof)
            .unwrap();
        write_plonky2_proof(asset_dir, &final_proof);

        // Save the testing query input.
        let [query_limit, query_offset] =
            [revelation_pi.query_limit(), revelation_pi.query_offset()].map(|u| {
                let u = u.to_canonical_u64();
                assert!(u <= u32::MAX as u64);

                u as u32
            });
        let [block_hash, computational_hash] = [
            revelation_pi.original_block_hash(),
            revelation_pi.flat_computational_hash(),
        ]
        .map(|h| {
            B256::from_slice(
                &h.iter()
                    .flat_map(|u| {
                        // Each field of the packed Keccak hash is an u32.
                        let u = u.to_canonical_u64();
                        assert!(u <= u32::MAX as u64);

                        (u as u32).to_be_bytes()
                    })
                    .collect_vec(),
            )
        });
        let query_input = TestQueryInput {
            query_limit,
            query_offset,
            min_block_number,
            max_block_number,
            block_hash,
            computational_hash,
            user_placeholders,
        };
        write_query_input(asset_dir, &query_input);

        // Save the testing query output.
        let entry_count = revelation_pi.entry_count().to_canonical_u64();
        let num_results = revelation_pi.num_results().to_canonical_u64();
        assert!(entry_count <= u32::MAX as u64);
        assert!(num_results <= u32::MAX as u64);
        let total_matched_rows = entry_count as u32;
        let rows = revelation_pi.result_values()[..num_results as usize].to_vec();
        let query_output = TestQueryOutput {
            total_matched_rows,
            rows,
        };
        write_query_output(asset_dir, &query_output);

        final_proof
    }
}
