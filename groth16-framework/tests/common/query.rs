//! Generate the query proof for testing.

use super::{
    utils::{write_plonky2_proof, write_query_input, write_query_output},
    TestContext, TestQueryInput, TestQueryOutput,
};
use alloy::primitives::B256;
use itertools::Itertools;
use mp2_common::{
    proof::{serialize_proof, ProofWithVK},
    F,
};
use plonky2::field::types::PrimeField64;
use rand::thread_rng;
use verifiable_db::{
    query::api::CircuitInput as QueryInput,
    revelation::{api::CircuitInput, PublicInputs as RevelationPI},
    test_utils::{
        TestRevelationData, MAX_NUM_COLUMNS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_OUTPUTS,
        MAX_NUM_PLACEHOLDERS, MAX_NUM_PREDICATE_OPS, MAX_NUM_RESULT_OPS,
    },
};

impl TestContext {
    /// Generate a testing query proof.
    // The main code is copied from the revelation API test.
    pub(crate) fn generate_query_proof(&self, asset_dir: &str) -> Vec<u8> {
        let rng = &mut thread_rng();

        // Generate the testing data for revelation circuit.
        let min_block_number = 42;
        let max_block_number = 76;
        let test_data = TestRevelationData::sample(min_block_number, max_block_number);

        // Generate the query proof.
        let [query_proof] = self
            .query_circuits
            .generate_input_proofs::<1>([test_data.query_pi_raw().try_into().unwrap()])
            .unwrap();
        let [query_vk] = self.query_circuits.verifier_data_for_input_proofs::<1>();
        let query_proof = ProofWithVK::from((query_proof, query_vk.clone()))
            .serialize()
            .unwrap();

        // Generate the preprocessing proof.
        let [preprocessing_proof] = self
            .preprocessing_circuits
            .generate_input_proofs::<1>([test_data.preprocessing_pi_raw().try_into().unwrap()])
            .unwrap();
        let preprocessing_proof = serialize_proof(&preprocessing_proof).unwrap();

        // Generate the revelation proof.
        let input = CircuitInput::new_revelation_no_results_tree(
            query_proof,
            preprocessing_proof,
            test_data.query_bounds(),
            test_data.placeholders(),
            test_data.predicate_operations(),
            test_data.results(),
        )
        .unwrap();
        let revelation_proof = self
            .revelation_params
            .generate_proof(input, self.query_circuits.get_recursive_circuit_set(), None)
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
            h.iter()
                .flat_map(|u| {
                    // Each field of the packed Keccak hash is an u32.
                    let u = u.to_canonical_u64();
                    assert!(u <= u32::MAX as u64);

                    (u as u32).to_be_bytes()
                })
                .collect_vec()
        });
        // Revert the bytes in each Uint32 of block hash to make consistent with
        // the block hash onchain.
        let block_hash = block_hash
            .chunks(4)
            .flat_map(|bytes| {
                let mut bytes = bytes.to_vec();
                bytes.reverse();
                bytes
            })
            .collect_vec();
        let [block_hash, computational_hash] =
            [block_hash, computational_hash].map(|bytes| B256::from_slice(&bytes));
        let query_input = TestQueryInput {
            query_limit,
            query_offset,
            min_block_number,
            max_block_number,
            block_hash,
            computational_hash,
            user_placeholders: test_data.user_placeholders().to_vec(),
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
