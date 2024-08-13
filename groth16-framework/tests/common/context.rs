//! Testing context used in the cases

use super::{
    MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_OUTPUTS, MAX_NUM_PLACEHOLDERS, MAX_NUM_PREDICATE_OPS,
    MAX_NUM_RESULT_OPS, NUM_PREPROCESSING_IO, NUM_QUERY_IO,
};
use groth16_framework::{compile_and_generate_assets, utils::clone_circuit_data};
use mp2_common::{C, D, F};
use recursion_framework::framework_testing::TestingRecursiveCircuits;
use verifiable_db::{api::WrapCircuitParams, revelation::api::Parameters as RevelationParameters};

/// Test context
pub(crate) struct TestContext {
    pub(crate) preprocessing_circuits: TestingRecursiveCircuits<F, C, D, NUM_PREPROCESSING_IO>,
    pub(crate) query_circuits: TestingRecursiveCircuits<F, C, D, NUM_QUERY_IO>,
    pub(crate) revelation_params: RevelationParameters<
        MAX_NUM_OUTPUTS,
        MAX_NUM_ITEMS_PER_OUTPUT,
        MAX_NUM_PLACEHOLDERS,
        { 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS) },
    >,
    pub(crate) wrap_circuit:
        WrapCircuitParams<MAX_NUM_OUTPUTS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_PLACEHOLDERS>,
}

impl TestContext {
    /// Create the test context.
    pub(crate) fn new() -> Self {
        // Generate a fake preprocessing circuit set.
        let preprocessing_circuits =
            TestingRecursiveCircuits::<F, C, D, NUM_PREPROCESSING_IO>::default();

        // Generate a fake query circuit set.
        let query_circuits = TestingRecursiveCircuits::<F, C, D, NUM_QUERY_IO>::default();

        // Create the revelation parameters.
        let revelation_params = RevelationParameters::<
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

        // Create the wrap circuit.
        let wrap_circuit = WrapCircuitParams::<
            MAX_NUM_OUTPUTS,
            MAX_NUM_ITEMS_PER_OUTPUT,
            MAX_NUM_PLACEHOLDERS,
        >::build(revelation_params.get_circuit_set());

        Self {
            preprocessing_circuits,
            query_circuits,
            revelation_params,
            wrap_circuit,
        }
    }

    /// Generate the Groth16 asset files.
    pub(crate) fn generate_assets(&self, asset_dir: &str) {
        let circuit_data = clone_circuit_data(self.wrap_circuit.circuit_data()).unwrap();

        compile_and_generate_assets(circuit_data, asset_dir)
            .expect("Failed to generate the Groth16 asset files");
    }
}
