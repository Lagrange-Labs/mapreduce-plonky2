use mp2_v1::{
    api::{generate_proof, CircuitInput},
    values_extraction::planner::{Extractable, ExtractionUpdatePlan, MP2PlannerError},
};
use ryhope::storage::updatetree::Next;

use super::TestContext;

impl TestContext {
    /// Method to run the plan to completion locally. For each item in the [`UpdatePlan`](ryhope::storage::updatetree::UpdatePlan) we fetch the data from [`self.proof_cache`](ExtractionUpdatePlan::proof_cache)
    /// convert the [`ProofData`](mp2_v1::values_extraction::planner::ProofData) to a [`CircuitInput`] which we then pass to the [`generate_proof`] function defined in [`mp2_v1::api`]. We then take the output proof
    /// and if the current key has a parent node in [`self.update_tree`](ExtractionUpdatePlan::update_tree) we update the [`ProofData`](mp2_v1::values_extraction::planner::ProofData) stored for this key. If no parent is present we must be at the root of the tree
    /// and so we just return the final proof.
    pub fn prove_extractable<E: Extractable>(
        &self,
        plan: &mut ExtractionUpdatePlan<E>,
        extractable: &E,
    ) -> Result<Vec<u8>, MP2PlannerError> {
        let params = self.params();
        // Convert the UpdateTree into an UpdatePlan
        let mut update_plan = plan.update_tree.clone().into_workplan();
        // Instantiate a vector that will eventually be the output.
        let mut final_proof = Vec::<u8>::new();
        // Run the loop while the UpdatePlan continues to yield tasks.
        while let Some(Next::Ready(work_plan_item)) = update_plan.next() {
            // Retrieve proof data related to this key
            let proof_data = plan.proof_cache.get(work_plan_item.k()).ok_or(
                MP2PlannerError::UpdateTreeError("Key not present in the proof cache".to_string()),
            )?;
            // Convert to CircuitInput
            let circuit_type =
                CircuitInput::ValuesExtraction(E::to_circuit_input(extractable, proof_data));

            // Generate the proof
            let proof = generate_proof(params, circuit_type).map_err(|e| {
                MP2PlannerError::ProvingError(format!(
                    "Error while generating proof for node {{ inner: {:?} }}",
                    e
                ))
            })?;

            // Fetch the parent of this key
            let parent = plan.update_tree.get_parent_key(work_plan_item.k());
            // Determine next steps based on whether the parent exists
            match parent {
                Some(parent_key) => {
                    let proof_data_ref = plan.proof_cache.get_mut(&parent_key).unwrap();
                    proof_data_ref.update(proof)?
                }
                None => {
                    final_proof = proof;
                }
            }
            // Mark the item as done
            update_plan.done(&work_plan_item)?;
        }
        Ok(final_proof)
    }
}
