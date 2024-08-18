//! Module handling the leaf full node of the index tree for query aggregation circuits

use crate::query::public_inputs::PublicInputs;
use alloy::primitives::U256;
use anyhow::Result;
use mp2_common::{
    poseidon::{empty_poseidon_hash, H},
    public_inputs::PublicInputCommon,
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::ToTargets,
    D, F,
};
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::proof::ProofWithPublicInputsTarget,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::iter;

/// Leaf wires
/// The constant generic parameter is only used for impl `CircuitLogicWires`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullNodeIndexLeafWires<const MAX_NUM_RESULTS: usize> {
    min_query: UInt256Target,
    max_query: UInt256Target,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullNodeIndexLeafCircuit<const MAX_NUM_RESULTS: usize> {
    /// Minimum range bound specified in the query for the indexed column
    pub(crate) min_query: U256,
    /// Maximum range bound specified in the query for the indexed column
    pub(crate) max_query: U256,
}

impl<const MAX_NUM_RESULTS: usize> FullNodeIndexLeafCircuit<MAX_NUM_RESULTS> {
    pub fn build(
        b: &mut CBuilder,
        subtree_proof: &PublicInputs<Target, MAX_NUM_RESULTS>,
    ) -> FullNodeIndexLeafWires<MAX_NUM_RESULTS> {
        let ttrue = b._true();
        let empty_hash = b.constant_hash(*empty_poseidon_hash());
        let empty_hash_targets = empty_hash.to_targets();

        let [min_query, max_query] = [0; 2].map(|_| b.add_virtual_u256());

        let index_ids = subtree_proof.index_ids_target();
        let index_value = subtree_proof.index_value_target();
        let index_value_targets = subtree_proof.to_index_value_raw();

        // Ensure the value of the indexed column for all the records stored in the
        // subtree found in this node is within the range specified by the query:
        // p.I >= MIN_query AND p.I <= MAX_query
        let is_not_less_than_min = b.is_less_or_equal_than_u256(&min_query, &index_value);
        let is_not_greater_than_max = b.is_less_or_equal_than_u256(&index_value, &max_query);
        let is_in_range = b.and(is_not_less_than_min, is_not_greater_than_max);
        b.connect(is_in_range.target, ttrue.target);

        // Compute the node hash:
        // node_hash = H(H("") || H("") || p.I || p.I || p.index_ids[0] || p.I || p.H))
        let inputs = empty_hash_targets
            .iter()
            .chain(empty_hash_targets.iter())
            .chain(index_value_targets)
            .chain(index_value_targets)
            .chain(iter::once(&index_ids[0]))
            .chain(index_value_targets)
            .cloned()
            .chain(subtree_proof.tree_hash_target().to_targets())
            .collect();
        let node_hash = b.hash_n_to_hash_no_pad::<H>(inputs);

        // Register the public inputs.
        PublicInputs::<_, MAX_NUM_RESULTS>::new(
            &node_hash.to_targets(),
            subtree_proof.to_values_raw(),
            &[subtree_proof.num_matching_rows_target()],
            subtree_proof.to_ops_raw(),
            index_value_targets,
            index_value_targets,
            index_value_targets,
            subtree_proof.to_index_ids_raw(),
            &min_query.to_targets(),
            &max_query.to_targets(),
            &[*subtree_proof.to_overflow_raw()],
            subtree_proof.to_computational_hash_raw(),
            subtree_proof.to_placeholder_hash_raw(),
        )
        .register(b);

        FullNodeIndexLeafWires {
            min_query,
            max_query,
        }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &FullNodeIndexLeafWires<MAX_NUM_RESULTS>) {
        pw.set_u256_target(&wires.min_query, self.min_query);
        pw.set_u256_target(&wires.max_query, self.max_query);
    }
}

/// Subtree proof number = 1, child proof number = 0
pub(crate) const NUM_VERIFIED_PROOFS: usize = 1;

impl<const MAX_NUM_RESULTS: usize> CircuitLogicWires<F, D, NUM_VERIFIED_PROOFS>
    for FullNodeIndexLeafWires<MAX_NUM_RESULTS>
{
    type CircuitBuilderParams = ();
    type Inputs = FullNodeIndexLeafCircuit<MAX_NUM_RESULTS>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F, MAX_NUM_RESULTS>::total_len();

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; NUM_VERIFIED_PROOFS],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        // The first one is the subtree proof.
        let subtree_proof = PublicInputs::from_slice(&verified_proofs[0].public_inputs);

        Self::Inputs::build(builder, &subtree_proof)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{
        aggregation::{
            random_aggregation_operations, random_aggregation_public_inputs,
            utils::tests::unify_subtree_proof,
        },
        PI_LEN,
    };
    use mp2_common::{utils::ToFields, C};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{iop::witness::WitnessWrite, plonk::config::Hasher};

    const MAX_NUM_RESULTS: usize = 20;

    #[derive(Clone, Debug)]
    struct TestFullNodeIndexLeafCircuit<'a> {
        c: FullNodeIndexLeafCircuit<MAX_NUM_RESULTS>,
        subtree_proof: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestFullNodeIndexLeafCircuit<'a> {
        // Circuit wires + subtree proof
        type Wires = (FullNodeIndexLeafWires<MAX_NUM_RESULTS>, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let subtree_proof = b
                .add_virtual_target_arr::<{ PI_LEN::<MAX_NUM_RESULTS> }>()
                .to_vec();
            let subtree_pi = PublicInputs::<Target, MAX_NUM_RESULTS>::from_slice(&subtree_proof);

            let wires = FullNodeIndexLeafCircuit::build(b, &subtree_pi);

            (wires, subtree_proof)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);
            pw.set_target_arr(&wires.1, self.subtree_proof);
        }
    }

    #[test]
    fn test_query_agg_full_node_index_leaf() {
        let min_query = U256::from(100);
        let max_query = U256::from(200);

        // Generate the subtree proof.
        let ops: [_; MAX_NUM_RESULTS] = random_aggregation_operations();
        let [mut subtree_proof] = random_aggregation_public_inputs(&ops);
        unify_subtree_proof::<MAX_NUM_RESULTS>(&mut subtree_proof, false, min_query, max_query);
        let subtree_pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&subtree_proof);

        let index_value = subtree_pi.index_value();
        let index_value_fields = subtree_pi.to_index_value_raw();
        let index_ids = subtree_pi.index_ids();

        // Construct the test circuit.
        let test_circuit = TestFullNodeIndexLeafCircuit {
            c: FullNodeIndexLeafCircuit {
                min_query,
                max_query,
            },
            subtree_proof: &subtree_proof,
        };

        // Prove for the test circuit.
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&proof.public_inputs);

        // Check the public inputs.
        // Tree hash
        {
            // H(H("") || H("") || p.I || p.I || p.index_ids[0] || p.I || p.H))
            let empty_hash = empty_poseidon_hash();
            let empty_hash_fields = empty_hash.to_fields();
            let inputs: Vec<_> = empty_hash_fields
                .iter()
                .chain(empty_hash_fields.iter())
                .chain(index_value_fields)
                .chain(index_value_fields)
                .chain(iter::once(&index_ids[0]))
                .chain(index_value_fields)
                .chain(subtree_pi.to_hash_raw())
                .cloned()
                .collect();
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.tree_hash(), exp_hash);
        }
        // Output values
        assert_eq!(pi.to_values_raw(), subtree_pi.to_values_raw());
        // Count
        assert_eq!(pi.num_matching_rows(), subtree_pi.num_matching_rows());
        // Operation IDs
        assert_eq!(pi.operation_ids(), subtree_pi.operation_ids());
        // Index value
        assert_eq!(pi.index_value(), index_value);
        // Minimum value
        assert_eq!(pi.min_value(), index_value);
        // Maximum value
        assert_eq!(pi.max_value(), index_value);
        // Index IDs
        assert_eq!(pi.index_ids(), index_ids);
        // Minimum query
        assert_eq!(pi.min_query_value(), min_query);
        // Maximum query
        assert_eq!(pi.max_query_value(), max_query);
        // Overflow flag
        assert_eq!(pi.overflow_flag(), subtree_pi.overflow_flag());
        // Computational hash
        assert_eq!(pi.computational_hash(), subtree_pi.computational_hash());
        // Placeholder hash
        assert_eq!(pi.placeholder_hash(), subtree_pi.placeholder_hash());
    }
}
