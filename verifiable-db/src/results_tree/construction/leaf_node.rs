//! Module handling the leaf node of the results tree for query circuits

use crate::results_tree::construction::public_inputs::PublicInputs;
use anyhow::Result;
use mp2_common::{
    poseidon::{empty_poseidon_hash, H},
    public_inputs::PublicInputCommon,
    types::CBuilder,
    utils::ToTargets,
    D, F,
};
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::proof::ProofWithPublicInputsTarget,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::{iter, slice};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafNodeWires<const S: usize>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafNodeCircuit<const S: usize>;

impl<const S: usize> LeafNodeCircuit<S> {
    pub fn build(b: &mut CBuilder, subtree_proof: &PublicInputs<Target, S>) -> LeafNodeWires<S> {
        let empty_hash = b.constant_hash(*empty_poseidon_hash()).to_targets();

        let tree_hash = subtree_proof.to_tree_hash_raw();
        let index_ids = subtree_proof.index_ids_target();
        let primary_index_value = subtree_proof.to_primary_index_value_raw();

        // Compute the node hash:
        // H(H("") || H("") || p.I || p.I || p.index_ids[0] || p.I || p.H)
        let inputs = empty_hash
            .iter()
            .chain(&empty_hash)
            .chain(primary_index_value)
            .chain(primary_index_value)
            .chain(iter::once(&index_ids[0]))
            .chain(primary_index_value)
            .chain(tree_hash)
            .cloned()
            .collect();
        let node_hash = b.hash_n_to_hash_no_pad::<H>(inputs);

        // Register the public inputs.
        PublicInputs::<_, S>::new(
            &node_hash.to_targets(),
            primary_index_value,
            primary_index_value,
            subtree_proof.to_min_items_raw(),
            subtree_proof.to_max_items_raw(),
            slice::from_ref(subtree_proof.to_min_counter_raw()),
            slice::from_ref(subtree_proof.to_max_counter_raw()),
            primary_index_value,
            subtree_proof.to_index_ids_raw(),
            slice::from_ref(subtree_proof.to_no_duplicates_raw()),
            subtree_proof.to_accumulator_raw(),
        )
        .register(b);

        LeafNodeWires
    }
}

/// Subtree proof number = 1
pub(crate) const NUM_VERIFIED_PROOFS: usize = 1;

impl<const S: usize> CircuitLogicWires<F, D, NUM_VERIFIED_PROOFS> for LeafNodeWires<S> {
    type CircuitBuilderParams = ();
    type Inputs = LeafNodeCircuit<S>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F, S>::total_len();

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; NUM_VERIFIED_PROOFS],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        // The first one is the subtree proof.
        let subtree_proof = PublicInputs::from_slice(&verified_proofs[0].public_inputs);

        Self::Inputs::build(builder, &subtree_proof)
    }

    fn assign_input(&self, _inputs: Self::Inputs, _pw: &mut PartialWitness<F>) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::results_tree::construction::{
        tests::random_results_construction_public_inputs, PI_LEN,
    };
    use mp2_common::{utils::ToFields, C};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{iop::witness::WitnessWrite, plonk::config::Hasher};

    const S: usize = 20;

    #[derive(Clone, Debug)]
    struct TestLeafNodeCircuit<'a> {
        subtree_proof: &'a [F],
    }

    impl UserCircuit<F, D> for TestLeafNodeCircuit<'_> {
        // Circuit wires + subtree proof
        type Wires = (LeafNodeWires<S>, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let subtree_proof = b.add_virtual_target_arr::<{ PI_LEN::<S> }>().to_vec();
            let subtree_pi = PublicInputs::<Target, S>::from_slice(&subtree_proof);

            let wires = LeafNodeCircuit::build(b, &subtree_pi);

            (wires, subtree_proof)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.1, self.subtree_proof);
        }
    }

    #[test]
    fn test_results_construction_leaf_node() {
        // Generate the subtree proof.
        let [subtree_proof] = random_results_construction_public_inputs::<1, S>();
        let subtree_pi = PublicInputs::<_, S>::from_slice(&subtree_proof);

        // Construct the test circuit.
        let test_circuit = TestLeafNodeCircuit {
            subtree_proof: &subtree_proof,
        };

        // Prove for the test circuit.
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::<_, S>::from_slice(&proof.public_inputs);

        // Check the public inputs.
        // Tree hash
        {
            let empty_hash = empty_poseidon_hash().to_fields();
            let tree_hash = subtree_pi.to_tree_hash_raw();
            let primary_index_value = subtree_pi.to_primary_index_value_raw();
            let index_ids = subtree_pi.index_ids();

            // H(H("") || H("") || p.I || p.I || p.index_ids[0] || p.I || p.H)
            let inputs: Vec<_> = empty_hash
                .iter()
                .chain(empty_hash.iter())
                .chain(primary_index_value)
                .chain(primary_index_value)
                .chain(iter::once(&index_ids[0]))
                .chain(primary_index_value)
                .chain(tree_hash)
                .cloned()
                .collect();
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.tree_hash(), exp_hash);
        }
        // Minimum value
        assert_eq!(pi.min_value(), subtree_pi.primary_index_value());
        // Maximum value
        assert_eq!(pi.max_value(), subtree_pi.primary_index_value());
        // Minimum items
        assert_eq!(pi.min_items(), subtree_pi.min_items());
        // Maximum items
        assert_eq!(pi.max_items(), subtree_pi.max_items());
        // Minimum counter
        assert_eq!(pi.min_counter(), subtree_pi.min_counter());
        // Maximum counter
        assert_eq!(pi.max_counter(), subtree_pi.max_counter());
        // Primary index value
        assert_eq!(pi.primary_index_value(), subtree_pi.primary_index_value());
        // Index IDs
        assert_eq!(pi.index_ids(), subtree_pi.index_ids());
        // No duplicates flag
        assert_eq!(pi.no_duplicates_flag(), subtree_pi.no_duplicates_flag());
        // Accumulator
        assert_eq!(pi.accumulator(), subtree_pi.accumulator());
    }
}
