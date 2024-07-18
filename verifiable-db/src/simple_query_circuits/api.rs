//! Query circuit APIs

use super::aggregation::{
    full_node_index_leaf::{self, FullNodeIndexLeafCircuit, FullNodeIndexLeafWires},
    full_node_with_one_child::{self, FullNodeWithOneChildCircuit, FullNodeWithOneChildWires},
    full_node_with_two_children::{
        self, FullNodeWithTwoChildrenCircuit, FullNodeWithTwoChildrenWires,
    },
};
use crate::simple_query_circuits::PI_LEN;
use alloy::primitives::U256;
use anyhow::Result;
use mp2_common::{default_config, proof::ProofWithVK, C, D, F};
use plonky2::{hash::poseidon::PoseidonHash, plonk::config::Hasher};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{RecursiveCircuitInfo, RecursiveCircuits},
};
use serde::{Deserialize, Serialize};
use std::array;

/// CircuitInput holding all the necessary inputs to generate the proofs
pub enum CircuitInput<const MAX_NUM_RESULTS: usize> {
    FullNodeIndexLeaf {
        witness: FullNodeIndexLeafCircuit<MAX_NUM_RESULTS>,
        base_proof: Vec<u8>,
    },
    FullNodeWithOneChild {
        witness: FullNodeWithOneChildCircuit<MAX_NUM_RESULTS>,
        base_proof: Vec<u8>,
        child_proof: Vec<u8>,
    },
    FullNodeWithTwoChildren {
        witness: FullNodeWithTwoChildrenCircuit<MAX_NUM_RESULTS>,
        base_proof: Vec<u8>,
        child_proofs: [Vec<u8>; 2],
    },
}

impl<const MAX_NUM_RESULTS: usize> CircuitInput<MAX_NUM_RESULTS> {
    /// Create a circuit input for a full node index leaf.
    pub fn full_node_index_leaf(min_query: U256, max_query: U256, base_proof: Vec<u8>) -> Self {
        Self::FullNodeIndexLeaf {
            witness: FullNodeIndexLeafCircuit {
                min_query,
                max_query,
            },
            base_proof,
        }
    }

    /// Create a circuit input for a full node with one child.
    pub fn full_node_with_one_child(
        is_rows_tree_node: bool,
        is_left_child: bool,
        min_query: U256,
        max_query: U256,
        base_proof: Vec<u8>,
        child_proof: Vec<u8>,
    ) -> Self {
        Self::FullNodeWithOneChild {
            witness: FullNodeWithOneChildCircuit {
                is_rows_tree_node,
                is_left_child,
                min_query,
                max_query,
            },
            base_proof,
            child_proof,
        }
    }

    /// Create a circuit input for a full node with two children.
    pub fn full_node_with_two_children(
        is_rows_tree_node: bool,
        min_query: U256,
        max_query: U256,
        base_proof: Vec<u8>,
        child_proofs: [Vec<u8>; 2],
    ) -> Self {
        Self::FullNodeWithTwoChildren {
            witness: FullNodeWithTwoChildrenCircuit {
                is_rows_tree_node,
                min_query,
                max_query,
            },
            base_proof,
            child_proofs,
        }
    }
}

/// Parameters holding the aggregation circuits
#[derive(Serialize, Deserialize)]
pub struct PublicParameters<const MAX_NUM_RESULTS: usize>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    full_node_index_leaf: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        { full_node_index_leaf::NUM_VERIFIED_PROOFS },
        FullNodeIndexLeafWires<MAX_NUM_RESULTS>,
    >,
    full_node_with_one_child: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        { full_node_with_one_child::NUM_VERIFIED_PROOFS },
        FullNodeWithOneChildWires<MAX_NUM_RESULTS>,
    >,
    full_node_with_two_children: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        { full_node_with_two_children::NUM_VERIFIED_PROOFS },
        FullNodeWithTwoChildrenWires<MAX_NUM_RESULTS>,
    >,
    set: RecursiveCircuits<F, C, D>,
}

// TODO: update to add more circuits
/// Number of circuits in the set
/// 1 index leaf
///     + 1 full node with one child
///     + 1 full node with two children
const CIRCUIT_SET_SIZE: usize = 3;

impl<const MAX_NUM_RESULTS: usize> PublicParameters<MAX_NUM_RESULTS>
where
    [(); MAX_NUM_RESULTS - 1]:,
    [(); PI_LEN::<MAX_NUM_RESULTS>]:,
    [(); <PoseidonHash as Hasher<F>>::HASH_SIZE]:,
{
    /// Generates the circuit parameters for the circuits.
    pub fn build() -> Self {
        let builder =
            CircuitWithUniversalVerifierBuilder::<F, D, { PI_LEN::<MAX_NUM_RESULTS> }>::new::<C>(
                default_config(),
                CIRCUIT_SET_SIZE,
            );

        let full_node_index_leaf = builder.build_circuit(());
        let full_node_with_one_child = builder.build_circuit(());
        let full_node_with_two_children = builder.build_circuit(());

        let set = RecursiveCircuits::new_from_circuit_digests(vec![
            full_node_index_leaf.get_verifier_data().circuit_digest,
            full_node_with_one_child.get_verifier_data().circuit_digest,
            full_node_with_two_children
                .get_verifier_data()
                .circuit_digest,
        ]);

        Self {
            full_node_index_leaf,
            full_node_with_one_child,
            full_node_with_two_children,
            set,
        }
    }

    /// Get the circuit set VK that is generated by this parameter.
    pub fn set_vk(&self) -> &RecursiveCircuits<F, C, D> {
        &self.set
    }

    /// Generate the proof by the circuit input.
    pub fn generate_proof(&self, input: CircuitInput<MAX_NUM_RESULTS>) -> Result<Vec<u8>> {
        match input {
            CircuitInput::FullNodeIndexLeaf {
                witness,
                base_proof,
            } => self.generate_full_node_index_leaf_proof(witness, base_proof),
            CircuitInput::FullNodeWithOneChild {
                witness,
                base_proof,
                child_proof,
            } => self.generate_full_node_with_one_child_proof(witness, base_proof, child_proof),
            CircuitInput::FullNodeWithTwoChildren {
                witness,
                base_proof,
                child_proofs,
            } => self.generate_full_node_with_two_children_proof(witness, base_proof, child_proofs),
        }
    }

    fn generate_full_node_index_leaf_proof(
        &self,
        witness: FullNodeIndexLeafCircuit<MAX_NUM_RESULTS>,
        base_proof: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let (input_proof, input_vk) = ProofWithVK::deserialize(&base_proof)?.into();

        let proof = self.set.generate_proof(
            &self.full_node_index_leaf,
            [input_proof],
            [&input_vk],
            witness,
        )?;

        ProofWithVK::new(proof, self.full_node_index_leaf.get_verifier_data().clone()).serialize()
    }

    fn generate_full_node_with_one_child_proof(
        &self,
        witness: FullNodeWithOneChildCircuit<MAX_NUM_RESULTS>,
        base_proof: Vec<u8>,
        child_proof: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let proofs = [base_proof, child_proof]
            .iter()
            .map(|p| ProofWithVK::deserialize(p))
            .collect::<Result<Vec<_>>>()?;
        let (input_proofs, input_vks): (Vec<_>, Vec<_>) =
            proofs.into_iter().map(Into::into).unzip();

        let proof = self.set.generate_proof(
            &self.full_node_with_one_child,
            input_proofs.try_into().unwrap(),
            array::from_fn(|i| &input_vks[i]),
            witness,
        )?;

        ProofWithVK::new(
            proof,
            self.full_node_with_one_child.get_verifier_data().clone(),
        )
        .serialize()
    }

    fn generate_full_node_with_two_children_proof(
        &self,
        witness: FullNodeWithTwoChildrenCircuit<MAX_NUM_RESULTS>,
        base_proof: Vec<u8>,
        child_proofs: [Vec<u8>; 2],
    ) -> Result<Vec<u8>> {
        let proofs = [&base_proof, &child_proofs[0], &child_proofs[1]]
            .iter()
            .map(|p| ProofWithVK::deserialize(p))
            .collect::<Result<Vec<_>>>()?;
        let (input_proofs, input_vks): (Vec<_>, Vec<_>) =
            proofs.into_iter().map(Into::into).unzip();

        let proof = self.set.generate_proof(
            &self.full_node_with_two_children,
            input_proofs.try_into().unwrap(),
            array::from_fn(|i| &input_vks[i]),
            witness,
        )?;

        ProofWithVK::new(
            proof,
            self.full_node_with_one_child.get_verifier_data().clone(),
        )
        .serialize()
    }
}

// TODO: add test
