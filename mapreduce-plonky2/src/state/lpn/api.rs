use plonky2::{iop::{target::Target, witness::PartialWitness}, plonk::circuit_data::{VerifierCircuitData, VerifierOnlyCircuitData}};
use recursion_framework::{circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder}, framework::{prepare_recursive_circuit_for_circuit_set, RecursiveCircuitInfo, RecursiveCircuits}};
use serde::{Deserialize, Serialize};

use crate::api::{deserialize_proof, get_config, ProofWithVK};

use super::{leaf::LeafCircuitWires, node::NodeCircuitWires, StateInputs};

use anyhow::Result;

const STATE_CIRCUIT_SET_SIZE: usize = 2;

type F = crate::api::F;
type C = crate::api::C;
const D: usize = crate::api::D;
#[derive(Serialize, Deserialize)]
/// Parameters representing the circuits employed to build the provable
/// state DB of LPN
pub struct Parameters {
    leaf: CircuitWithUniversalVerifier<F, C, D, 0, LeafCircuitWires>,
    node: CircuitWithUniversalVerifier<F, C, D, 2, NodeCircuitWires>,
    set: RecursiveCircuits<F, C, D>,
}

impl Parameters {
    /// Build parameters for circuits related to the state DB of LPN
    pub(crate) fn build(block_linking_circuit_vd: VerifierCircuitData<F, C, D>) -> Self {
        let builder = CircuitWithUniversalVerifierBuilder::<
            F, 
            D, 
            {StateInputs::<Target>::TOTAL_LEN}
        >::new::<C>(
            get_config(), 
            STATE_CIRCUIT_SET_SIZE,
        );
        let leaf = builder.build_circuit(block_linking_circuit_vd);
        let node = builder.build_circuit(());

        let set = RecursiveCircuits::new(vec![
            prepare_recursive_circuit_for_circuit_set(&leaf),
            prepare_recursive_circuit_for_circuit_set(&node),
        ]);

        Self {
            leaf,
            node,
            set,
        }        
    }

    pub(crate) fn generate_proof(&self, input: ProofInputs) -> Result<Vec<u8>> {
        let mut pw = PartialWitness::<F>::new();
        let proof_with_vk: ProofWithVK = match input {
            ProofInputs::Leaf(input) => {
                let proof = self.set.generate_proof(
                    &self.leaf,
                    [],
                    [],
                    input,
                )?;
                (
                    proof,
                    self.leaf.get_verifier_data().clone()
                ).into()
            },
            ProofInputs::Node((left_proof, right_proof)) => {
                let (left_proof, left_vd) = left_proof.into();
                let (right_proof, right_vd) = right_proof.into();
                let proof = self.set.generate_proof(
                    &self.node, 
                    [left_proof, right_proof], 
                    [&left_vd, &right_vd], 
                    ()
                )?;
                (
                    proof,
                    self.node.get_verifier_data().clone()
                ).into()
            }
        };
        proof_with_vk.serialize()
    }
}

pub(crate) enum ProofInputs {
    Leaf(ProofWithVK),
    Node((ProofWithVK, ProofWithVK))
}

impl ProofInputs {
    pub(crate) fn build_leaf_input(
        block_linking_proof: Vec<u8>, 
        block_linking_vd: &VerifierOnlyCircuitData<C, D>
    ) -> Result<Self> {
        let proof = deserialize_proof(&block_linking_proof)?;
        let proof_with_vk = (proof, block_linking_vd.clone()).into();
        Ok(ProofInputs::Leaf(proof_with_vk))
    }

    pub(crate) fn build_node_input(
        left_children: Vec<u8>,
        right_children: Vec<u8>,
    ) -> Result<Self> {
        Ok(
            ProofInputs::Node((
                ProofWithVK::deserialize(&left_children)?,
                ProofWithVK::deserialize(&right_children)?,
            ))
        )
    }
}

pub struct NodeInputs {
    left: Vec<u8>,
    right: Vec<u8>,
}

impl NodeInputs {
    pub fn new(left_proof: Vec<u8>, right_proof: Vec<u8>) -> Self {
        Self {
            left: left_proof,
            right: right_proof,
        }
    }
}

pub enum CircuitInput {
    Leaf(Vec<u8>),
    Node(NodeInputs),
}

#[cfg(test)]
mod tests {
    use std::array;

    use plonky2::field::types::Sample;

    use crate::{api::tests::TestDummyCircuit, state::{lpn::public_inputs, BlockLinkingInputs}};

    use super::*;


    const NUM_PUBLIC_INPUTS: usize = BlockLinkingInputs::<Target>::TOTAL_LEN;


    fn generate_leaf_proof_from_public_inputs(
        circuit_params: &Parameters,
        dummy_circuit: &TestDummyCircuit<NUM_PUBLIC_INPUTS>,
        public_inputs: [F; NUM_PUBLIC_INPUTS]
    ) -> Result<Vec<u8>> {
        let block_linking_proof = dummy_circuit.generate_proof(public_inputs).unwrap();
        let block_linking_proof = (
            block_linking_proof,
            dummy_circuit.circuit_data().verifier_only.clone(),
        ).into();
        circuit_params.generate_proof(ProofInputs::Leaf(block_linking_proof))

    }

    #[test]
    fn test_leaf_circuit() {
        let block_linking_dummy_circuit = TestDummyCircuit::<NUM_PUBLIC_INPUTS>::build();
        let state_circuit_params = Parameters::build(
            block_linking_dummy_circuit.circuit_data().verifier_data(),
        );

        // generate block linking proof
        let block_linking_pi = array::from_fn(|_|
            F::rand()
        );

        let left_proof = generate_leaf_proof_from_public_inputs(
            &state_circuit_params, 
            &block_linking_dummy_circuit, 
            block_linking_pi
        ).unwrap();
        
        state_circuit_params.leaf.circuit_data().verify(
            ProofWithVK::deserialize(&left_proof).unwrap().get_proof().clone(),
        ).unwrap()
    }

    #[test]
    fn test_state_circuit_parameters() {
        let block_linking_dummy_circuit = TestDummyCircuit::<NUM_PUBLIC_INPUTS>::build();
        let state_circuit_params = Parameters::build(
            block_linking_dummy_circuit.circuit_data().verifier_data(),
        );

        // generate block linking public inputs for leaf proofs
        let block_linking_pi = array::from_fn(|_|
            F::rand()
        );
        // generate block linking proof for lefth children
        let left_proof = generate_leaf_proof_from_public_inputs(
            &state_circuit_params, 
            &block_linking_dummy_circuit, 
            block_linking_pi
        ).unwrap();

        state_circuit_params.leaf.circuit_data().verify(
            ProofWithVK::deserialize(&left_proof).unwrap().get_proof().clone(),
        ).unwrap();
        
        // generate block linking proof for right children, employing the same set of block linking public inputs
        // for simplicity
        let right_proof = generate_leaf_proof_from_public_inputs(
            &state_circuit_params, 
            &block_linking_dummy_circuit, 
            block_linking_pi
        ).unwrap();

        state_circuit_params.leaf.circuit_data().verify(
            ProofWithVK::deserialize(&right_proof).unwrap().get_proof().clone(),
        ).unwrap();

        // build proof for intermediate node
        let intermediate_proof = state_circuit_params.generate_proof(
            ProofInputs::build_node_input(left_proof, right_proof).unwrap()
        ).unwrap();

        state_circuit_params.node.circuit_data().verify(
            ProofWithVK::deserialize(&intermediate_proof).unwrap().get_proof().clone(),
        ).unwrap();
        
    }
}