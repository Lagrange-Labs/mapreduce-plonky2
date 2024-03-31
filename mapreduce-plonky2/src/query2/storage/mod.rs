//! The module implementing the required mechanisms for ‶Query 2″
//! https://www.notion.so/lagrangelabs/Cryptographic-Documentation-85adb821f18647b2a3dc65efbe144981?pvs=4#fa3f5d23a7724d0699a04f72bbec2a16

use anyhow::Result;
use plonky2::{
    field::goldilocks_field::GoldilocksField, hash::hash_types::HashOut,
    plonk::config::GenericHashOut,
};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{RecursiveCircuitInfo, RecursiveCircuits},
};
use serde::{Deserialize, Serialize};

use crate::{
    api::{default_config, ProofWithVK, C, D, F},
    eth::left_pad32,
    utils::convert_u8_to_u32_slice,
};

use self::{
    full_inner::{FullInnerNodeCircuit, FullInnerNodeWires},
    leaf::{LeafCircuit, LeafWires},
    partial_inner::{PartialInnerNodeCircuit, PartialInnerNodeWires},
    public_inputs::PublicInputs,
};

mod full_inner;
mod leaf;
mod partial_inner;
pub mod public_inputs;

pub enum CircuitInput {
    Leaf(LeafCircuit),
    PartialInner(PartialInnerNodeCircuit, ProofWithVK),
    FullInner((ProofWithVK, ProofWithVK)),
}

impl CircuitInput {
    pub fn new_leaf(mapping_key: &[u8], mapping_value: &[u8]) -> Self {
        let mk = convert_u8_to_u32_slice(&left_pad32(mapping_key));
        let mv = convert_u8_to_u32_slice(&left_pad32(mapping_value));
        CircuitInput::Leaf(LeafCircuit {
            mapping_key: mk.try_into().unwrap(),
            mapping_value: mv.try_into().unwrap(),
        })
    }

    pub fn new_partial_node(left: &[u8], right: &[u8], proved_is_right: bool) -> Self {
        let proof = ProofWithVK::deserialize(if proved_is_right { right } else { left })
            .expect("unable to deserialize proof");
        let unproved_hash = HashOut::from_bytes(if proved_is_right { left } else { right });

        CircuitInput::PartialInner(
            PartialInnerNodeCircuit {
                proved_is_right,
                unproved_hash,
            },
            proof,
        )
    }

    pub fn new_full_node(left_proof: &[u8], right_proof: &[u8]) -> Self {
        let left = ProofWithVK::deserialize(left_proof).expect("unable to deserialize proof");
        let right = ProofWithVK::deserialize(right_proof).expect("unable to deserialize proof");
        CircuitInput::FullInner((left, right))
    }
}

const STORAGE_CIRCUIT_SET_SIZE: usize = 3;
const NUM_IO: usize = PublicInputs::<GoldilocksField>::TOTAL_LEN;

#[derive(Serialize, Deserialize)]
pub struct Parameters {
    leaf_circuit: CircuitWithUniversalVerifier<F, C, D, 0, LeafWires>,
    partial_node_circuit: CircuitWithUniversalVerifier<F, C, D, 1, PartialInnerNodeWires>,
    full_node_circuit: CircuitWithUniversalVerifier<F, C, D, 2, FullInnerNodeWires>,
    set: RecursiveCircuits<F, C, D>,
}

impl Parameters {
    pub fn build() -> Self {
        let config = default_config();
        let circuit_builder = CircuitWithUniversalVerifierBuilder::<F, D, NUM_IO>::new::<C>(
            config,
            STORAGE_CIRCUIT_SET_SIZE,
        );
        let leaf_circuit = circuit_builder.build_circuit::<C, 0, LeafWires>(());
        let partial_node_circuit = circuit_builder.build_circuit::<C, 1, PartialInnerNodeWires>(());
        let full_node_circuit = circuit_builder.build_circuit::<C, 2, FullInnerNodeWires>(());

        let circuit_set = vec![
            leaf_circuit.get_verifier_data().circuit_digest,
            partial_node_circuit.get_verifier_data().circuit_digest,
            full_node_circuit.get_verifier_data().circuit_digest,
        ];

        Self {
            leaf_circuit,
            partial_node_circuit,
            full_node_circuit,
            set: RecursiveCircuits::new_from_circuit_digests(circuit_set),
        }
    }

    pub fn generate_proof(&self, input: CircuitInput) -> Result<Vec<u8>> {
        match input {
            CircuitInput::Leaf(leaf) => {
                let proof = self.set.generate_proof(&self.leaf_circuit, [], [], leaf)?;
                ProofWithVK {
                    proof,
                    vk: self.leaf_circuit.get_verifier_data().clone(),
                }
            }
            CircuitInput::PartialInner(partial_inner, inner) => {
                let proof = self.set.generate_proof(
                    &self.partial_node_circuit,
                    [inner.proof],
                    [&inner.vk],
                    partial_inner,
                )?;

                ProofWithVK {
                    proof,
                    vk: self.partial_node_circuit.get_verifier_data().clone(),
                }
            }
            CircuitInput::FullInner((left, right)) => {
                let proof = self.set.generate_proof(
                    &self.full_node_circuit,
                    [left.proof, right.proof],
                    [&left.vk, &right.vk],
                    FullInnerNodeCircuit {},
                )?;

                ProofWithVK {
                    proof,
                    vk: self.full_node_circuit.get_verifier_data().clone(),
                }
            }
        }
        .serialize()
    }

    pub(crate) fn get_storage_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        &self.set
    }
}

#[cfg(test)]
mod tests;
