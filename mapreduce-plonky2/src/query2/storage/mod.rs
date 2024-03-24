//! The module implementing the required mechanisms for ‶Query 2″
//! https://www.notion.so/lagrangelabs/Cryptographic-Documentation-85adb821f18647b2a3dc65efbe144981?pvs=4#fa3f5d23a7724d0699a04f72bbec2a16

use anyhow::Result;
use plonky2::iop::target::Target;
use recursion_framework::circuit_builder::CircuitWithUniversalVerifier;
use serde::{Deserialize, Serialize};

use crate::{
    api::{ProofWithVK, C, D, F},
    array::Array,
    eth::left_pad32,
    mpt_sequential::Circuit,
};

mod full_inner;
mod leaf;
mod partial_inner;
pub(crate) mod public_inputs;

pub enum CircuitInput {
    Leaf(leaf::LeafCircuit),
    PartialInner(ProofWithVK),
    FullInner((ProofWithVK, ProofWithVK)),
}

impl CircuitInput {
    pub fn new_leaf(mapping_key: &[u8], mapping_value: &[u8]) -> Self {
        let mk = left_pad32(mapping_key);
        let mv = left_pad32(mapping_value);
        CircuitInput::Leaf(leaf::LeafCircuit {
            mapping_key: mk,
            mapping_value: mv,
        })
    }

    pub fn new_partial_node(child_proof: Vec<u8>) -> Self {
        let proof = ProofWithVK::deserialize(&child_proof).expect("unable to deserialize proof");
        CircuitInput::PartialInner(proof)
    }

    pub fn new_full_node(left_proof: Vec<u8>, right_proof: Vec<u8>) -> Self {
        let left = ProofWithVK::deserialize(&left_proof).expect("unable to deserialize proof");
        let right = ProofWithVK::deserialize(&right_proof).expect("unable to deserialize proof");
        CircuitInput::FullInner((left, right))
    }
}

#[derive(Serialize, Deserialize)]
pub struct Parameters {
    //leaf_circuit: CircuitWithUniversalVerifier<F, C, D, 0, leaf::LeafWires>,
    //partial_node_circuit:
    //    CircuitWithUniversalVerifier<F, C, D, 1, partial_inner::PartialInnerNodeWires>,
    //full_node_circuit: CircuitWithUniversalVerifier<F, C, D, 2, NodeWires>,
    //set: RecursiveCircuits<F, C, D>,
}

impl Parameters {
    pub fn build() -> Self {
        todo!()
    }

    pub fn generate_proof(&self, input: CircuitInput) -> Result<Vec<u8>> {
        todo!()
    }
}

#[cfg(test)]
mod tests;

// TODO: use 32B for address for now, see later if we prefer 20B
type AddressTarget = Array<Target, 32>;
