use std::ops::Index;

use anyhow::Result;
use ethers::types::U256;
use mp2_common::F;
use mp2_v1::api::ProofWithVK;
use serde::Deserialize;

use super::{
    full_node::FullNodeCircuit, leaf::LeafCircuit, partial_node::PartialNodeCircuit, IndexTuple,
};

pub struct Parameters {}

impl Parameters {}

/// Enum holding all the inputs necessary to generate
/// rows tree related proofs
pub enum CircuitInput {
    Leaf(LeafInput),
    Full(FullNodeInput),
    Partial(PartialNodeCircuit),
}

impl CircuitInput {
    pub fn leaf(identifier: F, value: U256, cells_proof: Vec<u8>) -> Result<Self> {
        let circuit = LeafCircuit::new(IndexTuple::new(identifier, value));
        let proof = ProofWithVK::deserialize(&cells_proof)?;
        Ok(CircuitInput::Leaf(LeafInput {
            witness: circuit,
            cells_proof: proof,
        }))
    }
    pub fn full(
        identifier: F,
        value: U256,
        left_proof: Vec<u8>,
        right_proof: Vec<u8>,
        cells_proof: Vec<u8>,
    ) -> Result<Self> {
        let left = ProofWithVK::deserialize(&left_proof)?;
        let right = ProofWithVK::deserialize(&right_proof)?;
        let cells = ProofWithVK::deserialize(&cells_proof)?;
        let circuit = FullNodeCircuit::from(IndexTuple::new(identifier, value));
        Ok(CircuitInput::Full(FullNodeInput {
            witness: circuit,
            left,
            right,
            cells,
        }))
    }
    pub fn partial(
        identifier: F,
        value: U256,
        is_child_left: bool,
        child_proof: Vec<u8>,
        cells_proof: Vec<u8>,
    ) -> Result<Self> {
        let child = ProofWithVK::deserialize(&child_proof)?;
        let cells = ProofWithVK::deserialize(&cells_proof)?;
        let tuple = IndexTuple::new(identifier, value);
        let witness = PartialNodeCircuit::new(tuple, is_child_left);
        Ok(CircuitInput::Partial(PartialNodeInput {
            witness,
            child,
            cells,
        }))
    }
}

pub struct LeafInput {
    witness: LeafCircuit,
    cells_proof: ProofWithVK,
}

pub struct FullNodeInput {
    witness: FullNodeCircuit,
    left: ProofWithVK,
    right: ProofWithVK,
    cells: ProofWithVK,
}

pub struct PartialNodeInput {
    witness: PartialNodeCircuit,
    child: ProofWithVK,
    cells: ProofWithVK,
}

#[cfg(test)]
mod test {
    #[test]
    fn try_some() {
        println!("hello");
    }
}
