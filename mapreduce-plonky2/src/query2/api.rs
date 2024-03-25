use plonky2::field::goldilocks_field::GoldilocksField;
use serde::{Deserialize, Serialize};

use super::{block, revelation, state, storage};

const SINGLE_CONTRACT_DEPTH: usize = 0;
/// L is the number of elements we allow to expose in the result
pub enum CircuitInput<const L: usize> {
    Storage(storage::CircuitInput),
    State(state::StateCircuit<SINGLE_CONTRACT_DEPTH, GoldilocksField>),
    Block(block::CircuitInput),
    Revelation(revelation::RevelationCircuit<L>),
}

const MAX_BLOCK_DEPTH: usize = 0;

#[derive(Serialize, Deserialize)]
pub struct Parameters<const L: usize> {
    storage: storage::Parameters,
    state: state::Parameters,
    block: block::Parameters,
    revelation: revelation::Parameters<MAX_BLOCK_DEPTH, L>,
}

impl<const L: usize> Parameters<L> {
    pub fn build() -> Self {
        todo!()
    }
    pub fn generate_proof(&self, input: CircuitInput<L>) -> Vec<u8> {
        todo!()
    }
}
