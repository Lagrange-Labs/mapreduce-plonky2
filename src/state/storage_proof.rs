//! This is the public inputs of previous storage proof, it's considered as
//! inputs of the current state proving process.

use crate::{array::Array, keccak::PACKED_HASH_LEN};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use std::array;

/// The previous storage public inputs are composed of:
/// - `D` Digest of all the values processed
/// - `C1` MPT root of blockchain storage trie
/// - `C2` Merkle root of LPN’s storage database (Merkle Tree)
/// - `A` Address of smart contract
/// - `M` Storage slot of the mapping
/// - `S` Storage slot of the variable holding the length
/// D = 5*2+1, C1 = C2 = 8, A = 5, M = 8, S = 1
const D_IDX: usize = 0;
const C1_IDX: usize = 11;
const C2_IDX: usize = 19;
const A_IDX: usize = 27;
const M_IDX: usize = 32;
const S_IDX: usize = 40;
const STORAGE_INPUT_LEN: usize = 41;

/// The public input values of previous storage proof
#[derive(Clone, Debug)]
pub struct StorageInputs<F> {
    inner: Vec<F>,
}

/// The public input targets of previous storage proof
pub struct StorageInputsWires {
    inner: Array<Target, STORAGE_INPUT_LEN>,
}

impl StorageInputsWires {
    pub fn new<F, const D: usize>(cb: &mut CircuitBuilder<F, D>) -> Self
    where
        F: RichField + Extendable<D>,
    {
        Self {
            inner: Array::new(cb),
        }
    }

    /// Assign the wires.
    pub fn assign<F>(&self, pw: &mut PartialWitness<F>, value: &StorageInputs<F>)
    where
        F: RichField,
    {
        self.inner
            .assign(pw, &value.inner.clone().try_into().unwrap());
    }

    /// Get the hash of storage MPT root (C1).
    pub fn mpt_root_hash(&self) -> Array<Target, PACKED_HASH_LEN> {
        array::from_fn(|i| self.inner.arr[C1_IDX + i]).into()
    }

    /// Get the targets at D index.
    pub fn d_targets(&self) -> &[Target] {
        &self.inner.arr[D_IDX..C1_IDX]
    }

    /// Get the targets at C1 index.
    pub fn c1_targets(&self) -> &[Target] {
        &self.inner.arr[C1_IDX..C2_IDX]
    }

    /// Get the targets at C2 index.
    pub fn c2_targets(&self) -> &[Target] {
        &self.inner.arr[C2_IDX..A_IDX]
    }

    /// Get the targets at A index.
    pub fn a_targets(&self) -> &[Target] {
        &self.inner.arr[A_IDX..M_IDX]
    }

    /// Get the targets at M index.
    pub fn m_targets(&self) -> &[Target] {
        &self.inner.arr[M_IDX..S_IDX]
    }

    /// Get the targets at S index.
    pub fn s_targets(&self) -> &[Target] {
        &self.inner.arr[S_IDX..]
    }
}
