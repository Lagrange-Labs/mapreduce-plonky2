use anyhow::{anyhow, Result};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use std::fmt::Debug;

use crate::utils::IntTargetWriter;

/// ArrayWire contains the wires representing an array of dynamic length
/// up to MAX_LEN. This is useful when you don't know the exact size in advance
/// of your data, for example in hashing MPT nodes.
#[derive(Debug, Clone)]
pub struct VectorWire<const MAX_LEN: usize> {
    pub arr: [Target; MAX_LEN],
    pub real_len: Target,
}

/// A fixed buffer array containing dynammic length data, the equivalent of
/// `ArrayWire` outside circuit.
#[derive(Clone, Debug)]
pub struct Vector<const MAX_LEN: usize> {
    // hardcoding to be bytes srently only use case
    pub arr: [u8; MAX_LEN],
    pub real_len: usize,
}

impl<const MAX_LEN: usize> VectorWire<MAX_LEN> {
    pub fn new<F, const D: usize>(b: &mut CircuitBuilder<F, D>) -> Self
    where
        F: RichField + Extendable<D>,
    {
        let real_len = b.add_virtual_target();
        let arr = b.add_virtual_target_arr::<MAX_LEN>();
        Self { arr, real_len }
    }
}
impl<const MAX_LEN: usize> Vector<MAX_LEN> {
    pub fn assign<F: RichField>(&self, pw: &mut PartialWitness<F>, wire: &VectorWire<MAX_LEN>) {
        pw.set_target(wire.real_len, F::from_canonical_usize(self.real_len));
        pw.set_int_targets(&wire.arr, &self.arr);
    }
}

/// Fixed size array in circuit of any type (Target or U32Target for example!)
/// of N elements.
#[derive(Clone, Debug)]
pub struct Array<T, const N: usize> {
    arr: [T; N],
}

impl<T, const N: usize> From<[T; N]> for Array<T, N> {
    fn from(value: [T; N]) -> Self {
        Self { arr: value }
    }
}
impl<T: Debug, const N: usize> TryFrom<Vec<T>> for Array<T, N> {
    type Error = anyhow::Error;
    fn try_from(value: Vec<T>) -> Result<Self> {
        Ok(Self {
            arr: value
                .try_into()
                .map_err(|e| anyhow!("can't conver to array: {:?}", e))?,
        })
    }
}

impl<const N: usize> Array<Target, N> {
    pub fn select<F: RichField + Extendable<D>, const D: usize>(
        &self,
        condition: BoolTarget,
        other: &Self,
        b: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Array {
            arr: core::array::from_fn(|i| b.select(condition, self.arr[i], other.arr[i])),
        }
    }
}

impl<const N: usize> Array<U32Target, N> {
    pub fn select<F: RichField + Extendable<D>, const D: usize>(
        &self,
        condition: BoolTarget,
        other: &Self,
        b: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Array {
            arr: core::array::from_fn(|i| {
                U32Target(b.select(condition, self.arr[i].0, other.arr[i].0))
            }),
        }
    }

    /// Returns a wire set to true iif the array contains the hash output at the designated index `at`
    /// It actually converts the concerned part of the array to u32 and then compare the u32s together.
    pub fn contains_subarray<F: RichField + Extendable<D>, const D: usize, const SUB: usize>(
        &self,
        sub: Array<U32Target, SUB>,
        at: Target,
        b: &mut CircuitBuilder<F, D>,
    ) -> () {
        ()
    }
}
