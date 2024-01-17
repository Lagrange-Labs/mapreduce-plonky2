use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::utils::IntTargetWriter;

/// ArrayWire contains the wires representing an array of dynamic length
/// up to MAX_LEN. This is useful when you don't know the exact size in advance
/// of your data, for example in hashing MPT nodes.
#[derive(Debug, Clone)]
pub struct ArrayWire<const MAX_LEN: usize> {
    pub arr: [Target; MAX_LEN],
    pub real_len: Target,
}

/// A fixed buffer array containing dynammic length data, the equivalent of
/// `ArrayWire` outside circuit.
#[derive(Clone, Debug)]
pub struct Array<const MAX_LEN: usize> {
    // hardcoding to be bytes currently only use case
    pub arr: [u8; MAX_LEN],
    pub real_len: usize,
}

impl<const MAX_LEN: usize> Array<MAX_LEN> {}

impl<const MAX_LEN: usize> ArrayWire<MAX_LEN> {
    pub fn new<F, const D: usize>(b: &mut CircuitBuilder<F, D>) -> Self
    where
        F: RichField + Extendable<D>,
    {
        let real_len = b.add_virtual_target();
        let arr = b.add_virtual_target_arr::<MAX_LEN>();
        Self { arr, real_len }
    }
}
impl<const MAX_LEN: usize> Array<MAX_LEN> {
    pub fn assign<F: RichField>(&self, pw: &mut PartialWitness<F>, wire: &ArrayWire<MAX_LEN>) {
        pw.set_target(wire.real_len, F::from_canonical_usize(self.real_len));
        pw.set_int_targets(&wire.arr, &self.arr);
    }
}
