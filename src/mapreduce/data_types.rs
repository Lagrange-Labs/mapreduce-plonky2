use plonky2::{field::extension::Extendable, hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder, iop::{target::{Target, BoolTarget}, witness::{WitnessWrite, PartialWitness}}};
use plonky2_crypto::u32::{arithmetic_u32::{CircuitBuilderU32, U32Target}, witness::WitnessU32};

use super::Data;

/// A Primitive is anything that we can treat as a "leaf" of the 
/// data tree without descending further through the tree. Each 
/// Primitive should have available methods on CircuitBuilder and
/// PartialWitness which allocates and sets targets for it correctly. 

pub enum Primitive {
    Bool(Bool),
    U8(U8),
    U32(U32),
    U64(U64),
}

pub trait Wire {
    type Value;
    type WireTarget;

    fn create_target<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self::WireTarget;
    fn set_target<F: RichField>(target: Self::WireTarget, value: Self::Value, pw: &mut PartialWitness<F>);
}

pub struct Bool;

impl Wire for Bool {
    type Value = bool;
    type WireTarget = BoolTarget;

    fn create_target<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self::WireTarget {
        builder.add_virtual_bool_target_unsafe()
    }

    fn set_target<F: RichField>(target: Self::WireTarget, value: Self::Value, pw: &mut PartialWitness<F>) {
        pw.set_bool_target(target, value)
    }
}

pub struct U8;

impl Wire for U8 {
    type Value = u8;
    type WireTarget = Target;

    fn create_target<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self::WireTarget {
        builder.add_virtual_target()
    }

    fn set_target<F: RichField>(target: Self::WireTarget, value: Self::Value, pw: &mut PartialWitness<F>) {
        pw.set_target(target, F::from_canonical_u8(value))
    }
}

pub struct U32;

impl Wire for U32 {
    type Value = u32;
    type WireTarget = U32Target;

    fn create_target<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self::WireTarget {
        builder.add_virtual_u32_target()
    }

    fn set_target<F: RichField>(target: Self::WireTarget, value: Self::Value, pw: &mut PartialWitness<F>) {
        pw.set_u32_target(target, value)
    }
}

pub struct U64;

impl Wire for U64 {
    type Value = u64;
    type WireTarget = Target;

    fn create_target<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self::WireTarget {
        builder.add_virtual_target()
    }

    fn set_target<F: RichField>(target: Self::WireTarget, value: Self::Value, pw: &mut PartialWitness<F>) {
        pw.set_target(target, F::from_canonical_u64(value))
    }
}