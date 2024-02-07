//! Field extension utility functions
//! Reference the plonky2 code for value operations:
//! <https://github.com/0xPolygonZero/plonky2/blob/f3f7433c29a3e12db5d13ff1ff9f09c48b3ef441/field/src/extension/quintic.rs>
//! Reference the plonky2-ecgfp5 code for target operations:
/// <https://github.com/Sladuca/plonky2-ecgfp5/blob/8c5d9c42ffb5e6eda6335e8c960432dacc4db415/src/gadgets/base_field.rs>
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use std::array;

/// Add extension value.
pub fn add_ext_value<F, const N: usize>(v1: [F; N], v2: [F; N]) -> [F; N]
where
    F: RichField + Extendable<N>,
{
    array::from_fn(|i| v1[i] + v2[i])
}

/// Sub extension value.
pub fn sub_ext_value<F, const N: usize>(v1: [F; N], v2: [F; N]) -> [F; N]
where
    F: RichField + Extendable<N>,
{
    array::from_fn(|i| v1[i] - v2[i])
}

/// Add extension target.
pub fn add_ext_target<F, const D: usize, const N: usize>(
    b: &mut CircuitBuilder<F, D>,
    t1: [Target; N],
    t2: [Target; N],
) -> [Target; N]
where
    F: RichField + Extendable<D> + Extendable<N>,
{
    array::from_fn(|i| b.add(t1[i], t2[i]))
}

/// Sub extension target.
pub fn sub_ext_target<F, const D: usize, const N: usize>(
    b: &mut CircuitBuilder<F, D>,
    t1: [Target; N],
    t2: [Target; N],
) -> [Target; N]
where
    F: RichField + Extendable<D> + Extendable<N>,
{
    array::from_fn(|i| b.sub(t1[i], t2[i]))
}

/// Select extension target.
pub fn select_ext_target<F, const D: usize, const N: usize>(
    b: &mut CircuitBuilder<F, D>,
    is_t1: BoolTarget,
    t1: [Target; N],
    t2: [Target; N],
) -> [Target; N]
where
    F: RichField + Extendable<D> + Extendable<N>,
{
    array::from_fn(|i| b.select(is_t1, t1[i], t2[i]))
}
