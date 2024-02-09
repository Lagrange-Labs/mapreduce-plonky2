//! Map to curve arithmetic and circuit functions

use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::{curve::curve::Point, gadgets::curve::CurveTarget};

mod curve;
mod gadget;
mod utils;

/// The trait for mapping to a curve point
pub trait ToCurvePoint {
    /// Convert to a curve point.
    fn map_to_curve_point(self) -> Point;
}

/// The trait for mapping to a curve target
pub trait ToCurveTarget<F, const D: usize>
where
    F: RichField + Extendable<D>,
{
    /// Convert to a curve target.
    fn map_to_curve_target(self, b: &mut CircuitBuilder<F, D>) -> CurveTarget;
}
