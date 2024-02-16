//! Group hashing arithmetic and circuit functions

use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::{
    base_field::CircuitBuilderGFp5,
    curve::{CircuitBuilderEcGFp5, CurveTarget},
};

mod curve_add;
pub(crate) mod field_to_curve;
mod sswu_gadget;
mod sswu_value;
mod utils;

/// Extension degree of EcGFp5 curve
pub(crate) const N: usize = 5;

/// Field-to-curve and curve point addition functions
pub use curve_add::add_curve_point;
pub use field_to_curve::map_to_curve_point;

/// Trait for adding field-to-curve and curve point addition functions to
/// circuit builder
pub trait CircuitBuilderGroupHashing {
    /// Calculate the curve target addition.
    fn add_curve_point(&mut self, targets: &[CurveTarget]) -> CurveTarget;

    /// Convert the field targets to a curve target.
    fn map_to_curve_point(&mut self, targets: &[Target]) -> CurveTarget;
}

impl<F, const D: usize> CircuitBuilderGroupHashing for CircuitBuilder<F, D>
where
    F: RichField + Extendable<D> + Extendable<N>,
    Self: CircuitBuilderGFp5<F> + CircuitBuilderEcGFp5,
{
    fn add_curve_point(&mut self, targets: &[CurveTarget]) -> CurveTarget {
        curve_add::add_curve_target(self, targets)
    }

    fn map_to_curve_point(&mut self, targets: &[Target]) -> CurveTarget {
        field_to_curve::map_to_curve_target(self, targets)
    }
}
