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
pub mod field_to_curve;
mod sswu_gadget;
mod sswu_value;
mod utils;

/// Extension degree of EcGFp5 curve
pub(crate) const N: usize = 5;

pub use curve_add::add_curve_point;
/// Field-to-curve and curve point addition functions
pub use field_to_curve::map_to_curve_point;

/// Trait for adding field-to-curve and curve point addition functions to
/// circuit builder
pub trait CircuitBuilderGroupHashing {
    /// Calculate the curve target addition.
    fn add_curve_point(&mut self, targets: &[CurveTarget]) -> CurveTarget;

    /// Convert the field target to a curve target.
    fn map_one_to_curve_point(&mut self, target: Target) -> CurveTarget;

    /// Convert the field targets to a curve target.
    fn map_to_curve_point(&mut self, targets: &[Target]) -> CurveTarget;

    /// Require that two points must be equal, and none is infinity.
    /// Unlike the [curve_eq](https://github.com/Lagrange-Labs/plonky2-ecgfp5/blob/d5a6a0b7dfee4ab69d8c1c315f9f4407502f07eb/src/gadgets/curve.rs#L83)
    /// function, this constrains none of the points is infinity.
    fn connect_curve_points(&mut self, a: CurveTarget, b: CurveTarget);
}

impl<F, const D: usize> CircuitBuilderGroupHashing for CircuitBuilder<F, D>
where
    F: RichField + Extendable<D> + Extendable<N>,
    Self: CircuitBuilderGFp5<F> + CircuitBuilderEcGFp5,
{
    fn add_curve_point(&mut self, targets: &[CurveTarget]) -> CurveTarget {
        curve_add::add_curve_target(self, targets)
    }

    fn map_one_to_curve_point(&mut self, target: Target) -> CurveTarget {
        self.map_to_curve_point(&[target])
    }

    fn map_to_curve_point(&mut self, targets: &[Target]) -> CurveTarget {
        field_to_curve::map_to_curve_target(self, targets)
    }

    fn connect_curve_points(&mut self, a: CurveTarget, b: CurveTarget) {
        let CurveTarget(([ax, ay], a_is_inf)) = a;
        let CurveTarget(([bx, by], b_is_inf)) = b;

        // Constrain two points are equal.
        self.connect_quintic_ext(ax, bx);
        self.connect_quintic_ext(ay, by);

        // Constrain none is infinity.
        let ffalse = self._false();
        self.connect(a_is_inf.target, ffalse.target);
        self.connect(b_is_inf.target, ffalse.target);
    }
}
