//! Map to curve field arithmetic and circuit functions

use plonky2_ecgfp5::curve::curve::Point;

mod curve;
mod gadget;

pub use gadget::map_to_curve_target;

pub trait ToCurvePoint {
    fn map_to_curve_point(&self) -> Point;
}
