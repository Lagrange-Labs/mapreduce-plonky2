//! Group hashing arithmetic and circuit functions

mod curve_add;
mod field_to_curve;
mod sswu_gadget;
mod sswu_value;
mod utils;

/// Extension degree of EcGFp5 curve
pub const ECGFP5_EXT_DEGREE: usize = 5;

pub use curve_add::{add_curve_points, add_curve_targets};
pub use field_to_curve::{
    field_to_curve_point, field_to_curve_target, ToCurvePoint, ToCurveTarget,
};
