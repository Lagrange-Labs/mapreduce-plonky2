//! Map to curve circuit functions

use crate::digest::ECGFP5_EXT_DEGREE as N;
use plonky2::{
    field::extension::{quintic::QuinticExtension, Extendable, FieldExtension},
    hash::hash_types::RichField,
    iop::target::Target,
};
use plonky2_ecgfp5::{curve::curve::Point, gadgets::curve::CurveTarget};

/// Convert the field targets to a curve target.
pub fn map_to_curve_target<F>(targets: [F; N]) -> CurveTarget {
    todo!()
}
