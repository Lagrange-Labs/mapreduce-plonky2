//! Hash to field functions

use super::ECGFP5_EXT_DEGREE as N;
use plonky2::{field::extension::Extendable, hash::hash_types::RichField, iop::target::Target};
use plonky2_ecgfp5::{curve::curve::Point, gadgets::curve::CurveTarget};

/// Convert the Poseidon hash to a curve point value.
pub fn hash_to_curve_point_value<F>(hash: [F; N]) -> Point
where
    F: RichField + Extendable<N>,
{
    todo!()
}

/// Convert the Poseidon hash to a curve point target.
pub fn hash_to_curve_point_target(hash: [Target; N]) -> CurveTarget {
    todo!()
}
