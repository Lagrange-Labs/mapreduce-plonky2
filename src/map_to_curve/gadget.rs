//! Map to curve circuit functions

use super::{
    utils::{a_sw, b_sw, two_thirds, z_sw},
    ToCurveTarget,
};
use crate::digest::ECGFP5_EXT_DEGREE as N;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::{
    base_field::{CircuitBuilderGFp5, QuinticExtensionTarget},
    curve::{CircuitBuilderEcGFp5, CurveTarget},
};

/// Implement curve target conversion for extension target.
impl<F, const D: usize> ToCurveTarget<F, D> for QuinticExtensionTarget
where
    F: RichField + Extendable<D> + Extendable<N>,
    CircuitBuilder<F, D>: CircuitBuilderGFp5<F> + CircuitBuilderEcGFp5,
{
    /// Convert extension target to a curve target.
    fn map_to_curve_target(self, b: &mut CircuitBuilder<F, D>) -> CurveTarget {
        // Invokes simplified SWU method.
        simple_swu(b, self)
    }
}

/// Simplified SWU mapping function for conversion from an extension target to a
/// curve target.
fn simple_swu<F, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    u: QuinticExtensionTarget,
) -> CurveTarget
where
    F: RichField + Extendable<D> + Extendable<N>,
    CircuitBuilder<F, D>: CircuitBuilderGFp5<F> + CircuitBuilderEcGFp5,
{
    // Initialize constants.
    let zero = b.zero_quintic_ext();
    let one = b.one_quintic_ext();
    let [two_thirds, a_sw, b_sw, z_sw] =
        [a_sw(), b_sw(), z_sw(), two_thirds()].map(|val| b.constant_quintic_ext(val));

    // Calculate tv1.
    let u_square = b.square_quintic_ext(u);
    let denom_part = b.mul_quintic_ext(z_sw, u_square);
    let denom_part_square = b.square_quintic_ext(denom_part);
    let denom = b.add_quintic_ext(denom_part_square, denom_part);
    let tv1 = b.inverse_quintic_ext(denom);

    // Calculate x1.
    // x1_lhs = b_sw / (z_sw * a_sw)
    let z_sw_mul_a_sw = b.mul_quintic_ext(z_sw, a_sw);
    let x1_lhs = b.div_quintic_ext(b_sw, z_sw_mul_a_sw);
    // x1_rhs = (-b_sw / a_sw) * (tv1 + 1)
    let neg_b_sw = b.neg_quintic_ext(b_sw);
    let neg_b_sw_div_a_sw = b.div_quintic_ext(neg_b_sw, a_sw);
    let tv1_add_one = b.add_quintic_ext(tv1, one);
    let x1_rhs = b.mul_quintic_ext(neg_b_sw_div_a_sw, tv1_add_one);
    // x1 = x1_lhs if tv1 == 0, else x1 = x1_rhs.
    let is_tv1_zero = b.is_equal_quintic_ext(tv1, zero);
    let x1 = b.select_quintic_ext(is_tv1_zero, x1_lhs, x1_rhs);

    // Calculate x2.
    let x2 = b.mul_quintic_ext(denom_part, x1);

    // g(x) = X^3 + A_sw*X + B_sw
    let x1_square = b.square_quintic_ext(x1);
    let x2_square = b.square_quintic_ext(x2);
    let x1_cube = b.mul_quintic_ext(x1, x1_square);
    let x2_cube = b.mul_quintic_ext(x2, x2_square);
    let a_sw_mul_x1 = b.mul_quintic_ext(a_sw, x1);
    let a_sw_mul_x2 = b.mul_quintic_ext(a_sw, x2);
    let gx1 = b.add_quintic_ext(x1_cube, a_sw_mul_x1);
    let gx2 = b.add_quintic_ext(x2_cube, a_sw_mul_x2);
    let gx1 = b.add_quintic_ext(gx1, b_sw);
    let gx2 = b.add_quintic_ext(gx2, b_sw);

    let (gx1_root, is_gx1_sqrt) = b.try_any_sqrt_quintic_ext(gx1);
    let gx2_root = b.any_sqrt_quintic_ext(gx2);
    let x_sw = b.select_quintic_ext(is_gx1_sqrt, x1, x2);
    let y_pos = b.select_quintic_ext(is_gx1_sqrt, gx1_root, gx2_root);
    let neg_y_pos = b.neg_quintic_ext(y_pos);

    // Calculate X_cand and Y_cand.
    let x_cand = b.sub_quintic_ext(x_sw, two_thirds);
    // y_cand = y_pos if y_pos_sgn0 == u_sgn0, else y_cand = -y_pos.
    let y_pos_sgn0 = b.sgn0_quintic_ext(y_pos);
    let u_sgn0 = b.sgn0_quintic_ext(u);
    let y_cand_lhs = b.select_quintic_ext(u_sgn0, y_pos, neg_y_pos);
    let y_cand_rhs = b.select_quintic_ext(u_sgn0, neg_y_pos, y_pos);
    let y_cand = b.select_quintic_ext(y_pos_sgn0, y_cand_lhs, y_cand_rhs);

    // Decode to a curve point.
    let y_cand_div_x_cand = b.div_quintic_ext(y_cand, x_cand);
    b.curve_decode_from_quintic_ext(y_cand_div_x_cand)
}
