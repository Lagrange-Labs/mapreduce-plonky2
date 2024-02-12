//! Map to curve field arithmetic functions

use super::{
    utils::{a_sw, b_sw, neg_b_div_a_sw, neg_z_inv_sw, two_thirds, z_sw},
    ToCurvePoint,
};
use plonky2::field::{
    extension::quintic::QuinticExtension, goldilocks_field::GoldilocksField, ops::Square,
    types::Field,
};
use plonky2_ecgfp5::curve::{
    base_field::{InverseOrZero, Sgn0, SquareRoot},
    curve::Point,
};

/// Define Goldilocks and extension field types.
type GFp = GoldilocksField;
type GFp5 = QuinticExtension<GFp>;

/// Implement curve point conversion for Goldilocks extension field.
impl ToCurvePoint for GFp5 {
    /// Convert extension field to a curve point.
    fn map_to_curve_point(self) -> Point {
        // Invokes simplified SWU method.
        simple_swu(self)
    }
}

/// Simplified SWU mapping function for conversion from an extension field to a
/// curve point.
pub(crate) fn simple_swu(u: GFp5) -> Point {
    // Initialize constants.
    let [two_thirds, a_sw, b_sw, z_sw, neg_z_inv_sw, neg_b_div_a_sw] = [
        two_thirds(),
        a_sw(),
        b_sw(),
        z_sw(),
        neg_z_inv_sw(),
        neg_b_div_a_sw(),
    ];

    // Calculate tv1.
    let denom_part = z_sw * u.square();
    let denom = denom_part.square() + denom_part;
    let tv1 = denom.inverse_or_zero();

    // Calculate x1.
    let x1 = if tv1.is_zero() {
        neg_z_inv_sw
    } else {
        tv1 + GFp5::ONE
    } * neg_b_div_a_sw;

    // Calculate x2.
    let x2 = denom_part * x1;

    // g(x) = X^3 + A_sw*X + B_sw
    let gx1 = x1 * x1.square() + a_sw * x1 + b_sw;
    let gx2 = x2 * x2.square() + a_sw * x2 + b_sw;

    let (x_sw, y_pos) = if let Some(gx1_root) = gx1.sqrt() {
        (x1, gx1_root)
    } else {
        (x2, gx2.sqrt().unwrap())
    };

    // Calculate X_cand and Y_cand.
    let x_cand = x_sw - two_thirds;
    let y_cand = if u.sgn0() == y_pos.sgn0() {
        y_pos
    } else {
        -y_pos
    };

    // Decode to a curve point.
    Point::decode(y_cand / x_cand).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::extension::FieldExtension;
    use std::array;

    /// Test simplified SWU method for mapping to curve point.
    #[test]
    fn test_simple_swu_for_curve_point() {
        let field = QuinticExtension::from_basefield_array(array::from_fn::<_, 5, _>(|i| {
            GoldilocksField(i as u64)
        }));

        let point = simple_swu(field).to_weierstrass();
        println!("Curve point from test conversion: {point:?}");
    }
}
