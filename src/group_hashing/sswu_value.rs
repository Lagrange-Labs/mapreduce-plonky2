//! Map to curve field arithmetic functions

use super::{
    field_to_curve::ToCurvePoint,
    utils::{a_sw, b_sw, neg_b_div_a_sw, neg_z_inv_sw, two_thirds, z_sw},
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
    use super::{super::N, *};
    use plonky2::field::extension::FieldExtension;
    use std::array;

    /// The array of input and output pairs is used for testing. The input is
    /// the raw values of an extension field, and output is the encoded
    /// extension field of a curve point (less data than a Weierstrass point).
    const TEST_INPUTS_OUTPUTS: [[[u64; N]; 2]; 3] = [
        [
            [1, 2, 3, 4, 5],
            [
                14787531356491256379,
                11461637202037498289,
                4291527673026618528,
                4746471857872952759,
                13337224262829952359,
            ],
        ],
        [
            [100, 100, 100, 100, 100],
            [
                5101977855671705567,
                18259369900233540211,
                4964766086423821262,
                6349865835816149910,
                13164635315267603389,
            ],
        ],
        [
            [0, u64::MAX, 0, u64::MAX, u64::MAX],
            [
                15406267945121757331,
                8614084671648873762,
                2366015382156010603,
                14529344599099006840,
                15466818755358183082,
            ],
        ],
    ];

    /// Test simplified SWU method for mapping to curve point.
    #[test]
    fn test_simple_swu_for_curve_point() {
        TEST_INPUTS_OUTPUTS.iter().for_each(|input_output| {
            let [input, expected_output] = input_output.map(ext_field_from_array);
            let real_output = simple_swu(input).encode();

            assert_eq!(
                real_output, expected_output,
                "The encoded extension field must be equal"
            );
        });
    }

    fn ext_field_from_array(values: [u64; N]) -> GFp5 {
        GFp5::from_basefield_array(array::from_fn::<_, N, _>(|i| GoldilocksField(values[i])))
    }
}
