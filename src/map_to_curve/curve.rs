//! Map to curve field arithmetic functions

use super::ToCurvePoint;
use plonky2::field::{
    extension::{quintic::QuinticExtension, FieldExtension},
    goldilocks_field::GoldilocksField,
    ops::Square,
    types::{Field, Field64, PrimeField64},
};
use plonky2_ecgfp5::curve::{
    base_field::{Legendre, SquareRoot},
    curve::Point,
};

type GFp = GoldilocksField;
type GFp5 = QuinticExtension<GFp>;

impl ToCurvePoint for GFp5 {
    fn map_to_curve_point(&self) -> Point {
        simple_swu(&self)
    }
}

fn simple_swu(u: &GFp5) -> Point {
    let two_thirds = GFp5::from_basefield_array([
        GFp::from_canonical_u64(6148914689804861441),
        GFp::ZERO,
        GFp::ZERO,
        GFp::ZERO,
        GFp::ZERO,
    ]);

    // coefficients for double-odd form y^2 = x(x^2 + Ax + B)
    // let A: GFp5 =
    //     GFp5::from_basefield_array([GFp::TWO, GFp::ZERO, GFp::ZERO, GFp::ZERO, GFp::ZERO]);
    // let B: GFp5 = GFp5::from_basefield_array([
    //     GFp::ZERO,
    //     GFp::from_canonical_u64(263),
    //     GFp::ZERO,
    //     GFp::ZERO,
    //     GFp::ZERO,
    // ]);

    // coefficients for Short Weierstrass form Y^2 = X^3 + a_sw*x + b_sw
    // a_sw = (3B - A^2)/3
    // b_sw = A(2A^2 -9B)/27
    let a_sw = GFp5::from_basefield_array([
        GFp::from_canonical_u64(6148914689804861439),
        GFp::from_canonical_u64(263),
        GFp::ZERO,
        GFp::ZERO,
        GFp::ZERO,
    ]);
    let b_sw = GFp5::from_basefield_array([
        GFp::from_canonical_u64(15713893096167979237),
        GFp::from_canonical_u64(6148914689804861265),
        GFp::ZERO,
        GFp::ZERO,
        GFp::ZERO,
    ]);

    // Z computed using SageMath
    // Z_sw = -4 - z = 18446744069414584317 + 18446744069414584320*z
    let Z_sw = GFp5::from_basefield_array([
        GFp::from_canonical_u64(GFp::ORDER - 4),
        GFp::NEG_ONE,
        GFp::ZERO,
        GFp::ZERO,
        GFp::ZERO,
    ]);

    let denom_part = Z_sw * u.square();
    let denom = denom_part.square() + denom_part;
    let tv1 = denom.inverse();

    let x1 = match tv1.is_zero() {
        true => b_sw / (Z_sw * a_sw),
        false => (-b_sw / a_sw) * (GFp5::ONE + tv1),
    };
    let x2 = denom_part * x1;

    // g(x) = X^3 + a_sw*X + b_sw
    let gx1 = x1 * x1.square() + a_sw * x1 + b_sw;
    let gx2 = x2 * x2.square() + a_sw * x2 + b_sw;

    let (x_sw, y_pos) = match is_square(gx1) {
        true => (x1, gx1.sqrt().unwrap()),
        false => (x2, gx2.sqrt().unwrap()),
    };

    let x_cand = x_sw - two_thirds;
    let y_cand = match sgn(&y_pos) == sgn(u) {
        true => y_pos,
        false => -y_pos,
    };

    Point::decode(y_cand / x_cand).unwrap()
}

fn sgn(x: &GFp5) -> bool {
    x.0.iter().map(|f| f.to_canonical_u64() % 2u64).sum::<u64>() % 2 == 1
}

fn is_square(x: GFp5) -> bool {
    let leg = x.legendre();
    (leg.square() - leg).is_zero()
}
