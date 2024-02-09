//! Map to curve utility functions

use crate::digest::ECGFP5_EXT_DEGREE as N;
use plonky2::{
    field::extension::{quintic::QuinticExtension, Extendable, FieldExtension},
    hash::hash_types::RichField,
};

pub fn two_thirds<F: Extendable<N>>() -> QuinticExtension<F> {
    QuinticExtension::<F>::from_basefield_array([
        F::from_canonical_u64(6148914689804861441),
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
    ])
}

// Coefficients for double-odd form y^2 = x(x^2 + Ax + B)
// A = QuinticExtension[2, 0, 0, 0, 0]
// B = QuinticExtension[0, 263, 0, 0, 0]
// Coefficients for Short Weierstrass form y^2 = x^3 + A_sw*x + B_sw
// A_sw = (3B - A^2)/3
pub fn a_sw<F: Extendable<N>>() -> QuinticExtension<F> {
    QuinticExtension::<F>::from_basefield_array([
        F::from_canonical_u64(6148914689804861439),
        F::from_canonical_u64(263),
        F::ZERO,
        F::ZERO,
        F::ZERO,
    ])
}

// Coefficients for double-odd form y^2 = x(x^2 + Ax + B)
// A = QuinticExtension[2, 0, 0, 0, 0]
// B = QuinticExtension[0, 263, 0, 0, 0]
// Coefficients for Short Weierstrass form y^2 = x^3 + A_sw*x + B_sw
// B_sw = A(2A^2 -9B)/27
pub fn b_sw<F: Extendable<N>>() -> QuinticExtension<F> {
    QuinticExtension::<F>::from_basefield_array([
        F::from_canonical_u64(15713893096167979237),
        F::from_canonical_u64(6148914689804861265),
        F::ZERO,
        F::ZERO,
        F::ZERO,
    ])
}

// Z computed using SageMath
// Z_sw = -4 - z = 18446744069414584317 + 18446744069414584320*z
// GoldilocksField::ORDER = 0xFFFFFFFF00000001
// GoldilocksField::NEG_ONE = ORDER - 1
// <https://github.com/nikkolasg/plonky2/blob/7a7649e55d68fe0e6bb924b00d7675e19a7f2a0a/field/src/goldilocks_field.rs>
pub fn z_sw<F: RichField + Extendable<N>>() -> QuinticExtension<F> {
    QuinticExtension::<F>::from_basefield_array([
        F::from_canonical_u64(F::ORDER - 4),
        F::NEG_ONE,
        F::ZERO,
        F::ZERO,
        F::ZERO,
    ])
}
