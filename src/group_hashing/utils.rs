//! Map to curve utility functions

use super::N;
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

pub fn neg_z_inv_sw<F: RichField + Extendable<N>>() -> QuinticExtension<F> {
    QuinticExtension::<F>::from_basefield_array([
        F::from_canonical_u64(4795794222525505369),
        F::from_canonical_u64(3412737461722269738),
        F::from_canonical_u64(8370187669276724726),
        F::from_canonical_u64(7130825117388110979),
        F::from_canonical_u64(12052351772713910496),
    ])
}

pub fn neg_b_div_a_sw<F: RichField + Extendable<N>>() -> QuinticExtension<F> {
    QuinticExtension::<F>::from_basefield_array([
        F::from_canonical_u64(6585749426319121644),
        F::from_canonical_u64(16990361517133133838),
        F::from_canonical_u64(3264760655763595284),
        F::from_canonical_u64(16784740989273302855),
        F::from_canonical_u64(13434657726302040770),
    ])
}
