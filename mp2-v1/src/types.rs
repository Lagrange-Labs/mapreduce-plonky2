//! Common types

use plonky2::{
    field::{extension::quintic::QuinticExtension, goldilocks_field::GoldilocksField},
    plonk::circuit_builder::CircuitBuilder,
};

/// Default field
pub(crate) type GFp = GoldilocksField;

/// Quintic extension field
pub(crate) type GFp5 = QuinticExtension<GFp>;

/// Default circuit builder
pub(crate) type CBuilder = CircuitBuilder<GoldilocksField, 2>;
