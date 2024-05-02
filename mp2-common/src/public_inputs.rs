//! Common public input types

use std::ops::Range;

/// Public input range for each item
pub type PublicInputRange = Range<usize>;

/// Public input common trait
pub trait PublicInputCommon {
    const RANGES: &'static [PublicInputRange];
}
