//! Common public input traits

use crate::types::CBuilder;
use std::ops::Range;

/// Public input range for each item
pub type PublicInputRange = Range<usize>;

/// Public input trait for plonky2 targets
pub trait PublicInputTargets {
    const RANGES: &'static [PublicInputRange];

    /// Register the public inputs with the index checking.
    fn register_with_check(cb: &mut CBuilder, funs: &[&dyn Fn(&mut CBuilder)]) {
        assert_eq!(Self::RANGES.len(), funs.len());

        Self::RANGES.iter().zip(funs).for_each(|(range, fun)| {
            fun(cb);

            assert_eq!(
                cb.num_public_inputs(),
                range.end,
                "Registered wrong number of public inputs"
            );
        });
    }
}
