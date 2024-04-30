//! Common public input traits

use crate::types::CBuilder;
use std::ops::Range;

/// Public input range for each item
pub type PublicInputRange = Range<usize>;

/// Public input trait for plonky2 targets
pub trait PublicInputTargets {
    /// Return the ranges of each public input in ascending order.
    fn all_ranges() -> &'static [PublicInputRange];

    /// Register each public input with the index checking.
    fn register_each<Fun>(cb: &mut CBuilder, fun: Fun)
    where
        Fun: Fn(&mut CBuilder),
    {
        let ranges = Self::all_ranges();
        let num = cb.num_public_inputs();

        // Check the current and get the next public input indexes.
        let ii = ranges
            .binary_search_by(|span| span.start.cmp(&num))
            .unwrap_or_else(|_| {
                panic!(
                    "Current public input number '{}' is not included by '{:?}'.",
                    num, ranges,
                )
            });
        let next_idx = ranges.get(ii + 1).expect("Out of range").start;

        // Callback to register the public input.
        fun(cb);

        // Check the registered public input number.
        assert_eq!(
            cb.num_public_inputs(),
            next_idx,
            "Registered wrong number of public inputs"
        );
    }
}
