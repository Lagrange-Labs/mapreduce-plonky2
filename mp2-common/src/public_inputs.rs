//! Common public input types

use std::ops::Range;

use crate::types::CBuilder;

/// Public input range for each item
pub type PublicInputRange = Range<usize>;

/// Public input common trait
pub trait PublicInputCommon {
    /// The slices within the public inputs arguments of this structure encompass the following
    /// ranges, which correspond to the logical attributes of the circuit.
    const RANGES: &'static [PublicInputRange];

    /// A user-defined function that registers the supplied arguments into [CBuilder].
    ///
    /// This function is not intended for use during circuit definition. Instead, please utilize
    /// the [PublicInputCommon::register] function for such purposes.
    fn register_args(&self, cb: &mut CBuilder);

    /// Registers the provided arguments as public inputs of the circuit.
    ///
    /// It will perform a validation, asserting the number of registered public inputs corresponds
    /// to the defined range arguments in length.
    fn register(&self, cb: &mut CBuilder) {
        let len: usize = Self::RANGES.iter().map(|r| r.end - r.start).sum();
        let initial = cb.num_public_inputs();

        self.register_args(cb);

        let dif = cb.num_public_inputs() - initial;

        // This assertion can be replaced with `debug_assert_eq` in production environments to
        // prevent rewind overhead. The runtime overhead in normal cases is expected to be
        // insignificant, while maintaining this check enhances test robustness.
        //
        // If multiple circuits utilizing the same proving key have overlapping public inputs
        // (i.e., the same target is used as public input in each circuit), potential issues may
        // arise. However, such a scenario is unlikely to occur under normal circumstances.
        assert_eq!(dif, len, "The number of registered public inputs {dif} doesn't match the expected ranges length {len}.");
    }
}
