//! Common public input types

use std::ops::Range;

use crate::types::CBuilder;

/// Public input range for each item
pub type PublicInputRange = Range<usize>;

/// Public input common trait
pub trait PublicInputCommon {
    /// Values to be registered on the [CBuilder] as public inputs. These values can be either
    /// owned or referenced, and they should conform to the expected [PublicInputsCommon::RANGES].
    type RegisterArgs;

    /// The slices within the public inputs arguments of this structure encompass the following
    /// ranges, which correspond to the logical attributes of the circuit.
    const RANGES: &'static [PublicInputRange];

    /// A user-defined function that registers the supplied arguments into [CBuilder].
    ///
    /// This function is not intended for use during circuit definition. Instead, please utilize
    /// the [PublicInputCommon::register] function for such purposes.
    fn register_args(cb: &mut CBuilder, args: Self::RegisterArgs);

    /// Registers the provided arguments as public inputs of the circuit.
    ///
    /// It will perform a validation, asserting the number of registered public inputs corresponds
    /// to the defined range arguments in length.
    fn register(cb: &mut CBuilder, args: Self::RegisterArgs) {
        let len: usize = Self::RANGES.iter().map(|r| r.end - r.start).sum();
        let initial = cb.num_public_inputs();

        Self::register_args(cb, args);

        let dif = cb.num_public_inputs() - initial;

        // This assertion can be replaced with `debug_assert_eq` in production environments to
        // prevent rewind overhead. The runtime overhead in normal cases is expected to be
        // insignificant, while maintaining this check enhances test robustness.
        assert_eq!(dif, len, "The number of registered public inputs {dif} doesn't match the expected ranges length {len}.");
    }
}
