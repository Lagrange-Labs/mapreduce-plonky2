//! Hash to field functions

use super::{MultisetHashingPointTarget, MultisetHashingPointValue};
use plonky2::{field::extension::Extendable, hash::hash_types::RichField, iop::target::Target};

/// Convert the Poseidon hash value to a curve extension point value.
pub fn hash_to_field_point_value<F, const N: usize>(hash: [F; N]) -> MultisetHashingPointValue<F, N>
where
    F: RichField + Extendable<N>,
{
    todo!()
}

/// Convert the Poseidon hash target to a curve extension point target.
pub fn hash_to_field_point_target<const N: usize>(
    hash: [Target; N],
) -> MultisetHashingPointTarget<N> {
    todo!()
}
