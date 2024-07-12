use mp2_common::array::{Targetable, ToField};
use plonky2::hash::hash_types::RichField;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Set of constant identifiers employed in the
/// computational hash, which is a compact representation
/// of the query being proven by the query circuits
pub enum ComputationalHashIdentifiers {
    AddOp,
    SubOp,
    MulOp,
    DivOp,
    ModOp,
    LessThanOp,
    EqOp,
    NeOp,
    GreaterThanOp,
    LessThanOrEqOp,
    GreaterThanOrEqOp,
    AndOp,
    OrOp,
    NotOp,
    XorOp,
}

impl<F: RichField> ToField<F> for ComputationalHashIdentifiers {
    fn to_field(&self) -> F {
        F::from_canonical_usize(*self as usize)
    }
}
