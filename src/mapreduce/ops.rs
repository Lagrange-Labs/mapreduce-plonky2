use std::marker::PhantomData;

use super::data_types::Data;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// Defines a map computation with its associated circuit
pub trait Map {
    type Input: Data;
    type Output: Data;

    // The map computation to be performed on a single item.
    // The input and output can have different types but each
    // must be representable in a circuit.
    fn eval(input: &<Self::Input as Data>::Value) -> <Self::Output as Data>::Value;

    // A function which adds constraints to
    // a CircuitBuilder that should be satisfied by `eval`.
    fn add_constraints<F, const D: usize>(
        input: &<Self::Input as Data>::WireTarget,
        builder: &mut CircuitBuilder<F, D>,
    ) where
        F: RichField + Extendable<D>;
}

/// Defines a reduce computation and its associated circuit.
pub trait Reduce {
    type Input: Data;

    /// A function producing the neutral element with respect to `eval`.
    fn neutral() -> <Self::Input as Data>::Value;

    // The reduce computation to be performed. The inputs and output
    // must be representable in a circuit. The `eval` function
    // should be associative and have a neutral element so that:
    //  eval(x, eval(y, z)) = eval(eval(x, y), z) for all x,y,z in T
    //  eval(neutral, x) = eval(x, neutral) = x for all x in T
    fn eval(
        left: &<Self::Input as Data>::Value,
        right: &<Self::Input as Data>::Value,
    ) -> <Self::Input as Data>::Value;

    // A function adding constraints to a circuit builder which should
    // be satisfied by the reduce computation in `eval`. That is,
    // if eval(x, y) = z, then circuit(x, y, z) should be true.
    fn add_constraints<F, const D: usize>(
        left: &<Self::Input as Data>::WireTarget,
        right: &<Self::Input as Data>::WireTarget,
        builder: &mut CircuitBuilder<F, D>,
    ) -> <Self::Input as Data>::WireTarget
    where
        F: RichField + Extendable<D>;
    // TODO
    // consider using eval and add_constraints to make the Reduce trait iterable and foldable
    // also, consider a recursion threshold
}

pub struct Identity<T> {
    _phantom: PhantomData<T>,
}

impl<T: Data + Clone> Map for Identity<T> {
    type Input = T;
    type Output = T;

    fn eval(input: &<Self::Input as Data>::Value) -> <Self::Output as Data>::Value {
        input.clone()
    }

    fn add_constraints<F, const D: usize>(
        input: &<Self::Input as Data>::WireTarget,
        builder: &mut CircuitBuilder<F, D>,
    ) where
        F: RichField + Extendable<D>,
    {
    }
}
