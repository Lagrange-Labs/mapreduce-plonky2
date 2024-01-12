mod data_types;
mod sum;

use std::marker::PhantomData;

use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder, iop::target::Target,
};

/// An item of a data set that can be represented by a fixed-length array of field elements
pub trait DataItem {
    // TODO:
    // consider making a struct that bookkeeps DataItems and their associated Targets
    // in a HashMap or similar

    /// An instance of DataItem must provide a function that encodes
    /// the data it contains as a vector of field elements
    fn encode<F>(&self) -> Vec<F>
    where
        F: RichField;

    fn len(&self) -> usize;
}

/// Defines a map computation with its associated circuit
pub trait Map {
    type Input: DataItem;
    type Output: DataItem + Clone;

    // The map computation to be performed on a single item.
    // The input and output can have different types but each
    // must be representable in a circuit.
    fn eval(&self, input: &Self::Input) -> Self::Output;

    // A function which adds constraints to a CircuitBuilder
    // that should be satisfied by `eval`.
    // TODO
    // consider making this a function returning a closure that adds constraints to a builder
    fn add_constraints<F: RichField + Extendable<D>, const D: usize>(
        &self,
        input: &Self::Input,
    ) -> impl Fn(&mut CircuitBuilder<F, D>) -> Self::Output;
}

/// Defines a reduce computation and its associated circuit.
pub trait Reduce {
    type Input: DataItem + Clone;

    /// A function producing the neutral element with respect to `eval`.
    fn neutral(&self) -> Self::Input;

    // The reduce computation to be performed. The inputs and output
    // must be representable in a circuit. The `eval` function
    // should be associative and have a neutral element so that:
    //  eval(x, eval(y, z)) = eval(eval(x, y), z) for all x,y,z in T
    //  eval(neutral, x) = eval(x, neutral) = x for all x in T
    fn eval(&self, left: &Self::Input, right: &Self::Input) -> Self::Input;

    // A function adding constraints to a circuit builder which should
    // be satisfied by the reduce computation in `eval`. That is,
    // if eval(x, y) = z, then circuit(x, y, z) should be true.
    fn add_constraints<F: RichField + Extendable<D>, const D: usize>(
        &self,
        left: &Self::Input,
        right: &Self::Input,
    ) -> impl Fn(&mut CircuitBuilder<F, D>) -> Self::Input;

    // TODO
    // consider using eval and add_constraints to make the Reduce trait iterable and foldable
    // also, consider a recursion threshold
}

/// A MapReduce computation is a list of Maps and Reduces whose input and output
/// types match up in sequence. Because a MapReduce computation consists of both
/// Maps and Reduces the output type may differ from the input type.
struct MapReduce<M, R, F, const D: usize>
where
    M: Map,
    R: Reduce<Input = M::Output>,
{
    // JOSH: For now we can keep this very simple as a single Map followed by a single Reduce.
    //       Some MapReduce computations we want to do (e.g. Average) require a final Map
    //       after the Reduce, and to make this completely general we may eventually want to
    //       allow any list of Maps and Reduces (whose type signatures work).
    map: M,
    reduce: R,
    phantom: PhantomData<F>,
}

impl<M, R, F, const D: usize> MapReduce<M, R, F, D>
where
    F: RichField + Extendable<D>,
    M: Map,
    R: Reduce<Input = M::Output>,
{
    fn new(map: M, reduce: R) -> Self {
        Self {
            map,
            reduce,
            phantom: PhantomData,
        }
    }

    fn eval(&self, inputs: Vec<M::Input>) -> R::Input {
        inputs.iter()
            .map(|i| 
                self.map.eval(i))
            .fold(self.reduce.neutral(), |acc, o| 
                self.reduce.eval(&acc, &o)
            )
    }

    fn add_reduce_constraints(
        &self,
        inputs: &[R::Input],
        builder: &mut CircuitBuilder<F, D>,
    ) -> R::Input {
        if inputs.len() == 1 {
            // put neutral on the right
            // is this *always* ok ?
            self.reduce.add_constraints(
                &inputs[0],
                &self.reduce.neutral()
            )(builder)
        } else {
            let (left_half, right_half) = inputs.split_at(inputs.len() / 2);
            let left = self.add_reduce_constraints(left_half, builder);
            let right = self.add_reduce_constraints(right_half, builder);
            let out = self.reduce.add_constraints(&left, &right)(builder);
            out
        }
    }

    fn add_map_constraints(
        &self,
        inputs: &[M::Input],
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<M::Output> {
        inputs.iter()
            .map(|i| 
                self.map.add_constraints(i)(builder)
            ).collect()
    }

    fn add_constraints(&self, inputs: &[M::Input], builder: &mut CircuitBuilder<F, D>) -> R::Input {
        let map_outs: Vec<M::Output> = inputs
            .iter()
            .map(|i| 
                self.map.add_constraints(i)(builder)
            ).collect();
            
        self.add_reduce_constraints(&map_outs, builder)
    }
}
