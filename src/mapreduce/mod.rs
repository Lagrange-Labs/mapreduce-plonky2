mod data_types;
mod sum;

use std::marker::PhantomData;

use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};

/// An item of a data set that can be represented by a fixed-length array of field elements
pub trait DataItem<F: RichField + Extendable<D>, const D: usize> {
    // TODO:
    // consider making a struct that bookkeeps DataItems and their associated Targets
    // in a HashMap or similar

    /// An instance of DataItem must provide a function that encodes
    /// the data it contains as a vector of field elements
    fn encode(&self) -> Vec<F>;
}

/// Defines a map computation with its associated circuit
pub trait Map<F: RichField + Extendable<D>, const D: usize> {
    type Input: DataItem<F, D>;
    type Output: DataItem<F, D>;

    // The map computation to be performed on a single item.
    // The input and output can have different types but each
    // must be representable in a circuit.
    fn eval(&self, input: &Self::Input) -> Self::Output;

    // A function which adds constraints to a CircuitBuilder
    // that should be satisfied by `eval`.
    // TODO
    // consider making this a function returning a closure that adds constraints to a builder
    fn add_constraints(
        &self,
        input: &Self::Input,
        output: &Self::Output,
        builder: &mut CircuitBuilder<F, D>,
    );

    // TODO
    // consider using eval and add_constraints to make the Map trait iterable
    fn apply_map(
        &self,
        inputs: &[Self::Input],
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Self::Output> {
        let outputs: Vec<Self::Output> = inputs.iter().map(|item| self.eval(item)).collect();

        inputs
            .iter()
            .zip(&outputs)
            .for_each(|(i, o)| self.add_constraints(i, o, builder));

        outputs
    }
}

/// Defines a reduce computation and its associated circuit.
pub trait Reduce<F: RichField + Extendable<D>, const D: usize> {
    type Input: DataItem<F, D> + Clone;

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
    fn add_constraints(
        &self,
        left: &Self::Input,
        right: &Self::Input,
        out: &Self::Input,
        builder: &mut CircuitBuilder<F, D>,
    );

    fn reduce_no_recurse(
        &self,
        inputs: &[Self::Input],
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self::Input {
        inputs.iter().fold(self.neutral(), |acc, z| {
            let acc_next = self.eval(&acc, z);
            self.add_constraints(&acc, z, &acc_next, builder);
            acc_next
        })
    }

    // TODO
    // consider using eval and add_constraints to make the Reduce trait iterable and foldable
    // also, consider a recursion threshold
    fn apply_reduce(
        &self,
        inputs: &[Self::Input],
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self::Input {
        if inputs.len() == 1 {
            inputs[0].clone()
        } else {
            let (left_half, right_half) = inputs.split_at(inputs.len() / 2);
            let pair = vec![
                self.apply_reduce(left_half, builder),
                self.apply_reduce(right_half, builder),
            ];
            self.reduce_no_recurse(&pair, builder)
        }
    }
}

/// A MapReduce computation is a list of Maps and Reduces whose input and output
/// types match up in sequence. Because a MapReduce computation consists of both
/// Maps and Reduces the output type may differ from the input type.
struct MapReduce<M, R, F, const D: usize>
where
    F: RichField + Extendable<D>,
    M: Map<F, D>,
    R: Reduce<F, D, Input = M::Output>,
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
    M: Map<F, D>,
    R: Reduce<F, D, Input = M::Output>,
{
    fn new(map: M, reduce: R) -> Self {
        Self {
            map,
            reduce,
            phantom: PhantomData,
        }
    }

    fn apply(&self, inputs: &[M::Input], builder: &mut CircuitBuilder<F, D>) -> R::Input {
        let map_outs = self.map.apply_map(inputs, builder);
        self.reduce.apply_reduce(&map_outs, builder)
    }
}
