mod data_types;
mod sum;

use data_types::DataItem;

use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder, iop::{witness::PartialWitness, target::Target},
};

trait Data: Clone {

}

// /// An item of a data set that can be represented by a fixed-length array of field elements
// pub trait DataItem {
//     // TODO:
//     // consider making a struct that bookkeeps DataItems and their associated Targets
//     // in a HashMap or similar

//     /// An instance of DataItem must provide a function that retrieves or computes
//     /// the values that will be added to the witness
//     fn get_values<F>(&self) -> Vec<F>
//     where
//         F: RichField;

//     /// An instance of DataItem must provide a function returning a closure that creates
//     /// the targets that will added to the circuit
//     fn create_targets<F, const D: usize>(&self) -> impl Fn(&mut CircuitBuilder<F, D>) -> Vec<Target>
//     where
//         F: RichField + Extendable<D>;
    
//     fn len(&self) -> usize;
// }

/// Defines a map computation with its associated circuit
pub trait Map {
    type Input: Data;
    type Output: Data;

    // The map computation to be performed on a single item.
    // The input and output can have different types but each
    // must be representable in a circuit.
    fn eval(&self, input: &Self::Input) -> Self::Output;

    // A function return a closure which adds constraints to
    // a CircuitBuilder that should be satisfied by `eval`.
    fn add_constraints_and_witnesses<F: RichField + Extendable<D>, const D: usize>(
        &self,
        input: &Self::Input,
    ) -> impl Fn(&mut CircuitBuilder<F, D>, &mut PartialWitness<F>) -> Self::Output;
}

/// Defines a reduce computation and its associated circuit.
pub trait Reduce {
    type Input: Data;

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
    fn add_constraints_and_witnesses<F: RichField + Extendable<D>, const D: usize>(
        &self,
        left: &Self::Input,
        right: &Self::Input,
    ) -> impl Fn(&mut CircuitBuilder<F, D>, &mut PartialWitness<F>) -> Self::Input;

    // TODO
    // consider using eval and add_constraints to make the Reduce trait iterable and foldable
    // also, consider a recursion threshold
}

/// A MapReduce computation is a list of Maps and Reduces whose input and output
/// types match up in sequence. Because a MapReduce computation consists of both
/// Maps and Reduces the output type may differ from the input type.
struct MapReduce<M, R>
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
}

impl<M, R> MapReduce<M, R>
where
    M: Map,
    R: Reduce<Input = M::Output>,
{
    fn new(map: M, reduce: R) -> Self {
        Self {
            map,
            reduce,
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

    fn add_reduce_constraints_and_witnesses<F, const D: usize>(
        &self,
        inputs: &[R::Input],
        builder: &mut CircuitBuilder<F, D>,
        pw: &mut PartialWitness<F>,
    ) -> R::Input 
    where
        F: RichField + Extendable<D>,    
    {
        if inputs.len() == 1 {
            // put neutral on the right
            // is this *always* ok ?
            self.reduce.add_constraints_and_witnesses(
                &inputs[0],
                &self.reduce.neutral()
            )(builder, pw)
        } else {
            let (left_half, right_half) = inputs.split_at(inputs.len() / 2);
            let left = self.add_reduce_constraints_and_witnesses(left_half, builder, pw);
            let right = self.add_reduce_constraints_and_witnesses(right_half, builder, pw);
            let out = self.reduce.add_constraints_and_witnesses(&left, &right)(builder, pw);
            out
        }
    }

    fn add_map_constraints_and_witnesses<F, const D: usize>(
        &self,
        inputs: &[M::Input],
        builder: &mut CircuitBuilder<F, D>,
        pw: &mut PartialWitness<F>,
    ) -> Vec<M::Output> 
    where F: RichField + Extendable<D>
    {
        inputs.iter()
            .map(|i| 
                self.map.add_constraints_and_witnesses(i)(builder, pw)
            ).collect()
    }

    fn add_constraints_and_witnesses<F, const D: usize>(
        &self,
        inputs: &[M::Input],
        builder: &mut CircuitBuilder<F, D>,
        pw: &mut PartialWitness<F>,
    ) -> R::Input
    where
        F: RichField + Extendable<D>,
    {
        let map_outs: Vec<M::Output> = inputs
            .iter()
            .map(|i| 
                self.map.add_constraints_and_witnesses(i)(builder, pw)
            ).collect();
            
        self.add_reduce_constraints_and_witnesses(&map_outs, builder, pw)
    }
}
