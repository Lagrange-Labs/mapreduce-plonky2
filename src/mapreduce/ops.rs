
use super::data_types::Data;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::field::extension::Extendable;

/// Defines a single operation with its associated constraints
trait Op {
    type Input: Data;
    type Output: Data;
}

/// Defines a map computation with its associated circuit
pub trait Map: Op {

    // The map computation to be performed on a single item.
    // The input and output can have different types but each
    // must be representable in a circuit.
    fn eval(&self, input: &Self::Input) -> Self::Output;

    // A function which adds constraints to
    // a CircuitBuilder that should be satisfied by `eval`.
    fn add_constraints<F, const D: usize>(
        &self,
        input: &Self::Input,
        builder: &mut CircuitBuilder<F, D>,
    )
    where
        F: RichField + Extendable<D>;
}

/// Defines a reduce computation and its associated circuit.
pub trait Reduce: Op<Input = Output> {

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
    fn add_constraints<C, F, const D: usize>(
        &self,
        left: &Self::Input,
        right: &Self::Input,
        builder: &mut CircuitBuilder<F, D>,
    )
    where
        F: RichField + Extendable<D>;
    // TODO
    // consider using eval and add_constraints to make the Reduce trait iterable and foldable
    // also, consider a recursion threshold
}

pub struct Identity<T>();
impl<T> Op for Identity<T> {
    type Input = T;
    type Output = T;
}

pub struct Composition<Fst, Snd>
where
    Fst: Op,
    Snd: Op<Input = Fst::Output>
{
    first: Fst,
    second: Snd,
}

impl Op<Fst, Snd> for Composition<Fst, Snd> {
    type Input = Fst::Input;
    type Output = Snd::Output;
}


/// A MapReduce computation is a list of Maps and Reduces whose input and output
/// types match up in sequence. Because a MapReduce computation consists of both
/// Maps and Reduces the output type may differ from the input type.

pub enum MapReduce<O>
{
    Identity(Idendity<O>),
    Composition(Composition<_, O>),
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
}