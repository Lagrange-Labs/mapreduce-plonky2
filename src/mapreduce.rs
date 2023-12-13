use plonky2::{plonk::circuit_builder::CircuitBuilder, hash::hash_types::RichField, field::extension::Extendable, iop::target::Target};

/// Data that can be represented in a circuit by some encoding
pub trait Data {
    // An instance of Data must provide a function that encodes
    // the data in contains in a circuit by mutating a CircuitBuilder.
    fn encoding<F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>);

    // A function producing the neutral element.
    fn neutral() -> Self;
}

/// Defines a map computation with its associated circuit
pub trait Map {
    type Input: Data;
    type Output: Data;

    // The map computation to be performed on a single item.
    // The input and output can have different types but each
    // must be representable in a circuit.
    fn eval(&self, input: &Self::Input) -> Self::Output;

    // A function which adds constraints to a CircuitBuilder
    // that should be satisfied by `eval`.
    fn circuit<F: RichField + Extendable<D>, const D: usize>(&self, input: Self::Input, output: Self::Output, builder: &mut CircuitBuilder<F, D>);  
}

/// Defines a reduce computation and its associated circuit. 
pub trait Reduce {
    type Input: Data;

    // TO DO:
    // Have a Reduce computation be general over an arity other than 2.
    // This is easy for `eval` as we can just use the `eval` function
    // in a flatmap. However this may not be as easy for constructing (efficient) 
    // circuits because we'll need to know how to pack the constraints.
    //
    // Unless...plonky2 packs constraints for you?


    // The reduce computation to be performed. The inputs and output
    // must be representable in a circuit. The `eval` function
    // should be associative and have a neutral element so that:
    //  eval(x, eval(y, z)) = eval(eval(x, y), z) for all x,y,z in T
    //  eval(neutral, x) = eval(x, neutral) = x for all x in T
    fn eval(&self, left: Self::Input, right: Self::Input) -> Self::Input;

    // A function adding constraints to a circuit builder which should
    // be satisfied by the reduce computation in `eval`. That is,
    // if eval(x, y) = z, then circuit(x, y, z) should be true.
    fn circuit<F: RichField + Extendable<D>, const D: usize>(&self, left: Self::Input, right: Self::Input, output: Self::Input, builder: &mut CircuitBuilder<F, D>);
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

    // This can be derived from the `eval` methods of the component Maps and Reduces
    fn eval(&self, inputs: Vec<M::Input>) -> R::Input {
        inputs.iter()
        .map(|a| self.map.eval(a))
        .fold(R::Input::neutral(), |acc, element| self.reduce.eval(acc, element))
    }

    // Create the circuits
    // fn circuits(&self, inputs: Vec<M::Input>) -> Fn(....)
}


struct PublicInputU64 {
    x: u64,
}

impl Data for PublicInputU64 {
    fn neutral() -> Self {
        Self {
            x: 0u64
        }
    }

    fn encoding<F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) {
        let target = builder.constant(F::from_canonical_u64(self.x));
        builder.register_public_input(target);
    }
}

struct Sum<D: Data>{
    data: Vec<D>
}

impl<I: Data> Reduce for Sum<I> {
    type Input = I;

    fn eval(&self, left: Self::Input, right: Self::Input) -> Self::Input {
        todo!()
    }

    fn circuit<F: RichField + Extendable<D>, const D: usize>(&self, left: Self::Input, right: Self::Input, output: Self::Input, builder: &mut CircuitBuilder<F, D>) {
        todo!()
    }

    
}