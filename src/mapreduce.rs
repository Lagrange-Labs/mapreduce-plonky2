use plonky2::plonk::circuit_builder::CircuitBuilder;

/// Data that can be represented in a circuit by some encoding
pub trait Data {
    // An instance of Data must provide a closure that 
    // adds its data to a circuit builder
    fn encoding(self) -> impl Fn(&mut CircuitBuilder<C::F, D>);
}

/// Defines a map computation with its associated circuit
pub trait Map {
    type A: Data;
    type B: Data;

    // The map computation to be performed on a single item.
    // The input and output can have different types but each
    // must be representable in a circuit.
    fn eval(input: A) -> B;

    // A closure adding constraints to a circuit which should
    // be satisfied by the map computation in `eval`. That is,
    // if eval(x) = y, then circuit(x, y) should be true.
    fn circuit(input: Self::A, output: Self::B) -> impl Fn(&mut CircuitBuilder);  
}

/// Defines a reduce computation and its associated circuit
pub trait Reduce {
    type A: Data;

    // A function producing the neutral element.
    fn neutral(self) -> A;

    // The reduce computation to be performed. The inputs and output
    // must be representable in a circuit. The `eval` function
    // should be associative and have a neutral element so that:
    //  eval(x, eval(y, z)) = eval(eval(x, y), z) for all x,y,z in T
    //  eval(neutral, x) = eval(x, neutral) = x for all x in T
    fn eval(left: A, right: A) -> A;

    // A closure adding constraints to a circuit which should
    // be satisfied by the reduce computation in `eval`. That is,
    // if eval(x, y) = z, then circuit(x, y, z) should be true.

    // TO CONSIDER: should this function take types A? Shouldn't it take
    // the closures defined in A.encoding()?
    fn circuit(left: A, right: A, output: A) -> impl Fn(&mut CircuitBuilder<C::F, D>);
}

/// A MapReduce computation is a list of Maps and Reduces whose input and output
/// types match up in sequence.
trait MapReduce {


}