use plonky2::{plonk::circuit_builder::CircuitBuilder, hash::hash_types::RichField, field::extension::Extendable, iop::target::Target};

/// Data that can be represented in a circuit by some encoding
pub trait Data {
    /// An instance of Data must provide a function that encodes
    /// the data in contains in a circuit by mutating a CircuitBuilder.
    fn encode<F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> Target;
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
    fn add_constraints<F: RichField + Extendable<D>, const D: usize>(&self, input: &Target, builder: &mut CircuitBuilder<F, D>) -> Target;
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
    fn add_constraints<F: RichField + Extendable<D>, const D: usize>(&self, left: &Target, right: &Target, builder: &mut CircuitBuilder<F, D>) -> Target;
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
        .map(|x| self.map.eval(x))
        .fold(self.reduce.neutral(), |acc, y| self.reduce.eval(&acc, &y))
    }

    // Create the circuit
    fn add_constraints<F: RichField + Extendable<D>, const D: usize>(&self, inputs: Vec<M::Input>, builder: &mut CircuitBuilder<F, D>) {
        let init_targets: Vec<Target> = inputs.iter()
            .map(|x| x.encode(builder))
            .collect();
        let after_map_targets: Vec<Target> = init_targets.iter()
            .map(|y| self.map.add_constraints(y, builder))
            .collect();

        let neutral = self.reduce.neutral().encode(builder);
        let after_reduce_target = after_map_targets.iter()
            .fold(neutral, |acc, z| self.reduce.add_constraints(&acc, z, builder));
    }
}


struct PublicInputU64 {
    x: u64,
}

impl Data for PublicInputU64 {
    fn encode<F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> Target {
        let target = builder.constant(F::from_canonical_u64(self.x));
        builder.register_public_input(target);
        target
    }
}

struct SumPublicInputU64{
    data: Vec<PublicInputU64>
}

impl Reduce for SumPublicInputU64 {
    type Input = PublicInputU64;

    fn neutral(&self) -> Self::Input {
        PublicInputU64 {
            x: 0u64,
        }
    }

    fn eval(&self, left: &Self::Input, right: &Self::Input) -> Self::Input {
        PublicInputU64 {
            x: left.x + right.x,
        }
    }

    fn add_constraints<F: RichField + Extendable<D>, const D: usize>(&self, left: &Target, right: &Target, builder: &mut CircuitBuilder<F, D>) -> Target {
        builder.add(*left, *right)
    }
}