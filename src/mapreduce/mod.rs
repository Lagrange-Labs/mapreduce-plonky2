mod sum;
mod data_types;

use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField,
    plonk::{circuit_builder::CircuitBuilder, config::GenericConfig, circuit_data::CircuitConfig}, iop::witness::PartialWitness,
};
use anyhow::Result;
use crate::ProofTuple;

/// Data that can be represented in a circuit by some encoding
pub trait Data {
    type Encoded;
    /// An instance of Data must provide a function that encodes
    /// the data it contains in a circuit as a Target or Targets 
    /// by mutating a CircuitBuilder.
    fn encode<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self::Encoded;

    /// An instance of Data must provide a way to connect its underlying Targets
    fn connect<F: RichField + Extendable<D>, const D: usize>(
        left: Self::Encoded,
        right: Self::Encoded,
        builder: &mut CircuitBuilder<F, D>,
    );
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
    fn add_constraints<F: RichField + Extendable<D>, const D: usize>(
        &self,
        input: &<<Self as Map>::Input as Data>::Encoded,
        builder: &mut CircuitBuilder<F, D>,
    ) -> <<Self as Map>::Output as Data>::Encoded;
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
    fn add_constraints<F: RichField + Extendable<D>, const D: usize>(
        &self,
        left: &<<Self as Reduce>::Input as Data>::Encoded,
        right: &<<Self as Reduce>::Input as Data>::Encoded,
        builder: &mut CircuitBuilder<F, D>,
    ) -> <<Self as Reduce>::Input as Data>::Encoded;
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
        Self { map, reduce }
    }

    // This can be derived from the `eval` methods of the component Maps and Reduces
    fn eval(&self, inputs: Vec<M::Input>) -> R::Input {
        inputs
            .iter()
            .map(|x| self.map.eval(x))
            .fold(self.reduce.neutral(), |acc, y| self.reduce.eval(&acc, &y))
    }

    // Create the circuit
    fn add_constraints<F: RichField + Extendable<D>, const D: usize>(
        &self,
        inputs: Vec<M::Input>,
        builder: &mut CircuitBuilder<F, D>,
    ) -> <R::Input as Data>::Encoded {
        let init_targets: Vec<<M::Input as Data>::Encoded> = inputs.iter().map(|x| x.encode(builder)).collect();
        let after_map_targets: Vec<<M::Output as Data>::Encoded> = init_targets
            .iter()
            .map(|y| self.map.add_constraints(y, builder))
            .collect();

        let neutral = self.reduce.neutral().encode(builder);

        after_map_targets.iter().fold(neutral, |acc, z| {
            self.reduce.add_constraints(&acc, z, builder)
        })
    }

    // Creates a circuit verifying a Map computation and produces a proof for it
    fn map_proof<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        &self,
        config: &CircuitConfig,
        inputs: Vec<M::Input>,
    ) -> Result<ProofTuple<F, C, D>> {
        let mut b = CircuitBuilder::<F, D>::new(config.clone());
        let pw = PartialWitness::new();

        // compute the outputs by evaluating the map
        let outputs: Vec<M::Output> = inputs.iter().map(|inp| self.map.eval(inp)).collect();

        // add both the inputs and outputs as data in the circuit
        let in_targets: Vec<<M::Input as Data>::Encoded> = inputs.iter().map(|x| x.encode(&mut b)).collect();
        let out_targets: Vec<<M::Output as Data>::Encoded> = outputs.iter().map(|x| x.encode(&mut b)).collect();

        // add constraints 
        let computed_out_targets: Vec<<M::Output as Data>::Encoded> = in_targets
            .iter()
            .map(|y| self.map.add_constraints(y, &mut b))
            .collect();
        
        // connect outputs
        out_targets.into_iter().zip(computed_out_targets).for_each(|(ot, cot)| M::Output::connect(ot, cot, &mut b));


        // proving part
        let data = b.build::<C>();
        let proof = data.prove(pw)?;

        Ok((proof, data.verifier_only, data.common))
    }

    // TODO

    //     // Creates a circuit verifying a Map computation and verifying a previous proof and produces a single proof of both
    //     fn map_proof_recursive<
    //     F: RichField + Extendable<D>,
    //     C: GenericConfig<D, F = F>,
    //     const D: usize,
    // >(
    //     &self,
    //     config: &CircuitConfig,
    //     inputs: Vec<M::Input>,
    //     in_proof: ProofTuple<F, C, D>,
    // ) -> Result<ProofTuple<F, C, D>> {

    // }
}
