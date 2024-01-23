use std::marker::PhantomData;

use super::data_types::Data;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::iop::witness::PartialWitness;

/// Defines a MapOp computation with its associated circuit
pub trait MapOp {
    type Input: Data;
    type Output: Data;

    // The MapOp computation to be performed on a single item.
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

/// Defines a ReduceOp computation and its associated circuit.
pub trait ReduceOp {
    type Input: Data;

    /// A function producing the neutral element with respect to `eval`.
    fn neutral() -> <Self::Input as Data>::Value;

    // The ReduceOp computation to be performed. The inputs and output
    // must be representable in a circuit. The `eval` function
    // should be associative and have a neutral element so that:
    //  eval(x, eval(y, z)) = eval(eval(x, y), z) for all x,y,z in T
    //  eval(neutral, x) = eval(x, neutral) = x for all x in T
    fn eval(
        left: &<Self::Input as Data>::Value,
        right: &<Self::Input as Data>::Value,
    ) -> <Self::Input as Data>::Value;

    // A function adding constraints to a circuit builder which should
    // be satisfied by the ReduceOp computation in `eval`. That is,
    // if eval(x, y) = z, then circuit(x, y, z) should be true.
    fn add_constraints<F, const D: usize>(
        left: &<Self::Input as Data>::WireTarget,
        right: &<Self::Input as Data>::WireTarget,
        builder: &mut CircuitBuilder<F, D>,
    ) -> <Self::Input as Data>::WireTarget
    where
        F: RichField + Extendable<D>;
}

pub struct Identity<T> {
    _phantom: PhantomData<T>,
}

impl<T: Data + Clone> MapOp for Identity<T> {
    type Input = T;
    type Output = T;

    fn eval(input: &<Self::Input as Data>::Value) -> <Self::Output as Data>::Value {
        input.clone()
    }

    fn add_constraints<F, const D: usize>(
        _input: &<Self::Input as Data>::WireTarget,
        _builder: &mut CircuitBuilder<F, D>,
    ) where
        F: RichField + Extendable<D>,
    {}
}

pub struct Reduce<Op>(pub Op);

impl<Op: ReduceOp> Reduce<Op> {
    pub fn generate_partial_witness<F: RichField>(
        &self, 
        input_size: usize,
        input_values: Vec<<<Op as ReduceOp>::Input as Data>::Value>,
        targets: Vec<<<Op as ReduceOp>::Input as Data>::WireTarget>,
    ) -> PartialWitness<F> {
        assert_eq!(input_size, input_values.len());
        let padded_values = Self::pad_with_neutral_value(&input_values);
        let values = Self::generate_values(padded_values);
        assert_eq!(values.len(), targets.len());
        let mut pw = PartialWitness::new();
        values
            .iter()
            .zip(targets)
            .for_each(|(v, t)| <Op::Input as Data>::set_target(t, v, &mut pw));
        pw
    }

    // takes input data structure and creates the entire circuit, returning an augmented data structure
    // containing input and intermediate data and ALL corresponding targets
    pub fn write_circuit<F: RichField + Extendable<D>, const D: usize>(
        &self,
        input_size: usize,
        builder: &mut CircuitBuilder<F, D>,
    ) -> (Vec<<Op as ReduceOp>::Input>, Vec<<Op::Input as Data>::WireTarget>) {
        let padded_input_size = input_size.next_power_of_two();
        let input_targets: Vec<<Op::Input as Data>::WireTarget> = (0..padded_input_size)
            .map(|_| <Op::Input as Data>::create_target(builder))
            .collect();

        let all_data = vec![<<Op as ReduceOp>::Input as Data>::new(); 2 * padded_input_size - 1];
        let all_targets = Self::generate_targets(input_targets, builder);

        (all_data, all_targets)
    }

    // pads the values to a power of two with the "neutral" element
    // required of every reduce operation
    fn pad_with_neutral_value(valueset: &[<Op::Input as Data>::Value]) -> Vec<<Op::Input as Data>::Value> {
        if valueset.len().is_power_of_two() {
            valueset.to_vec()
        } else {
            let new_length_with_pad = valueset.len().next_power_of_two();
            let padding_length = new_length_with_pad - valueset.len();
            let padding = vec![<Op as ReduceOp>::neutral(); padding_length];
            [valueset, &padding].concat()
        }
    }

    // computes one reduction computation step, producing a vector 1/2 the length of the original,
    fn get_intermediate_values(values: &[<Op::Input as Data>::Value]) -> Vec<<Op::Input as Data>::Value> {
        // length should always be greater than two
        assert!(values.len() >= 2);

        if values.len() == 2 {
            vec![<Op as ReduceOp>::eval(&values[0], &values[1])]
        } else {
            let (left, right) = values.split_at(values.len() / 2);
            [
                Self::get_intermediate_values(left),
                Self::get_intermediate_values(right),
            ]
            .concat()
        }
    }

    // recursively generates all values from a list of input values
    fn generate_values(values: Vec<<Op::Input as Data>::Value>) -> Vec<<Op::Input as Data>::Value> {
        let intermediates = Self::get_intermediate_values(&values);
        if intermediates.len() == 1 {
            [values, intermediates].concat()
        } else {
            [values, Self::generate_values(intermediates)].concat()
        }
    }

    fn get_intermediate_targets<F: RichField + Extendable<D>, const D: usize>(
        targets: &[<Op::Input as Data>::WireTarget],
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<<Op::Input as Data>::WireTarget> {
        // length should always be greater than two
        assert!(targets.len() >= 2);

        if targets.len() == 2 {
            vec![<Op as ReduceOp>::add_constraints(&targets[0], &targets[1], builder)]
        } else {
            let (left, right) = targets.split_at(targets.len() / 2);
            [
                Self::get_intermediate_targets(left, builder),
                Self::get_intermediate_targets(right, builder),
            ]
            .concat()
        }
    }

    // recursively computes all targets from a list of input targets
    fn generate_targets<F: RichField + Extendable<D>, const D: usize>(
        targets: Vec<<Op::Input as Data>::WireTarget>,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<<Op::Input as Data>::WireTarget> {
        let reduced = Self::get_intermediate_targets(&targets, builder);
        if reduced.len() == 1 {
            [targets, reduced].concat()
        } else {
            [targets, Self::generate_targets(reduced, builder)].concat()
        }
    }
}
