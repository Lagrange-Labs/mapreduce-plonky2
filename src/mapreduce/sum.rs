use plonky2::iop::target::Target;
use plonky2::iop::witness;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::mapreduce::data_types::{Data, U64};
use crate::mapreduce::ops::{Map, Reduce};

struct SumU64;

impl Reduce for SumU64 {
    type Input = U64;

    fn neutral() -> u64 {
        0
    }

    fn eval(left: &u64, right: &u64) -> u64 {
        left + right
    }

    fn add_constraints<F: RichField + Extendable<D>, const D: usize>(
        left: &Target,
        right: &Target,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Target {
        builder.add(*left, *right)
    }
}

// most of this is boilerplate that can be made generic for all reduce operations
impl SumU64 {
    fn generate_partial_witness<F: RichField>(
        input_size: usize,
        input_values: Vec<u64>,
        targets: Vec<Target>,
    ) -> PartialWitness<F> {
        assert_eq!(input_size, input_values.len());
        let padded_values = Self::pad_with_neutral_value(&input_values);
        let values = Self::generate_values(padded_values);
        assert_eq!(values.len(), targets.len());
        let mut pw = PartialWitness::new();
        values
            .iter()
            .zip(targets)
            .for_each(|(v, t)| U64::set_target(t, *v, &mut pw));
        pw
    }

    // takes input data structure and creates the entire circuit, returning an augmented data structure
    // containing input and intermediate data and ALL corresponding targets
    fn write_circuit<F: RichField + Extendable<D>, const D: usize>(
        input_size: usize,
        builder: &mut CircuitBuilder<F, D>,
    ) -> (Vec<U64>, Vec<Target>) {
        let padded_input_size = input_size.next_power_of_two();
        let input_targets: Vec<Target> = (0..padded_input_size)
            .map(|_| U64::create_target(builder))
            .collect();

        let all_data = vec![U64; 2 * padded_input_size - 1];
        let all_targets = Self::generate_targets(input_targets, builder);

        (all_data, all_targets)
    }

    // pads the values to a power of two with the "neutral" element
    // required of every reduce operation
    fn pad_with_neutral_value(valueset: &[u64]) -> Vec<u64> {
        if valueset.len().is_power_of_two() {
            valueset.to_vec()
        } else {
            let new_length_with_pad = valueset.len().next_power_of_two();
            let padding_length = new_length_with_pad - valueset.len();
            let padding = vec![Self::neutral(); padding_length];
            [valueset, &padding].concat()
        }
    }

    // computes one reduction computation step, producing a vector 1/2 the length of the original,
    fn get_intermediate_values(values: &[u64]) -> Vec<u64> {
        // length should always be greater than two
        assert!(values.len() >= 2);

        if values.len() == 2 {
            vec![Self::eval(&values[0], &values[1])]
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
    fn generate_values(values: Vec<u64>) -> Vec<u64> {
        let intermediates = Self::get_intermediate_values(&values);
        if intermediates.len() == 1 {
            [values, intermediates].concat()
        } else {
            [values, Self::generate_values(intermediates)].concat()
        }
    }

    fn get_intermediate_targets<F: RichField + Extendable<D>, const D: usize>(
        targets: &[Target],
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        // length should always be greater than two
        assert!(targets.len() >= 2);

        if targets.len() == 2 {
            vec![Self::add_constraints(&targets[0], &targets[1], builder)]
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
        targets: Vec<Target>,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        let reduced = Self::get_intermediate_targets(&targets, builder);
        if reduced.len() == 1 {
            [targets, reduced].concat()
        } else {
            [targets, Self::generate_targets(reduced, builder)].concat()
        }
    }
}

mod test {
    use anyhow::Result;
    use plonky2::field::types::Field;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{self, CircuitConfig};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use std::env;
    use std::io::Write;
    use std::time::Instant;

    use crate::mapreduce::{data_types::U64, sum::SumU64};

    #[test]
    fn test_sum_circuit() -> Result<()> {
        const SIZE: usize = 10;

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();

        // building phase
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let (data, targets) = SumU64::write_circuit(SIZE, &mut builder);
        let circuit_data = builder.build::<C>();

        // witness generation and proving
        let input_values: Vec<u64> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let pw = SumU64::generate_partial_witness(SIZE, input_values, targets);
        let proof = circuit_data.prove(pw)?;

        // verification
        let res = circuit_data.verify(proof);

        res
    }
}
