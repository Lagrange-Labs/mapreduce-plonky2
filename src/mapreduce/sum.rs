use plonky2::iop::target::Target;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::mapreduce::data_types::U64;
use crate::mapreduce::ops::ReduceOp;

struct SumU64;

impl ReduceOp for SumU64 {
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

    use crate::mapreduce::{data_types::U64, sum::SumU64, ops::Reduce};

    #[test]
    fn test_sum_circuit() -> Result<()> {
        let sum_u64 = Reduce(SumU64);
        const SIZE: usize = 10;

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();

        // building phase
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let (data, targets) = sum_u64.write_circuit(SIZE, &mut builder);
        let circuit_data = builder.build::<C>();

        // witness generation and proving
        let input_values: Vec<u64> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let pw = sum_u64.generate_partial_witness(SIZE, input_values, targets);
        let proof = circuit_data.prove(pw)?;

        // verification
        let res = circuit_data.verify(proof);

        res
    }
}
