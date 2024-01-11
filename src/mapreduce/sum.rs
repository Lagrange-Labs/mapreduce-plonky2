use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};

use super::{data_types::PublicU64, DataItem, Map, Reduce};

// this is a hack that is only necessary because the MapReduce struct requires one
// map followed by one reduce
struct SumU64Id;

// identity map
impl<F, const D: usize> Map<F, D> for SumU64Id
where
    F: RichField + Extendable<D>,
{
    type Input = PublicU64;
    type Output = PublicU64;

    fn eval(&self, input: &Self::Input) -> Self::Output {
        input.clone()
    }

    fn add_constraints(
        &self,
        _input: &PublicU64,
        _output: &PublicU64,
        _builder: &mut CircuitBuilder<F, D>,
    ) {
    }
}

struct SumU64;

impl<F, const D: usize> Reduce<F, D> for SumU64
where
    F: RichField + Extendable<D>,
{
    type Input = PublicU64;

    fn neutral(&self) -> Self::Input {
        PublicU64(0u64)
    }

    fn eval(&self, left: &Self::Input, right: &Self::Input) -> Self::Input {
        PublicU64(left.0 + right.0)
    }

    fn add_constraints(
        &self,
        left: &PublicU64,
        right: &PublicU64,
        out: &PublicU64,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        let left_target = left.allocate(builder);
        let right_target = right.allocate(builder);
        let out_target = out.allocate(builder);
        let computed_out = builder.add(left_target[0], right_target[0]);
        builder.connect(out_target[0], computed_out);
    }
}

mod test {
    use anyhow::Result;
    use plonky2::field::types::Field;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use std::env;
    use std::io::Write;
    use std::time::Instant;

    use crate::mapreduce::{
        data_types::PublicU64,
        sum::{SumU64, SumU64Id},
        MapReduce,
    };

    #[test]
    fn test_sum_circuit() -> Result<()> {
        let data: Vec<u64> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let computed_output: u64 = data.iter().sum();

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let id_map = SumU64Id;
        let sum = SumU64;

        let mr_sum = MapReduce::new(id_map, sum);

        let inputs: Vec<PublicU64> = data.iter().map(|x| PublicU64(*x)).collect();
        let output = mr_sum.apply(&inputs, &mut builder);

        assert!(output.0 == computed_output);

        let circuit_data = builder.build::<C>();

        let pw = PartialWitness::new();
        let proof = circuit_data.prove(pw)?;
        let res = circuit_data.verify(proof);

        res
    }
}
