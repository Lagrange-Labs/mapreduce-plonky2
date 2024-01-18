use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder, iop::witness::{PartialWitness, WitnessWrite},
};

use super::{Map, Reduce};
use crate::mapreduce::data_types::DataItem;

// this is a hack that is only necessary because the MapReduce struct requires one
// map followed by one reduce
struct SumU64Id;

// identity map
impl Map for SumU64Id
{
    type Input = DataItem;
    type Output = DataItem;

    fn eval(&self, input: &Self::Input) -> Self::Output {
        input.clone()
    }

    fn add_constraints_and_witnesses<F: RichField + Extendable<D>, const D: usize>(
        &self,
        input: &Self::Input,
    ) -> impl Fn(&mut CircuitBuilder<F, D>, &mut PartialWitness<F>) -> Self::Output { 
        {
            |_builder: &mut CircuitBuilder<F, D>, _pw: &mut PartialWitness<F>| input.clone()
        }
    }
}

struct SumU64;

impl<F: RichField + Extendable<D>> Reduce for SumU64
{
    type Input = DataItem<F>;

    fn neutral(&self) -> Self::Input {
        F::from_canonical_u64(0)
    }

    fn eval(&self, left: &Self::Input, right: &Self::Input) -> Self::Input {
        PublicU64(left.0 + right.0)
    }

    fn add_constraints_and_witnesses<F: RichField + Extendable<D>, const D: usize>(
        &self,
        left: &Self::Input,
        right: &Self::Input,
    ) -> impl Fn(&mut CircuitBuilder<F, D>, &mut PartialWitness<F>) -> Self::Input {
        move |builder, pw| {
            let left_target= builder.add_virtual_target();
            let right_target= builder.add_virtual_target();
            let out_target = builder.add(left_target, right_target);
            pw.set_target(left_target, left.get_values()[0]);
            pw.set_target(right_target, right.get_values()[0]);
            self.eval(&left, &right)
        }
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
        let output = mr_sum.add_constraints(&inputs, &mut builder);

        assert!(output.0 == computed_output);

        let circuit_data = builder.build::<C>();

        let pw = PartialWitness::new();
        let proof = circuit_data.prove(pw)?;
        let res = circuit_data.verify(proof);

        res
    }
}
