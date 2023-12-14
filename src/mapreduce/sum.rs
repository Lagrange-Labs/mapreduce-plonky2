use plonky2::{hash::hash_types::RichField, field::extension::Extendable, plonk::circuit_builder::CircuitBuilder, iop::target::Target};

use super::{data_types::PublicInputU64, Map, Reduce};

struct IdPublicInputU64;

// identity map
impl Map for IdPublicInputU64 {
    type Input = PublicInputU64;
    type Output = PublicInputU64;

    fn eval(&self, input: &Self::Input) -> Self::Output {
        input.clone()
    }

    fn add_constraints<F: RichField + Extendable<D>, const D: usize>(
        &self,
        input: &Target,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Target {
        *input
    }
}

struct SumPublicInputU64;

impl Reduce for SumPublicInputU64 {
    type Input = PublicInputU64;

    fn neutral(&self) -> Self::Input {
        PublicInputU64(0u64)
    }

    fn eval(&self, left: &Self::Input, right: &Self::Input) -> Self::Input {
        PublicInputU64(left.0 + right.0)
    }

    fn add_constraints<F: RichField + Extendable<D>, const D: usize>(
        &self,
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
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use crate::mapreduce::{sum::IdPublicInputU64, MapReduce, data_types::PublicInputU64, sum::SumPublicInputU64};

    #[test]
    fn test_sum_circuit() -> Result<()> {
        let data: Vec<u64> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let computed_output: u64 = data.iter().sum();

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let id_map = IdPublicInputU64;
        let sum = SumPublicInputU64;

        let mr_sum = MapReduce::new(id_map, sum);

        let inputs = data.into_iter().map(|x| PublicInputU64(x)).collect();
        let output = mr_sum.add_constraints(inputs, &mut builder);

        // check that the computed output equals the circuit output
        let computed_target = builder.constant(F::from_canonical_u64(computed_output));
        builder.connect(output, computed_target);

        let circuit_data = builder.build::<C>();

        let pw = PartialWitness::new();
        let proof = circuit_data.prove(pw)?;
        let res = circuit_data.verify(proof);

        res
    }
}