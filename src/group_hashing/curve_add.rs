//! Curve point addition arithmetic and circuit functions

use super::N;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::{
    curve::curve::Point,
    gadgets::{
        base_field::CircuitBuilderGFp5,
        curve::{CircuitBuilderEcGFp5, CurveTarget},
    },
};

/// Calculate the curve point addition.
pub fn add_curve_point(inputs: &[Point]) -> Point {
    assert!(!inputs.is_empty());

    inputs.iter().cloned().reduce(|acc, p| acc + p).unwrap()
}

/// Calculate the curve target addition.
pub(crate) fn add_curve_target<F, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    inputs: &[CurveTarget],
) -> CurveTarget
where
    F: RichField + Extendable<D> + Extendable<N>,
    CircuitBuilder<F, D>: CircuitBuilderGFp5<F> + CircuitBuilderEcGFp5,
{
    assert!(!inputs.is_empty());

    inputs
        .iter()
        .cloned()
        .reduce(|acc, point| b.curve_add(acc, point))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group_hashing::CircuitBuilderGroupHashing;
    use anyhow::Result;
    use plonky2::{
        field::{
            extension::{quintic::QuinticExtension, FieldExtension},
            goldilocks_field::GoldilocksField,
            types::{Field, Sample},
        },
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2_ecgfp5::{
        curve::curve::WeierstrassPoint,
        gadgets::{base_field::PartialWitnessQuinticExt, curve::PartialWitnessCurve},
    };
    use rand::{thread_rng, Rng};
    use std::array;

    const ARITY: usize = 4;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    /// Test curve point addition.
    #[test]
    fn test_curve_point_addition_gadget() -> Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);

        // Build the input and output targets.
        let input_targets = [0; ARITY].map(|_| b.add_virtual_curve_target());
        let output_target = b.add_curve_point(&input_targets);

        // Register the public inputs, register the output first since it's easy
        // to index in proof for testing.
        b.register_curve_public_input(output_target);
        input_targets
            .into_iter()
            .for_each(|it| b.register_curve_public_input(it));

        // Generate random curve points as inputs.
        let mut rng = thread_rng();
        let input_values = [0; ARITY].map(|_| Point::sample(&mut rng));

        // Set the value to target for witness.
        let mut pw = PartialWitness::new();
        input_targets
            .into_iter()
            .zip(input_values)
            .for_each(|(it, iv)| pw.set_curve_target(it, iv.to_weierstrass()));

        println!(
            "[+] This test curve point addition gadget has {} gates",
            b.num_gates()
        );

        // Generate the proof.
        let data = b.build::<C>();
        let proof = data.prove(pw)?;

        // Calculate the output point and check with proof.
        let expected_point = add_curve_point(&input_values).to_weierstrass();
        let real_point = WeierstrassPoint {
            x: QuinticExtension(proof.public_inputs[..N].try_into().unwrap()),
            y: QuinticExtension(proof.public_inputs[N..N + N].try_into().unwrap()),
            is_inf: proof.public_inputs[N + N].is_nonzero(),
        };
        assert_eq!(
            real_point, expected_point,
            "Expected output point must be same with proof"
        );

        // Verify the proof.
        data.verify(proof)
    }
}
