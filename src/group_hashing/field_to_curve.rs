//! Field-to-curve point conversion arithmetic and circuit functions

use super::N;
use plonky2::{
    field::extension::{quintic::QuinticExtension, Extendable, FieldExtension},
    hash::{
        hash_types::RichField,
        hashing::hash_n_to_m_no_pad,
        poseidon::{PoseidonHash, PoseidonPermutation},
    },
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::{
    curve::curve::Point,
    gadgets::{
        base_field::{CircuitBuilderGFp5, QuinticExtensionTarget},
        curve::{CircuitBuilderEcGFp5, CurveTarget},
    },
};

/// The trait for mapping to a curve point
pub trait ToCurvePoint {
    /// Convert to a curve point.
    fn map_to_curve_point(self) -> Point;
}

/// The trait for mapping to a curve target
pub trait ToCurveTarget<F, const D: usize>
where
    F: RichField + Extendable<D>,
{
    /// Convert to a curve target.
    fn map_to_curve_target(self, b: &mut CircuitBuilder<F, D>) -> CurveTarget;
}

/// Convert the field values to a curve points.
pub fn map_to_curve_point<F>(values: &[F]) -> Point
where
    F: RichField + Extendable<N>,
    QuinticExtension<F>: ToCurvePoint,
{
    // Calculate the Poseidon hash and output N values of base field.
    let hash: [F; N] = hash_n_to_m_no_pad::<F, PoseidonPermutation<F>>(values, N)
        .try_into()
        .unwrap();

    // Convert the hash to a curve point.
    QuinticExtension::from_basefield_array(hash).map_to_curve_point()
}

/// Convert the field targets to a curve target.
pub(crate) fn map_to_curve_target<F, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    targets: &[Target],
) -> CurveTarget
where
    F: RichField + Extendable<D> + Extendable<N>,
    CircuitBuilder<F, D>: CircuitBuilderGFp5<F> + CircuitBuilderEcGFp5,
{
    // Calculate the Poseidon hash for inputs.
    let hash = b
        .hash_n_to_m_no_pad::<PoseidonHash>(targets.to_vec(), N)
        .try_into()
        .unwrap();

    // Convert the hash to a curve target.
    QuinticExtensionTarget(hash).map_to_curve_target(b)
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
        iop::witness::{PartialWitness, WitnessWrite},
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

    const ARITY: usize = 1;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    /// Test field to curve point conversion.
    #[test]
    fn test_field_to_curve_point_gadget() -> Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);

        // Build the input and output targets.
        let input_targets = [0; ARITY].map(|_| b.add_virtual_target());
        let output_target = b.map_to_curve_point(&input_targets);

        // Register the public inputs, register the output first since it's easy
        // to index in proof for testing.
        b.register_curve_public_input(output_target);
        b.register_public_inputs(&input_targets);

        // Generate random field values as inputs.
        let input_values = rand::thread_rng()
            .gen::<[u64; ARITY]>()
            .map(F::from_canonical_u64);

        // Set the value to target for witness.
        let mut pw = PartialWitness::new();
        input_targets
            .into_iter()
            .zip(input_values)
            .for_each(|(it, iv)| pw.set_target(it, iv));

        println!(
            "[+] This test field-to-curve gadget has {} gates",
            b.num_gates()
        );

        // Generate the proof.
        let data = b.build::<C>();
        let proof = data.prove(pw)?;

        // Calculate the output point and check with proof.
        let expected_point = map_to_curve_point(&input_values).to_weierstrass();
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
