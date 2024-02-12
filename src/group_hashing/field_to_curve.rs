//! Field to curve point conversion arithmetic and circuit functions

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
pub fn field_to_curve_point<F>(values: &[F]) -> Point
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
pub fn field_to_curve_target<F, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    targets: Vec<Target>,
) -> CurveTarget
where
    F: RichField + Extendable<D> + Extendable<N>,
    CircuitBuilder<F, D>: CircuitBuilderGFp5<F> + CircuitBuilderEcGFp5,
{
    // Calculate the Poseidon hash for inputs.
    let hash = b
        .hash_n_to_m_no_pad::<PoseidonHash>(targets, N)
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
    use plonky2_ecgfp5::gadgets::{
        base_field::PartialWitnessQuinticExt, curve::PartialWitnessCurve,
    };
    use rand::{thread_rng, Rng};
    use std::array;

    const ARITY: usize = 8;
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
        let output_target = b.field_to_curve_target(&input_targets);

        // Register public inputs.
        b.register_public_inputs(&input_targets);
        b.register_curve_public_input(output_target);

        // Generate random field values as inputs.
        let input_values = rand::thread_rng()
            .gen::<[u64; ARITY]>()
            .map(F::from_canonical_u64);

        // Calculate the output curve point.
        let output_value = field_to_curve_point(&input_values);

        // Set the value to target for witness.
        let mut pw = PartialWitness::new();
        input_targets
            .into_iter()
            .zip(input_values)
            .for_each(|(it, iv)| pw.set_target(it, iv));
        pw.set_curve_target(output_target, output_value.to_weierstrass());

        // Prove and verify.
        let data = b.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }
}
