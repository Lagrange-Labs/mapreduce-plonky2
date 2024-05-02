//! Map to curve circuit functions

use super::{
    field_to_curve::ToCurveTarget,
    utils::{a_sw, b_sw, neg_b_div_a_sw, neg_z_inv_sw, two_thirds, z_sw},
    EXTENSION_DEGREE as N,
};
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::{
    base_field::{CircuitBuilderGFp5, QuinticExtensionTarget},
    curve::{CircuitBuilderEcGFp5, CurveTarget},
};

/// Implement curve target conversion for extension target.
impl<F, const D: usize> ToCurveTarget<F, D> for QuinticExtensionTarget
where
    F: RichField + Extendable<D> + Extendable<N>,
    CircuitBuilder<F, D>: CircuitBuilderGFp5<F> + CircuitBuilderEcGFp5,
{
    /// Convert extension target to a curve target.
    fn map_to_curve_target(self, b: &mut CircuitBuilder<F, D>) -> CurveTarget {
        // Invokes simplified SWU method.
        simple_swu(b, self)
    }
}

/// Simplified SWU mapping function for conversion from an extension target to a
/// curve target.
pub(crate) fn simple_swu<F, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    u: QuinticExtensionTarget,
) -> CurveTarget
where
    F: RichField + Extendable<D> + Extendable<N>,
    CircuitBuilder<F, D>: CircuitBuilderGFp5<F> + CircuitBuilderEcGFp5,
{
    // Initialize constants.
    let zero = b.zero_quintic_ext();
    let one = b.one_quintic_ext();
    let [two_thirds, a_sw, b_sw, z_sw, neg_z_inv_sw, neg_b_div_a_sw] = [
        two_thirds(),
        a_sw(),
        b_sw(),
        z_sw(),
        neg_z_inv_sw(),
        neg_b_div_a_sw(),
    ]
    .map(|val| b.constant_quintic_ext(val));

    // Calculate tv1.
    let u_square = b.square_quintic_ext(u);
    let denom_part = b.mul_quintic_ext(z_sw, u_square);
    let denom_part_square = b.square_quintic_ext(denom_part);
    let denom = b.add_quintic_ext(denom_part_square, denom_part);
    let tv1 = b.inverse_quintic_ext(denom);

    // Calculate x1.
    let tv1_add_one = b.add_quintic_ext(tv1, one);
    let is_tv1_zero = b.is_equal_quintic_ext(tv1, zero);
    let x1 = b.select_quintic_ext(is_tv1_zero, neg_z_inv_sw, tv1_add_one);
    let x1 = b.mul_quintic_ext(x1, neg_b_div_a_sw);

    // Calculate x2.
    let x2 = b.mul_quintic_ext(denom_part, x1);

    // g(x) = X^3 + A_sw*X + B_sw
    let x1_square = b.square_quintic_ext(x1);
    let x2_square = b.square_quintic_ext(x2);
    let x1_cube = b.mul_quintic_ext(x1, x1_square);
    let x2_cube = b.mul_quintic_ext(x2, x2_square);
    let a_sw_mul_x1 = b.mul_quintic_ext(a_sw, x1);
    let a_sw_mul_x2 = b.mul_quintic_ext(a_sw, x2);
    let gx1 = b.add_quintic_ext(x1_cube, a_sw_mul_x1);
    let gx2 = b.add_quintic_ext(x2_cube, a_sw_mul_x2);
    let gx1 = b.add_quintic_ext(gx1, b_sw);
    let gx2 = b.add_quintic_ext(gx2, b_sw);

    let (gx1_root, is_gx1_sqrt) = b.try_any_sqrt_quintic_ext(gx1);
    let gx2_root = b.any_sqrt_quintic_ext(gx2);
    let x_sw = b.select_quintic_ext(is_gx1_sqrt, x1, x2);
    let y_pos = b.select_quintic_ext(is_gx1_sqrt, gx1_root, gx2_root);
    let neg_y_pos = b.neg_quintic_ext(y_pos);

    // Calculate X_cand and Y_cand.
    let x_cand = b.sub_quintic_ext(x_sw, two_thirds);
    // y_cand = y_pos if u_sgn == y_pos_sgn, else y_cand = -y_pos.
    let u_sgn = b.sgn0_quintic_ext(u);
    let y_pos_sgn = b.sgn0_quintic_ext(y_pos);
    let is_sgn_equal = b.is_equal(u_sgn.target, y_pos_sgn.target);
    let y_cand = b.select_quintic_ext(is_sgn_equal, y_pos, neg_y_pos);

    // Decode to a curve point.
    let y_cand_div_x_cand = b.div_quintic_ext(y_cand, x_cand);
    b.curve_decode_from_quintic_ext(y_cand_div_x_cand)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group_hashing::sswu_value;
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
        curve::curve::WeierstrassPoint, gadgets::base_field::PartialWitnessQuinticExt,
    };
    use rand::thread_rng;
    use std::array;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    /// Test simplified SWU method.
    #[test]
    fn test_simple_swu_gadget() -> Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);

        // Build the input and output targets.
        let input_target = b.add_virtual_quintic_ext_target();
        let output_target = simple_swu(&mut b, input_target);

        // Register the public inputs, register the output first since it's easy
        // to index in proof for testing.
        b.register_curve_public_input(output_target);
        b.register_quintic_ext_public_input(input_target);

        // Generate a random input value.
        let mut rng = thread_rng();
        let input_value = QuinticExtension::from_basefield_array(array::from_fn::<_, 5, _>(|_| {
            GoldilocksField::sample(&mut rng)
        }));

        // Set the value to target for witness.
        let mut pw = PartialWitness::new();
        pw.set_quintic_ext_target(input_target, input_value);

        println!(
            "[+] This test simplied SWU gadget has {} gates",
            b.num_gates()
        );

        // Generate the proof.
        let data = b.build::<C>();
        let proof = data.prove(pw)?;

        // Calculate the output point and check with proof.
        let expected_point = sswu_value::simple_swu(input_value).to_weierstrass();
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
